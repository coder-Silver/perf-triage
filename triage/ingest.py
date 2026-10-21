"""Expand zip/gzip bundles and keep only files this tool can analyze."""

from __future__ import annotations

import gzip
import itertools
import tempfile
import zipfile
from contextlib import contextmanager
from pathlib import Path

from .logs import is_text_log, is_trace, looks_like_log

SKIP_DIRS = {".git", ".venv", "vendor", "__pycache__", "node_modules"}
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_DEPTH = 3
MAX_MEMBERS = 2000
MAX_UNCOMPRESSED = MAX_FILE_BYTES
_SEQUENCE = itertools.count()


@contextmanager
def open_inputs(root: Path):
    """Yield recognized log/trace paths, display labels, and unpack notes."""
    temporary = tempfile.TemporaryDirectory(prefix="perf-triage-")
    try:
        files: list[Path] = []
        labels: list[str] = []
        notes: list[str] = []
        _walk(root, Path(temporary.name), files, labels, notes)
        yield files, labels, notes
    finally:
        temporary.cleanup()


def _walk(root: Path, dest: Path, files: list[Path], labels: list[str], notes: list[str]) -> None:
    if root.is_file():
        _consume(root, root.name, 0, dest, files, labels, notes)
        return
    if not root.is_dir():
        notes.append("路径不是文件或目录。")
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            label = path.relative_to(root).as_posix()
        except ValueError:
            label = path.name
        _consume(path, label, 0, dest, files, labels, notes)


def _consume(
    path: Path,
    label: str,
    depth: int,
    dest: Path,
    files: list[Path],
    labels: list[str],
    notes: list[str],
) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        notes.append(f"无法读取 {label}：{exc}")
        return
    container = _sniff_container(path)
    if container and size > MAX_FILE_BYTES:
        notes.append(f"跳过 {label}，压缩包超过 512MB。")
        return
    if container and depth >= MAX_DEPTH:
        notes.append(f"{label} 嵌套超过 {MAX_DEPTH} 层，已跳过。")
        return
    if container == "zip":
        _unpack_zip(path, label, depth, dest, files, labels, notes)
        return
    if container == "gzip":
        _unpack_gzip(path, label, depth, dest, files, labels, notes)
        return
    if size > MAX_FILE_BYTES:
        notes.append(f"跳过 {label}，文件超过 512MB。")
        return
    if is_trace(path) or is_text_log(path) or looks_like_log(path):
        files.append(path)
        labels.append(label)


def _sniff_container(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
    except OSError:
        return ""
    if magic.startswith(b"PK"):
        return "zip"
    if magic.startswith(b"\x1f\x8b"):
        return "gzip"
    suffix = path.suffix.lower()
    if suffix == ".zip":
        return "zip"
    if suffix == ".gz":
        return "gzip"
    return ""


def _unpack_zip(
    path: Path,
    label: str,
    depth: int,
    dest: Path,
    files: list[Path],
    labels: list[str],
    notes: list[str],
) -> None:
    out = dest / f"zip-{next(_SEQUENCE)}"
    out.mkdir(parents=True, exist_ok=True)
    try:
        archive = zipfile.ZipFile(path, metadata_encoding="utf-8")
    except TypeError:
        try:
            archive = zipfile.ZipFile(path)
        except zipfile.BadZipFile:
            _reject_archive(path, label, files, labels, notes)
            return
    except zipfile.BadZipFile:
        _reject_archive(path, label, files, labels, notes)
        return
    before = len(files)
    total = 0
    members = 0
    unsafe = 0
    encrypted = 0
    try:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                encrypted += 1
                continue
            target = _safe_join(out, info.filename)
            if target is None:
                unsafe += 1
                continue
            members += 1
            if members > MAX_MEMBERS:
                notes.append(f"{label} 内文件过多，已停止继续解压。")
                break
            written = _extract_member(archive, info, target)
            if written < 0:
                notes.append(f"{label} 解压后超过 512MB，已停止。")
                break
            total += written
            if total > MAX_UNCOMPRESSED:
                notes.append(f"{label} 解压后超过 512MB，已停止。")
                break
            if not target.is_file():
                continue
            inner = f"{label}/{info.filename.replace(chr(92), '/')}"
            _consume(target, inner, depth + 1, dest, files, labels, notes)
    finally:
        archive.close()
    if unsafe:
        notes.append(f"{label} 里有 {unsafe} 个不安全路径，已跳过。")
    if encrypted:
        notes.append(f"{label} 里有 {encrypted} 个加密文件，已跳过。")
    added = len(files) - before
    if added:
        shown = "、".join(labels[before : before + 8])
        suffix = "" if added <= 8 else f" 等 {added} 个"
        notes.append(f"已解压 {label}，识别到 {added} 个日志：{shown}{suffix}")
    else:
        notes.append(f"已解压 {label}，里面没有可识别的日志。")


def _unpack_gzip(
    path: Path,
    label: str,
    depth: int,
    dest: Path,
    files: list[Path],
    labels: list[str],
    notes: list[str],
) -> None:
    inner_name = path.name[:-3] if path.name.lower().endswith(".gz") else (path.stem or "log")
    out = dest / f"gz-{next(_SEQUENCE)}"
    target = _safe_join(out, inner_name)
    if target is None:
        notes.append(f"无法解压 {label}。")
        return
    try:
        with gzip.open(path, "rb") as source:
            written = _copy_limited(source, target, MAX_FILE_BYTES)
    except (OSError, gzip.BadGzipFile, EOFError):
        _reject_archive(path, label, files, labels, notes)
        return
    if written < 0:
        notes.append(f"{label} 解压后超过 512MB，已跳过。")
        return
    before = len(files)
    _consume(target, f"{label}/{inner_name}", depth + 1, dest, files, labels, notes)
    if len(files) == before:
        notes.append(f"已解压 {label}，里面没有可识别的日志。")
    else:
        notes.append(f"已解压 {label}，识别到 {labels[before]}。")


def _reject_archive(path: Path, label: str, files: list[Path], labels: list[str], notes: list[str]) -> None:
    notes.append(f"{label} 无法作为压缩包打开。")
    if looks_like_log(path):
        files.append(path)
        labels.append(label)
        notes.append(f"{label} 内容是日志，已按日志分析。")


def _extract_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> int:
    try:
        with archive.open(info, "r") as source:
            return _copy_limited(source, target, MAX_FILE_BYTES)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return 0


def _copy_limited(source, target: Path, limit: int) -> int:
    total = 0
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as output:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                return total
            total += len(chunk)
            if total > limit:
                break
            output.write(chunk)
    target.unlink(missing_ok=True)
    return -1


def _safe_join(dest: Path, name: str) -> Path | None:
    raw = (name or "").replace("\\", "/")
    if raw.startswith("/") or (len(raw) >= 2 and raw[1] == ":"):
        return None
    parts: list[str] = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == ".." or part == "__MACOSX" or part.startswith("._"):
            return None
        parts.append(part)
    if not parts:
        return None
    root = dest.resolve()
    target = root.joinpath(*parts)
    try:
        target.relative_to(root)
    except ValueError:
        return None
    return target
