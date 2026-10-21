"""Zip, gzip, and content sniffing before graded analysis."""

import gzip
import io
import zipfile
from pathlib import Path
import tempfile

from triage.analyze import analyze_paths
from triage.ingest import open_inputs

ANR = "10-20 11:00:02.000  1234  1234 E ActivityManager: ANR in com.demo.app (com.demo.app/1234)\n"
ANR_NESTED = "10-20 11:00:02.200  7777  7777 E ActivityManager: ANR in com.demo.nested (com.demo.nested/7777)\n"
WATCHDOG = "10-20 11:00:01.000  1800  1800 E Watchdog: WATCHDOG KILLING SYSTEM PROCESS: system_server\n"
LEAKED = "10-20 11:00:02.000  9  9 E ActivityManager: ANR in leaked.app (leaked.app/9)\n"


def test_archives_are_unpacked_and_typed() -> None:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        (root / "mainlog").write_text(ANR, encoding="utf-8")
        (root / "photo.dat").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
        (root / "notes.md").write_text("this is not a log\n", encoding="utf-8")

        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as inner:
            inner.writestr("inside.txt", ANR_NESTED)
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as archive:
            archive.writestr("bundle/mainlog", ANR)
            archive.writestr("readme.md", "not a log\n")
            archive.writestr("../outside.txt", LEAKED)
            archive.writestr("inner.zip", nested.getvalue())
        (root / "capture.zip").write_bytes(outer.getvalue())

        with gzip.open(root / "watchdog.log.gz", "wt", encoding="utf-8") as handle:
            handle.write(WATCHDOG)
        (root / "broken.zip").write_text("not really a zip\n", encoding="utf-8")

        with open_inputs(root) as (files, labels, notes):
            report = analyze_paths(files, "", "", "", labels=labels, prep_notes=notes)
            joined = "\n".join(labels)
            assert "mainlog" in joined
            assert "capture.zip/bundle/mainlog" in joined
            assert "capture.zip/inner.zip/inside.txt" in joined
            assert "watchdog.log.gz/watchdog.log" in joined
            assert "outside.txt" not in joined
            assert "photo.dat" not in joined
            assert "notes.md" not in joined
            assert "broken.zip" not in joined
            assert not (root / "outside.txt").exists()
            text = " ".join(notes)
            assert "已解压 capture.zip" in text
            assert "不安全路径" in text
            assert "无法作为压缩包打开" in text
            assert any(item["pid"] == "1234" for item in report["findings"])
            assert any(item["pid"] == "7777" for item in report["findings"])
            assert any(item["category"] == "Watchdog" for item in report["findings"])
            assert all("leaked" not in item["process"] and "leaked" not in " ".join(item["evidence"]) for item in report["findings"])
    print("ingest ok", report["summary"])


if __name__ == "__main__":
    test_archives_are_unpacked_and_typed()
