"""Local page: point at a log directory, save an API key, print P0/P1/P2."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from triage.advice import trace_analysis
from triage.analyze import analyze_paths
from triage.ask import answer_question
from triage.ingest import open_inputs
from triage.probe import probe_model
from triage.providers import PROVIDERS, default_model, host_of, resolve_model
from triage.trace_store import (
    list_traces,
    load_analysis,
    load_home_report,
    save_analysis,
    save_home_report,
    store_traces,
    trace_file,
)

ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web" / "index.html"
TRACE_PAGE = ROOT / "web" / "trace.html"
PERFETTO_JS = ROOT / "web" / "perfetto.js"
CONFIG = Path.home() / ".perf-triage" / "config.json"
HOST = "127.0.0.1"
PORT = 8765
_SESSION_LOCK = threading.Lock()
_SESSION: dict = {"report": None, "history": []}


def load_config() -> dict:
    empty_model = default_model()
    empty = {
        "base_url": empty_model.base_url,
        "model": empty_model.id,
        "last_path": "",
        "keys": {},
    }
    if not CONFIG.exists():
        return empty
    try:
        data = json.loads(CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}
    model = resolve_model(str(data.get("model") or "")) or empty_model
    keys = data.get("keys") if isinstance(data.get("keys"), dict) else {}
    cleaned_keys = {
        str(host): str(secret)
        for host, secret in keys.items()
        if str(host).strip() and str(secret).strip()
    }
    legacy = str(data.get("api_key") or "").strip()
    legacy_host = host_of(str(data.get("base_url") or model.base_url))
    if legacy and legacy_host:
        cleaned_keys.setdefault(legacy_host, legacy)
    return {
        "base_url": model.base_url,
        "model": model.id,
        "last_path": data.get("last_path") or "",
        "keys": cleaned_keys,
    }


class ConfigError(ValueError):
    pass


def save_config(data: dict) -> dict:
    current = load_config()
    if "model" in data or data.get("api_key") or data.get("clear_key"):
        model = resolve_model(str(data.get("model") or current["model"]))
        if model is None:
            raise ConfigError("未知模型，请从列表中选择")
        current["model"] = model.id
        current["base_url"] = model.base_url
        host = host_of(model.base_url)
        if data.get("api_key"):
            current["keys"][host] = str(data["api_key"]).strip()
        if data.get("clear_key"):
            current["keys"].pop(host, None)
    if "last_path" in data:
        current["last_path"] = str(data.get("last_path") or "")
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    CONFIG.write_text(
        json.dumps(
            {
                "model": current["model"],
                "base_url": current["base_url"],
                "last_path": current["last_path"],
                "keys": current["keys"],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    return current


def perfetto_ready() -> bool:
    try:
        import perfetto.trace_processor  # noqa: F401
    except ImportError:
        return False
    return True


def public_config(data: dict) -> dict:
    model = resolve_model(data.get("model") or "") or default_model()
    host = host_of(model.base_url)
    keys = data.get("keys") or {}
    return {
        "base_url": model.base_url,
        "model": model.id,
        "has_key": bool(keys.get(host)),
        "last_path": data.get("last_path") or "",
        "providers": [item.as_dict() for item in PROVIDERS],
        "perfetto": perfetto_ready(),
    }


def folder_picker_script() -> str:
    return r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$csharp = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace PerfTriage {
  [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IShellItem {
    void BindToHandler(IntPtr pbc, ref Guid bhid, ref Guid riid, out IntPtr ppv);
    void GetParent(out IShellItem ppsi);
    void GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
    void GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
    void Compare(IShellItem psi, uint hint, out int piOrder);
  }

  [ComImport, Guid("42f85136-db7e-439c-85f1-e4075d135fc8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IFileOpenDialog {
    [PreserveSig] int Show(IntPtr parent);
    void SetFileTypes(uint cFileTypes, IntPtr rgFilterSpec);
    void SetFileTypeIndex(uint iFileType);
    void GetFileTypeIndex(out uint piFileType);
    void Advise(IntPtr pfde, out uint pdwCookie);
    void Unadvise(uint dwCookie);
    void SetOptions(uint fos);
    void GetOptions(out uint pfos);
    void SetDefaultFolder(IShellItem psi);
    void SetFolder(IShellItem psi);
    void GetFolder(out IShellItem ppsi);
    void GetCurrentSelection(out IShellItem ppsi);
    void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string pszName);
    void GetFileName([MarshalAs(UnmanagedType.LPWStr)] out string pszName);
    void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string pszTitle);
    void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string pszText);
    void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string pszLabel);
    void GetResult(out IShellItem ppsi);
    void AddPlace(IShellItem psi, int fdap);
    void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string pszDefaultExtension);
    void Close(int hr);
    void SetClientGuid(ref Guid guid);
    void ClearClientData();
    void SetFilter(IntPtr pFilter);
    void GetResults(out IntPtr ppenum);
    void GetSelectedItems(out IntPtr ppsai);
  }

  [ComImport, Guid("DC1C5A9C-E88A-4dde-A5A1-60F82A20AEF7"), ClassInterface(ClassInterfaceType.None)]
  public class FileOpenDialogRCW { }

  public static class Native {
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, IntPtr processId);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool attach);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int command);
    [DllImport("user32.dll")] public static extern IntPtr GetWindow(IntPtr hWnd, uint command);
    [DllImport("user32.dll")] public static extern void SwitchToThisWindow(IntPtr hWnd, bool altTab);
    [DllImport("user32.dll")] public static extern bool AllowSetForegroundWindow(int processId);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    public static extern void SHCreateItemFromParsingName(string path, IntPtr bindContext, ref Guid iid, out IShellItem item);

    public static void ForceForeground(IntPtr hwnd) {
      if (hwnd == IntPtr.Zero) return;
      AllowSetForegroundWindow(-1);
      IntPtr foreground = GetForegroundWindow();
      uint foregroundThread = GetWindowThreadProcessId(foreground, IntPtr.Zero);
      uint currentThread = GetCurrentThreadId();
      bool attached = false;
      if (foregroundThread != 0 && foregroundThread != currentThread) {
        attached = AttachThreadInput(foregroundThread, currentThread, true);
      }
      ShowWindow(hwnd, 5);
      BringWindowToTop(hwnd);
      SetForegroundWindow(hwnd);
      SwitchToThisWindow(hwnd, true);
      if (attached) AttachThreadInput(foregroundThread, currentThread, false);
    }
  }

  public static class Vista {
    const uint FOS_PICKFOLDERS = 0x20;
    const uint FOS_FORCEFILESYSTEM = 0x40;
    const uint FOS_NOCHANGEDIR = 0x8;
    const uint FOS_PATHMUSTEXIST = 0x800;

    public static string Pick(IntPtr owner, string initial) {
      var dialog = (IFileOpenDialog)new FileOpenDialogRCW();
      dialog.SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST | FOS_NOCHANGEDIR);
      dialog.SetTitle("选择已经抓好的日志目录");
      if (!string.IsNullOrEmpty(initial) && Directory.Exists(initial)) {
        try {
          Guid iid = new Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE");
          IShellItem folder;
          Native.SHCreateItemFromParsingName(initial, IntPtr.Zero, ref iid, out folder);
          dialog.SetFolder(folder);
        } catch (Exception) {
        }
      }
      int hr = dialog.Show(owner);
      if ((uint)hr == 0x800704C7u) return "";
      if (hr != 0) Marshal.ThrowExceptionForHR(hr);
      IShellItem result;
      dialog.GetResult(out result);
      string path;
      result.GetDisplayName(0x80058000, out path);
      return path ?? "";
    }
  }

  public static class Legacy {
    public static string Pick(Form owner, string initial) {
      using (var dialog = new FolderBrowserDialog()) {
        dialog.Description = "选择已经抓好的日志目录";
        dialog.ShowNewFolderButton = false;
        if (!string.IsNullOrEmpty(initial) && Directory.Exists(initial)) dialog.SelectedPath = initial;
        DialogResult result = dialog.ShowDialog(owner);
        if (result == DialogResult.OK && !string.IsNullOrEmpty(dialog.SelectedPath)) return dialog.SelectedPath;
        return "";
      }
    }
  }

  public static class Picker {
    public static string Choose(string initial) {
      using (var owner = new Form()) {
        owner.Text = "选择日志目录";
        owner.TopMost = true;
        owner.ShowInTaskbar = true;
        owner.FormBorderStyle = FormBorderStyle.FixedDialog;
        owner.MinimizeBox = false;
        owner.MaximizeBox = false;
        owner.Opacity = 1;
        owner.Width = 460;
        owner.Height = 128;
        var area = Screen.FromPoint(Cursor.Position).WorkingArea;
        owner.StartPosition = FormStartPosition.Manual;
        owner.Location = new System.Drawing.Point(
          area.Left + Math.Max(0, (area.Width - owner.Width) / 2),
          area.Top + Math.Max(0, (area.Height - owner.Height) / 2));
        var label = new Label();
        label.Dock = DockStyle.Fill;
        label.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
        label.Text = "请在最前面的窗口中选择日志目录。取消不会开始分析。";
        owner.Controls.Add(label);
        owner.Show();
        owner.TopMost = true;
        owner.Activate();
        Native.ForceForeground(owner.Handle);
        var timer = new Timer();
        int ticks = 0;
        timer.Interval = 200;
        timer.Tick += delegate {
          ticks++;
          if (ticks > 30) { timer.Stop(); return; }
          IntPtr popup = Native.GetWindow(owner.Handle, 6);
          if (popup != IntPtr.Zero) Native.ForceForeground(popup);
          else Native.ForceForeground(owner.Handle);
        };
        timer.Start();
        try {
          try {
            return Vista.Pick(owner.Handle, initial);
          } catch (Exception) {
            return Legacy.Pick(owner, initial);
          }
        } finally {
          timer.Stop();
          timer.Dispose();
        }
      }
    }
  }
}
'@
Add-Type -TypeDefinition $csharp -ReferencedAssemblies System.Windows.Forms, System.Drawing
if ($env:PERF_TRIAGE_PICK_SELFTEST -eq '1') {
  [Console]::Out.WriteLine('SELFTEST_OK')
  exit 0
}
$chosen = [PerfTriage.Picker]::Choose([string]$env:PERF_TRIAGE_INITIAL)
if ($chosen) { [Console]::Out.WriteLine($chosen) }
"""


def _decode_ps(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _picker_stdout(raw: bytes) -> str:
    lines = [line.strip() for line in _decode_ps(raw).splitlines() if line.strip()]
    return lines[-1] if lines else ""


def finish_pick(chosen: str) -> dict:
    if not chosen:
        return {"cancelled": True}
    save_config({"last_path": chosen})
    return {"path": chosen}


def _mac_cancelled(detail: str) -> bool:
    text = detail.casefold()
    return "user canceled" in text or "(-128)" in text or "-128" in text


def pick_folder(initial: str) -> str:
    if sys.platform == "darwin":
        return _pick_folder_mac(initial)
    if os.name != "nt":
        raise RuntimeError("当前系统请把日志目录路径粘贴到输入框")
    script_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w", suffix=".ps1", delete=False, encoding="utf-8-sig"
        ) as handle:
            handle.write(folder_picker_script())
            script_path = handle.name
        env = os.environ.copy()
        env.pop("PERF_TRIAGE_PICK_SELFTEST", None)
        if initial:
            env["PERF_TRIAGE_INITIAL"] = initial
        else:
            env.pop("PERF_TRIAGE_INITIAL", None)
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File", script_path],
            capture_output=True,
            env=env,
            timeout=600,
            check=False,
        )
    finally:
        if script_path:
            try:
                os.remove(script_path)
            except OSError:
                pass
    if completed.returncode != 0:
        detail = _decode_ps(completed.stderr).strip() or _decode_ps(completed.stdout).strip()
        detail = detail.splitlines()[-1] if detail else f"powershell 退出码 {completed.returncode}"
        raise RuntimeError(detail[:500])
    return _picker_stdout(completed.stdout)


def _pick_folder_mac(initial: str) -> str:
    script = 'POSIX path of (choose folder with prompt "选择已经抓好的日志目录"'
    if initial and Path(initial).is_dir():
        script += " default location POSIX file " + json.dumps(initial)
    script += ")"
    completed = subprocess.run(
        ["osascript", "-e", script],
        capture_output=True,
        timeout=600,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace")
        if _mac_cancelled(detail):
            return ""
        raise RuntimeError((detail.strip() or "无法打开目录选择")[:500])
    return completed.stdout.decode("utf-8", errors="replace").strip()


def current_probe() -> dict:
    config = load_config()
    model = resolve_model(config["model"]) or default_model()
    key = (config.get("keys") or {}).get(host_of(model.base_url), "")
    return probe_model(model.base_url, key, model.id)


def analyze_target(target: str) -> tuple[dict, int]:
    folder = Path(target).expanduser()
    if not folder.exists():
        return {"error": f"路径不存在：{folder}"}, 400
    if not folder.is_dir() and not folder.is_file():
        return {"error": "路径不是文件或目录"}, 400
    try:
        with open_inputs(folder) as (files, labels, prep_notes):
            if not files:
                message = "没有识别到可分析的日志。支持 logcat、bugreport、tombstone、pftrace，以及包含这些文件的 zip、gz。"
                if prep_notes:
                    message = message + " " + " ".join(prep_notes)
                return {"error": message}, 400
            config = load_config()
            model = resolve_model(config["model"]) or default_model()
            key = (config.get("keys") or {}).get(host_of(model.base_url), "")
            report = analyze_paths(
                files,
                model.base_url,
                key,
                model.id,
                labels=labels,
                prep_notes=prep_notes,
            )
            report["traces"] = store_traces(files, labels)
            report["path"] = str(folder)
            save_analysis(trace_analysis(report))
            save_home_report(report)
    except OSError as exc:
        return {"error": f"读取日志失败：{exc}"}, 400
    save_config({"last_path": str(folder)})
    with _SESSION_LOCK:
        _SESSION["report"] = report
        _SESSION["history"] = []
    return report, 200


def current_report() -> dict | None:
    with _SESSION_LOCK:
        report = _SESSION["report"]
        if report is not None:
            return report
    saved = load_home_report()
    if not saved:
        return None
    with _SESSION_LOCK:
        if _SESSION["report"] is None:
            _SESSION["report"] = saved
        return _SESSION["report"]


def ask_followup(question: str) -> tuple[dict, int]:
    text = question.strip()
    if not text:
        return {"error": "请输入问题"}, 400
    if len(text) > 500:
        return {"error": "问题请控制在 500 字以内"}, 400
    report = current_report()
    with _SESSION_LOCK:
        history = list(_SESSION["history"])
    if report is None:
        return {"error": "请先分析一份日志，再继续提问"}, 400
    config = load_config()
    model = resolve_model(config["model"]) or default_model()
    key = (config.get("keys") or {}).get(host_of(model.base_url), "")
    result = answer_question(report, text, history, model.base_url, key, model.id)
    if result.get("error"):
        return result, 400
    turn_user = {"role": "user", "text": text}
    turn_assistant = {
        "role": "assistant",
        "text": result["answer"],
        "source": result["source"],
        "note": result.get("note") or "",
    }
    with _SESSION_LOCK:
        _SESSION["history"] = (history + [turn_user, turn_assistant])[-12:]
        result["history"] = list(_SESSION["history"])
    return result, 200


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print("[perf-triage]", fmt % args)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/config":
            self._json(public_config(load_config()))
            return
        if path == "/api/report":
            self._json({"report": load_home_report()}, cache=False)
            return
        if path in ("/", "/index.html"):
            body = WEB.read_bytes()
            self._bytes(body, "text/html; charset=utf-8", cache=False)
            return
        if path == "/trace":
            self._bytes(TRACE_PAGE.read_bytes(), "text/html; charset=utf-8", cache=False)
            return
        if path == "/perfetto.js":
            self._bytes(PERFETTO_JS.read_bytes(), "text/javascript; charset=utf-8", cache=False)
            return
        if path == "/api/traces":
            self._json({"traces": list_traces(), "analysis": load_analysis()})
            return
        file_match = re.fullmatch(r"/api/traces/(\d+)/file", path)
        if file_match:
            target = trace_file(file_match.group(1))
            if target is None:
                self._json({"error": "没有这份 trace"}, 404)
                return
            self._stream(target)
            return
        self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if path == "/api/config":
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "配置不是合法 JSON"}, 400)
                return
            try:
                saved = save_config(data)
            except ConfigError as exc:
                self._json({"error": str(exc)}, 400)
                return
            payload = public_config(saved)
            if data.get("api_key"):
                payload["probe"] = current_probe()
            self._json(payload)
            return
        if path == "/api/test-connection":
            self._json(current_probe())
            return
        if path == "/api/analyze":
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "请求不是合法 JSON"}, 400)
                return
            target = str(data.get("path") or "").strip()
            if not target:
                self._json({"error": "请先选择日志目录"}, 400)
                return
            payload, status = analyze_target(target)
            self._json(payload, status)
            return
        if path == "/api/ask":
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                self._json({"error": "请求不是合法 JSON"}, 400)
                return
            payload, status = ask_followup(str(data.get("question") or ""))
            self._json(payload, status)
            return
        if path == "/api/pick":
            try:
                chosen = pick_folder(load_config().get("last_path") or "")
            except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
                self._json({"error": f"无法打开目录选择：{exc}"}, 400)
                return
            self._json(finish_pick(chosen))
            return
        self._json({"error": "not found"}, 404)

    def _json(self, data: dict, status: int = 200, cache: bool = True) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._bytes(body, "application/json; charset=utf-8", status, cache)

    def _bytes(self, body: bytes, content_type: str, status: int = 200, cache: bool = True) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if not cache:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _stream(self, path: Path) -> None:
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(size))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)


def ensure_shortcut() -> None:
    if os.name != "nt":
        return
    desktop = Path(os.environ.get("USERPROFILE", "")) / "Desktop"
    link = desktop / "性能初筛.lnk"
    bat = ROOT / "一键安装.bat"
    if not desktop.is_dir() or link.exists() or not bat.exists():
        return
    env = os.environ.copy()
    env["PERF_TRIAGE_LINK"] = str(link)
    env["PERF_TRIAGE_BAT"] = str(bat)
    env["PERF_TRIAGE_HOME"] = str(ROOT)
    subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-Command",
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:PERF_TRIAGE_LINK); "
            "$s.TargetPath = $env:PERF_TRIAGE_BAT; "
            "$s.WorkingDirectory = $env:PERF_TRIAGE_HOME; "
            "$s.Save()",
        ],
        env=env,
        check=False,
    )


def main() -> None:
    ensure_shortcut()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}"
    print(f"性能初筛已启动：{url}")
    print("只监听本机。API Key 保存在", CONFIG)
    if os.environ.get("PERF_TRIAGE_NO_BROWSER") != "1":
        webbrowser.open(url)
    server.serve_forever()


if __name__ == "__main__":
    main()
