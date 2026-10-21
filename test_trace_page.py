"""Trace files are cached for the viewer, and advice follows captured directions."""

import json
from pathlib import Path
import tempfile

import triage.trace_store as trace_store
from test_logs import SAMPLE
from triage.advice import trace_analysis
from triage.analyze import analyze_paths
from triage.trace_store import list_traces, store_traces, trace_file

_BELOW = "有数据但未达到 P0/P1/P2"


def test_store_and_advice() -> None:
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        previous = trace_store.CACHE
        trace_store.CACHE = root / "cache"
        try:
            trace = root / "demo.pftrace"
            trace.write_bytes(b"trace-bytes")
            log = root / "logcat.txt"
            log.write_text("not a trace", encoding="utf-8")
            stored = store_traces([log, trace], ["logcat.txt", "bundle/demo.pftrace"])
            assert list_traces()[0]["id"] == stored[0]["id"]
            assert trace_file(stored[0]["id"]).read_bytes() == b"trace-bytes"
            assert trace_file("../0") is None
            assert trace_file("nope") is None
        finally:
            trace_store.CACHE = previous
    assert len(stored) == 1
    assert stored[0]["name"] == "demo.pftrace"
    assert stored[0]["label"] == "bundle/demo.pftrace"
    report = {
        "upgrade": "版本 DEMO",
        "summary": {"p0": 1, "p1": 0, "p2": 0},
        "findings": [
            {
                "level": "P0",
                "category": "ANR",
                "process": "com.demo.app",
                "pid": "1234",
                "title": "分析窗口内出现 ANR",
                "event": "ANR",
                "time": "10-20 11:00:02.000",
                "evidence": ["文件 demo.pftrace", "ANR in com.demo.app"],
            }
        ],
    }
    analysis = trace_analysis(report)
    assert analysis["problems"][0]["dimension"] == "系统异常"
    assert "主线程" in analysis["problems"][0]["advice"]
    assert analysis["problems"][0]["evidence"] == "ANR in com.demo.app"
    assert [item["id"] for item in analysis["directions"]] == ["system"]
    assert analysis["directions"][0]["title"] == "系统异常"
    assert analysis["directions"][0]["present"] is True
    assert analysis["directions"][0]["severity"] == "P0"
    assert "主线程" in analysis["directions"][0]["advice"]
    assert "严重程度 P0" in analysis["directions"][0]["conclusion"]
    assert _BELOW not in analysis["directions"][0]["conclusion"]
    print("trace page data ok", stored[0]["id"])


def _ids(report: dict) -> list[str]:
    analysis = trace_analysis(report)
    assert all(item["present"] is True for item in analysis["directions"])
    blob = json.dumps(analysis["directions"], ensure_ascii=False)
    assert "未抓取" not in blob
    return [item["id"] for item in analysis["directions"]]


def test_memory_signal_omits_frame_direction() -> None:
    analysis = trace_analysis({"findings": [], "signals": {"memory": True, "frame": False}})
    assert _ids({"findings": [], "signals": {"memory": True}}) == ["memory"]
    memory = analysis["directions"][0]
    assert memory["title"] == "内存"
    assert memory["conclusion"] == _BELOW
    assert memory["severity"] == ""
    assert memory["advice"]
    assert "显示帧率" not in json.dumps(analysis, ensure_ascii=False)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(
            "10-20 11:00:07.000  5000  5000 E lmkd: Kill 'com.demo.bg' (5000), reason: lowmemorykiller device is low on memory\n",
            encoding="utf-8",
        )
        report = analyze_paths([path], "", "", "")
    assert report["signals"]["memory"] is True
    assert report["signals"]["frame"] is False
    assert _ids(report) == ["memory"]
    graded = trace_analysis(report)["directions"][0]
    assert graded["severity"] == "P2"
    assert "严重程度 P2" in graded["conclusion"]
    assert graded["advice"]
    print("memory signal omits frame")


def test_jank_has_frame_rate_conclusion() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(
            "10-20 11:00:05.000  3333  3333 E Choreographer: Skipped 42 frames! The application may be doing too much work on its main thread.\n",
            encoding="utf-8",
        )
        report = analyze_paths([path], "", "", "")
    assert _ids(report) == ["frame"]
    frame = trace_analysis(report)["directions"][0]
    assert frame["title"] == "显示帧率"
    assert frame["severity"] == "P1"
    assert "严重程度 P1" in frame["conclusion"]
    assert "42" in frame["conclusion"]
    assert frame["advice"]
    assert _BELOW not in frame["conclusion"]
    print("frame conclusion ok")


def test_short_jank_stays_below_grade() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(
            "10-20 11:00:05.000  3333  3333 E Choreographer: Skipped 2 frames!\n",
            encoding="utf-8",
        )
        report = analyze_paths([path], "", "", "")
    assert report["findings"] == []
    assert report["signals"]["frame"] is True
    analysis = trace_analysis(report)
    assert [item["id"] for item in analysis["directions"]] == ["frame"]
    assert analysis["directions"][0]["conclusion"] == _BELOW
    assert analysis["directions"][0]["severity"] == ""
    assert analysis["directions"][0]["advice"]
    print("below-grade frame ok")


def test_cpu_direction_follows_captured_sources() -> None:
    assert _ids({"findings": [], "signals": {"cpu_counter": True}}) == ["cpu"]
    assert _ids({"findings": [], "signals": {"sched": True}}) == ["sched"]
    assert _ids({"findings": [], "signals": {"freq": True}}) == ["power"]
    assert _ids({"findings": [], "signals": {}}) == []
    sched_only = {
        "findings": [
            {
                "level": "P1",
                "category": "调度",
                "process": "com.demo.app",
                "event": "主线程 Runnable 80 ms",
            }
        ],
        "signals": {},
    }
    assert _ids(sched_only) == ["sched"]
    assert trace_analysis(sched_only)["directions"][0]["severity"] == "P1"
    cpu = trace_analysis({"findings": [], "signals": {"cpu_counter": True}})["directions"][0]
    assert cpu["title"] == "CPU 使用率"
    assert cpu["conclusion"] == _BELOW
    assert "%" not in cpu["conclusion"]
    assert cpu["advice"]
    print("cpu sources ok")


def test_sample_log_directions_match_captured_data() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(SAMPLE, encoding="utf-8")
        report = analyze_paths([path], "", "", "")
    assert report["rules_only"] is True
    assert report["signals"]["cpu_counter"] is False
    assert _ids(report) == ["memory", "frame", "power", "system"]
    analysis = trace_analysis(report)
    by_id = {item["id"]: item for item in analysis["directions"]}
    assert by_id["frame"]["title"] == "显示帧率"
    assert by_id["frame"]["severity"] == "P1"
    assert by_id["system"]["severity"] == "P0"
    assert by_id["memory"]["severity"] == "P2"
    assert by_id["power"]["severity"] == "P2"
    assert "cpu" not in by_id
    assert "sched" not in by_id
    print("sample directions ok")


def test_cpu_usage_log_is_not_inferred_from_throttling() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(
            "10-20 11:00:04.000  1000  1000 I ActivityManager: CPU usage from 2000ms to 0ms ago:\n"
            "  12% 2222/com.demo.app: 8% user + 4% kernel\n"
            "  40% TOTAL: 20% user + 20% kernel\n",
            encoding="utf-8",
        )
        low = analyze_paths([path], "", "", "")
    assert low["rules_only"] is True
    assert low["signals"]["cpu_counter"] is True
    assert low["signals"]["freq"] is False
    assert low["findings"] == []
    assert _ids(low) == ["cpu"]
    cpu = trace_analysis(low)["directions"][0]
    assert cpu["title"] == "CPU 使用率"
    assert cpu["conclusion"] == _BELOW
    assert "%" not in cpu["conclusion"]
    assert cpu["advice"]

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(
            "10-20 11:00:04.000  1000  1000 I ActivityManager: CPU usage from 2000ms to 0ms ago:\n"
            "  92% 1000/system_server: 60% user + 32% kernel\n"
            "  160% 3333/com.demo.hot: 120% user + 40% kernel\n"
            "10-20 11:00:06.000  4000  4000 E ThermalService: CPU throttling due to temperature\n",
            encoding="utf-8",
        )
        high = analyze_paths([path], "", "", "")
    assert _ids(high) == ["cpu", "power"]
    by_id = {item["id"]: item for item in trace_analysis(high)["directions"]}
    assert by_id["cpu"]["severity"] == "P1"
    assert "160" in by_id["cpu"]["conclusion"]
    assert "92" in by_id["cpu"]["conclusion"]
    assert "严重程度 P1" in by_id["cpu"]["conclusion"]
    assert by_id["power"]["title"] == "限频/功耗"
    assert by_id["power"]["severity"] == "P2"
    assert "未抓取" not in json.dumps(trace_analysis(high), ensure_ascii=False)
    print("cpu usage log ok")


def _scan_built(fill) -> dict:
    from perfetto.trace_builder.proto_builder import TraceProtoBuilder
    from triage.trace import scan_trace

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "demo.pftrace"
        builder = TraceProtoBuilder()
        packet = builder.add_packet()
        packet.timestamp = 1000
        fill(builder, packet)
        path.write_bytes(builder.serialize())
        findings, _notes, _flame, signals = scan_trace(path)
    return {"findings": [item.to_dict() for item in findings], "signals": signals}


def test_frequency_and_idle_are_not_cpu_usage() -> None:
    def freq(_builder, packet) -> None:
        packet.ftrace_events.cpu = 0
        event = packet.ftrace_events.event.add()
        event.timestamp = 1000
        event.pid = 1
        event.cpu_frequency.state = 1800000
        event.cpu_frequency.cpu_id = 0

    report = _scan_built(freq)
    assert report["signals"]["freq"] is True
    assert report["signals"]["cpu_counter"] is False
    assert _ids(report) == ["power"]
    power = trace_analysis(report)["directions"][0]
    assert power["title"] == "限频/功耗"
    assert power["conclusion"] == _BELOW
    assert "CPU 使用率" not in json.dumps(trace_analysis(report)["directions"], ensure_ascii=False)

    def idle(_builder, packet) -> None:
        packet.ftrace_events.cpu = 0
        event = packet.ftrace_events.event.add()
        event.timestamp = 1000
        event.pid = 1
        event.cpu_idle.state = 0
        event.cpu_idle.cpu_id = 0

    idle_report = _scan_built(idle)
    assert idle_report["signals"]["cpu_counter"] is False
    assert idle_report["signals"]["freq"] is False
    assert _ids(idle_report) == []
    print("freq and idle are not cpu usage")


def test_cpu_times_ratio_is_graded_without_inventing_a_single_sample() -> None:
    from perfetto.trace_builder.proto_builder import TraceProtoBuilder
    from triage.trace import scan_trace

    def write(path: Path, samples: list[tuple[int, int, int]]) -> None:
        builder = TraceProtoBuilder()
        for ts, user, idle in samples:
            packet = builder.add_packet()
            packet.timestamp = ts
            stat = packet.sys_stats.cpu_stat.add()
            stat.cpu_id = 0
            stat.user_ns = user
            stat.idle_ns = idle
        path.write_bytes(builder.serialize())

    def report_for(samples: list[tuple[int, int, int]]) -> dict:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "cpu.pftrace"
            write(path, samples)
            findings, _notes, _flame, signals = scan_trace(path)
        return {"findings": [item.to_dict() for item in findings], "signals": signals}

    single = report_for([(1000, 900_000_000, 100_000_000)])
    assert single["signals"]["cpu_counter"] is True
    assert single["findings"] == []
    assert _ids(single) == ["cpu"]
    alone = trace_analysis(single)["directions"][0]
    assert alone["conclusion"] == _BELOW
    assert "%" not in alone["conclusion"]

    low = report_for([(1000, 0, 0), (1_000_000_000, 100_000_000, 900_000_000)])
    assert _ids(low) == ["cpu"]
    assert trace_analysis(low)["directions"][0]["conclusion"] == _BELOW
    assert "%" not in trace_analysis(low)["directions"][0]["conclusion"]

    high = report_for([(1000, 0, 0), (1_000_000_000, 900_000_000, 100_000_000)])
    assert high["signals"]["freq"] is False
    assert _ids(high) == ["cpu"]
    graded = trace_analysis(high)["directions"][0]
    assert graded["severity"] == "P1"
    assert "严重程度 P1" in graded["conclusion"]
    assert "90" in graded["conclusion"]
    assert graded["advice"]
    print("cpu.times ratio ok")


def test_home_report_restores_without_secrets() -> None:
    import threading
    import time
    import urllib.request
    from http.server import ThreadingHTTPServer

    import server

    secret = "sk-test-secret"
    report = {
        "summary": {"p0": 1, "p1": 0, "p2": 2, "files": 1},
        "upgrade": "版本 DEMO",
        "notes": ["无法读取 demo", "普通说明"],
        "processes": [
            {
                "level": "P0",
                "process": "com.demo.app",
                "pid": "1234",
                "api_key": secret,
                "problems": [
                    {
                        "level": "P0",
                        "dimension": "系统异常",
                        "title": "分析窗口内出现 ANR",
                        "impact": "主线程卡住",
                        "time": "10-20 11:00:02.000",
                        "event": "ANR",
                        "upgrade": "版本 DEMO",
                        "cause": "",
                        "evidence": ["ANR in com.demo.app"],
                    }
                ],
            }
        ],
        "findings": [{"level": "P0", "category": "ANR", "process": "com.demo.app", "api_key": secret}],
        "traces": [{"id": "0", "name": "demo.pftrace", "label": "demo.pftrace", "size": 4}],
        "rules_only": False,
        "ai_error": "模型接口调用失败：超时",
        "path": r"C:\logs\demo",
        "api_key": secret,
        "keys": {"api.example": secret},
        "flames": [{"root": {"name": secret}}],
        "signals": {"system": True},
    }
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        previous_cache = trace_store.CACHE
        previous_report = server._SESSION["report"]
        previous_history = list(server._SESSION["history"])
        trace_store.CACHE = root / "cache"
        server._SESSION["report"] = None
        server._SESSION["history"] = []
        httpd = None
        try:
            saved = trace_store.save_home_report(report)
            assert saved["rules_only"] is False
            assert trace_store.public_home_report({"summary": {}, "rules_only": True})["rules_only"] is True
            assert saved["path"] == r"C:\logs\demo"
            assert saved["notes"] == ["无法读取 demo", "普通说明"]
            assert saved["traces"] == report["traces"]
            assert "flames" not in saved and "signals" not in saved and "api_key" not in saved
            raw = (trace_store.CACHE / "report.json").read_text(encoding="utf-8")
            assert secret not in raw
            assert "api_key" not in raw
            assert "flames" not in raw
            loaded = trace_store.load_home_report()
            assert loaded["summary"]["p0"] == 1 and loaded["summary"]["p2"] == 2
            assert loaded["processes"][0]["process"] == "com.demo.app"
            assert loaded["processes"][0]["level"] == "P0"
            assert "api_key" not in loaded["processes"][0]
            assert loaded["findings"][0]["category"] == "ANR"
            assert "api_key" not in loaded["findings"][0]
            assert loaded["ai_error"] == "模型接口调用失败：超时"
            assert loaded["rules_only"] is False
            remembered = server.current_report()
            assert remembered["upgrade"] == "版本 DEMO"
            assert secret not in json.dumps(remembered, ensure_ascii=False)

            (trace_store.CACHE / "report.json").unlink()
            trace_store.save_analysis(
                {
                    "summary": {"p0": 0, "p1": 1, "p2": 0},
                    "upgrade": "仅有旧分析",
                    "problems": [
                        {
                            "level": "P1",
                            "process": "com.old.app",
                            "pid": "9",
                            "dimension": "显示卡顿",
                            "title": "连续掉帧",
                            "event": "jank",
                            "time": "10-20 11:00:03.000",
                            "evidence": "jank",
                        }
                    ],
                    "directions": [{"id": "frame"}],
                }
            )
            (trace_store.CACHE / "manifest.json").write_text(
                json.dumps([{"id": "0", "name": "old.pftrace", "label": "old.pftrace", "size": 2}]),
                encoding="utf-8",
            )
            server._SESSION["report"] = None
            fallback = trace_store.load_home_report()
            assert fallback["upgrade"] == "仅有旧分析"
            assert fallback["processes"][0]["level"] == "P1"
            assert fallback["processes"][0]["process"] == "com.old.app"
            assert fallback["processes"][0]["problems"][0]["evidence"] == ["jank"]
            assert fallback["traces"][0]["name"] == "old.pftrace"
            assert "rules_only" not in fallback
            assert secret not in json.dumps(fallback, ensure_ascii=False)

            httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
            port = httpd.server_address[1]
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()

            def fetch_report() -> tuple[dict, str]:
                last_error = None
                for _ in range(20):
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/report", timeout=2) as response:
                            payload = json.loads(response.read().decode("utf-8"))
                            return payload, response.headers.get("Cache-Control") or ""
                    except Exception as exc:
                        last_error = exc
                        time.sleep(0.05)
                raise AssertionError(last_error)

            payload, cache_control = fetch_report()
            assert cache_control == "no-store"
            assert payload["report"]["upgrade"] == "仅有旧分析"
            assert secret not in json.dumps(payload, ensure_ascii=False)
            trace_store.CACHE = root / "empty"
            server._SESSION["report"] = None
            empty, _header = fetch_report()
            assert empty == {"report": None}
            assert server.current_report() is None
        finally:
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()
            server._SESSION["report"] = previous_report
            server._SESSION["history"] = previous_history
            trace_store.CACHE = previous_cache
    print("home report restore ok")


def test_open_trace_button_is_outside_the_form() -> None:
    root = Path(__file__).resolve().parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    form = html.split('<form id="run">', 1)[1].split("</form>", 1)[0]
    assert "open-trace" not in form
    assert "查看 trace 分析" not in form
    out = html.split('id="out"', 1)[1].split("</section>", 1)[0]
    assert 'id="open-trace"' in out
    assert 'type="button"' in out
    assert "查看 trace 分析" in out
    assert 'href="/trace"' not in out
    assert 'target="_blank"' not in html
    assert "window.open" not in html
    assert 'id="trace-layer"' in html
    assert "返回结论" in html
    assert "/perfetto.js" in html
    script = html.split("<script>", 1)[1]
    assert 'setTraceLink("busy")' in script
    assert 'setTraceLink("ready")' in script
    assert 'setTraceLink("hidden")' in script
    assert "startPreload" in script
    assert "traceCount > 0" in script
    assert "/api/report" in script
    assert "async function restoreConclusion" in script
    restore = script.split("async function restoreConclusion", 1)[1].split('setTraceLink("hidden")', 1)[0]
    assert "render(report)" in restore
    assert 'setTraceLink("ready")' not in restore
    ready = script.split("if (traceCount > 0)", 1)[1].split("} else {", 1)[0]
    assert "startPreload" in ready
    page = (root / "web" / "trace.html").read_text(encoding="utf-8")
    host = (root / "web" / "perfetto.js").read_text(encoding="utf-8")
    assert '<a href="/">返回主页</a>' in page
    assert "/perfetto.js" in page
    assert "?ts=" not in page and "?ts=" not in host
    assert "未抓取" not in page and "未抓取" not in host
    assert "postMessage" in host
    assert "https://ui.perfetto.dev" in host
    assert "mode=embedded" in host
    assert "PING" in host and "PONG" in host
    assert "/file" in host
    assert "arrayBuffer" in host
    print("trace button placement ok")


def test_folder_picker_is_foreground_and_cancel_does_not_analyze() -> None:
    import os
    import subprocess

    import server

    script = server.folder_picker_script()
    assert "TopMost" in script
    assert "SetForegroundWindow" in script
    assert "ForceForeground" in script
    assert "FOS_PICKFOLDERS" in script
    assert "Opacity = 0" not in script
    assert "Opacity = 1" in script
    assert script.index("PERF_TRIAGE_PICK_SELFTEST") < script.index("Picker]::Choose")
    saved = []
    original_save = server.save_config

    def remember(data):
        saved.append(data)
        raise AssertionError("取消不应该写入配置")

    server.save_config = remember
    try:
        assert server.finish_pick("") == {"cancelled": True}
        assert saved == []
        assert "analyze_target" not in server.finish_pick.__code__.co_names
    finally:
        server.save_config = original_save
    html = (Path(__file__).resolve().parent / "web" / "index.html").read_text(encoding="utf-8")
    browse = html.split('$("browse").addEventListener', 1)[1].split('$("run").addEventListener', 1)[0]
    assert "cancelled" in browse
    assert "analyze(" not in browse
    source = Path(server.__file__).read_text(encoding="utf-8")
    pick = source.split('if path == "/api/pick":', 1)[1].split("not found", 1)[0]
    assert "finish_pick" in pick
    assert "analyze_target" not in pick
    env = os.environ.copy()
    env["PERF_TRIAGE_PICK_SELFTEST"] = "1"
    with tempfile.NamedTemporaryFile("w", suffix=".ps1", delete=False, encoding="utf-8-sig") as handle:
        handle.write(script)
        script_path = handle.name
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-STA", "-ExecutionPolicy", "Bypass", "-File", script_path],
            capture_output=True,
            env=env,
            timeout=90,
            check=False,
        )
    finally:
        os.remove(script_path)
    assert completed.returncode == 0, completed.stderr
    assert server._picker_stdout(completed.stdout) == "SELFTEST_OK"
    print("folder picker foreground ok")


def test_mac_cancel_is_empty_not_failure() -> None:
    import server

    assert server._mac_cancelled("execution error: User canceled. (-128)")
    assert not server._mac_cancelled("osascript: command not found")
    print("mac folder cancel ok")


if __name__ == "__main__":
    test_store_and_advice()
    test_memory_signal_omits_frame_direction()
    test_jank_has_frame_rate_conclusion()
    test_short_jank_stays_below_grade()
    test_cpu_direction_follows_captured_sources()
    test_sample_log_directions_match_captured_data()
    test_cpu_usage_log_is_not_inferred_from_throttling()
    test_frequency_and_idle_are_not_cpu_usage()
    test_cpu_times_ratio_is_graded_without_inventing_a_single_sample()
    test_home_report_restores_without_secrets()
    test_open_trace_button_is_outside_the_form()
    test_folder_picker_is_foreground_and_cancel_does_not_analyze()
    test_mac_cancel_is_empty_not_failure()
