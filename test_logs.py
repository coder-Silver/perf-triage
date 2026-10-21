import json
from pathlib import Path
import tempfile

from triage.advice import trace_analysis
from triage.analyze import analyze_paths

SAMPLE = """\
10-20 11:00:00.100  1000  1000 I SystemServer: ro.build.display.id=RQ1A.210105.003
10-20 11:00:01.000  1800  1800 E Watchdog: WATCHDOG KILLING SYSTEM PROCESS: system_server
10-20 11:00:02.000  1234  1234 E ActivityManager: ANR in com.demo.app (com.demo.app/1234)
10-20 11:00:02.100  1234  1234 E ActivityManager: Reason: Input dispatching timed out
10-20 11:00:03.000  2222  2222 E AndroidRuntime: FATAL EXCEPTION: main
10-20 11:00:03.100  2222  2222 E AndroidRuntime: Process: com.demo.game, PID: 2222
10-20 11:00:04.000  3333  3333 E Foo: java.lang.IllegalStateException: boom
10-20 11:00:05.000  3333  3333 E Choreographer: Skipped 42 frames! The application may be doing too much work on its main thread.
10-20 11:00:06.000  4000  4000 E ThermalService: CPU throttling due to temperature
10-20 11:00:07.000  5000  5000 E lmkd: Kill 'com.demo.bg' (5000), reason: lowmemorykiller device is low on memory
10-20 11:00:08.000  1000  1000 W SystemServer: Slow operation on system_server took 8000ms
10-20 11:00:09.000  1000  1000 I update_engine: OTA 升级写入完成
"""

SPAM = "\n".join(
    f"10-20 11:01:{i:02d}.000  3333  3333 E Foo: java.lang.IllegalStateException: boom {i}"
    for i in range(15)
)


def test_grades() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(SAMPLE + "\n" + SPAM, encoding="utf-8")
        report = analyze_paths([path], "", "", "")
    levels = {(item["level"], item["category"]) for item in report["findings"]}
    assert ("P0", "ANR") in levels, levels
    assert ("P0", "Watchdog") in levels, levels
    assert ("P0", "system_server") in levels, levels
    assert ("P1", "进程崩溃") in levels, levels
    assert ("P1", "异常刷屏") in levels, levels
    assert ("P1", "连续掉帧") in levels, levels
    assert ("P2", "限频") in levels, levels
    assert ("P2", "内存压力") in levels, levels
    anr = next(item for item in report["findings"] if item["category"] == "ANR")
    assert anr["pid"] == "1234"
    assert "RQ1A.210105.003" in anr["upgrade"]
    assert "OTA" in anr["upgrade"] or "升级" in anr["upgrade"]
    crash = next(item for item in report["findings"] if item["category"] == "进程崩溃")
    assert "com.demo.game" in crash["impact"]
    assert report["summary"]["p0"] >= 3
    print("ok", report["summary"])


NOISE = """\
WINDOW MANAGER LAST ANR (dumpsys window lastanr)
  <no ANR has occurred since boot>
10-19 19:52:07.407 10054  2305  2348 I GPK_ANRWatchDog: mainHandler.sendEmptyMessage(MESSAGE_WATCHDOG_TIME_TICK)
01-01 08:00:37.470  1000  1363  1363 I PackageWatchdog: Syncing state, reason: added new observer
  434  2649 lmkd         20   0  0.0 S 2.0G 5.1M     lmkd
10-20 09:49:54.620  1000  2084  2084 D Mercury : at[Throttler.ensure(SlideHelper.kt:349)]
In thermal throttling?: false
10-12 18:52:57.691  1000  1363  1563 W Looper  : Slow dispatch took 192ms android.fg
10-20 09:49:50.889  1000  2084  2101 I OpenGLRenderer: Davey! duration=60202939ms; Flags=0
10-20 15:15:23.866  lmkd   434   434 I lowmemorykiller: 6 memory pressure events were skipped after a kill!
10-20 15:15:23.867  lmkd   434   434 I lowmemorykiller: Ignoring pressure since per-zone watermarks ok
10-20 15:15:23.816  lmkd   434   434 I lowmemorykiller: Reclaimed 92984kB at oom_score_adj 606
"""


def test_noise_is_not_a_problem() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(NOISE, encoding="utf-8")
        report = analyze_paths([path], "", "", "")
    assert report["findings"] == [], report["findings"]
    assert report["processes"] == []
    assert report["signals"] == {
        "memory": False,
        "cpu_counter": False,
        "sched": False,
        "freq": False,
        "frame": False,
        "system": False,
    }
    analysis = trace_analysis(report)
    assert analysis["directions"] == []
    assert "未抓取" not in json.dumps(analysis, ensure_ascii=False)
    print("noise hidden ok")


def test_only_problem_processes_are_listed() -> None:
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(SAMPLE + "\n" + SPAM + "\n" + NOISE, encoding="utf-8")
        report = analyze_paths([path], "", "", "")
    names = {item["process"] for item in report["processes"]}
    assert "com.demo.app" in names, names
    assert "com.demo.game" in names, names
    assert "system_server" in names, names
    assert "com.demo.bg" in names, names
    assert "PackageWatchdog" not in names
    assert "GPK_ANRWatchDog" not in names
    assert "lmkd" not in names
    assert all(item["problems"] for item in report["processes"])
    print("processes", [(item["level"], item["process"]) for item in report["processes"]])


if __name__ == "__main__":
    test_grades()
    test_noise_is_not_a_problem()
    test_only_problem_processes_are_listed()
