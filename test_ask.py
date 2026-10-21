"""Follow-up answers stay inside the graded report when no model is configured."""

from triage.analyze import analyze_paths
from triage.ask import answer_locally, answer_question
from test_logs import SAMPLE, SPAM


def _report() -> dict:
    from pathlib import Path
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "logcat.txt"
        path.write_text(SAMPLE + "\n" + SPAM, encoding="utf-8")
        return analyze_paths([path], "", "", "")


def test_rules_answer_names_the_process() -> None:
    report = _report()
    assert report["rules_only"] is True
    text = answer_locally(report, "com.demo.app 为什么是这个等级")
    assert "com.demo.app" in text
    assert "1234" in text
    assert "P0" in text
    assert "ANR" in text
    missed = answer_locally(report, "com.not.exist 发生了什么")
    assert "没有和这个问题对应的证据" in missed
    empty = answer_question(None, "总结", [], "", "", "")
    assert empty["error"]
    ruled = answer_question(report, "有哪些 P0", [], "https://api.deepseek.com", "", "deepseek-flash")
    assert ruled["source"] == "rules"
    assert "com.demo.app" in ruled["answer"]
    assert "system_server" in ruled["answer"]
    print("ask rules ok")


if __name__ == "__main__":
    test_rules_answer_names_the_process()
