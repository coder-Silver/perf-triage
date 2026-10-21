"""Flame graphs collapse stacks and can be read from a small Perfetto trace."""

from pathlib import Path
import tempfile

from perfetto.trace_builder.proto_builder import TraceProtoBuilder
from perfetto.trace_processor import TraceProcessor, TraceProcessorConfig

from triage.flame import build_flame, read_flame
from triage.trace import bundled_shell, scan_trace


def test_build_flame_merges_same_stack() -> None:
    tree = build_flame([
        (["doFrame", "draw", "gl"], 2),
        (["doFrame", "draw"], 3),
        (["doFrame", "input"], 1),
    ])
    assert tree["name"] == "all"
    assert tree["value"] == 6
    frame = tree["children"][0]
    assert frame["name"] == "doFrame"
    assert frame["value"] == 6
    draw = next(child for child in frame["children"] if child["name"] == "draw")
    assert draw["value"] == 5
    gl = next(child for child in draw["children"] if child["name"] == "gl")
    assert gl["value"] == 2
    print("flame merge ok")


def _write_trace(path: Path) -> None:
    builder = TraceProtoBuilder()
    descriptor = builder.add_packet()
    descriptor.trusted_packet_sequence_id = 1
    descriptor.sequence_flags = 1
    descriptor.track_descriptor.uuid = 122
    descriptor.track_descriptor.process.pid = 100
    descriptor.track_descriptor.process.process_name = "demo.app"
    thread = builder.add_packet()
    thread.trusted_packet_sequence_id = 1
    thread.sequence_flags = 1
    thread.track_descriptor.uuid = 123
    thread.track_descriptor.parent_uuid = 122
    thread.track_descriptor.name = "main"
    thread.track_descriptor.thread.pid = 100
    thread.track_descriptor.thread.tid = 100
    thread.track_descriptor.thread.thread_name = "demo.app"

    def mark(timestamp: int, kind: int, name: str = "") -> None:
        packet = builder.add_packet()
        packet.timestamp = timestamp
        packet.trusted_packet_sequence_id = 1
        packet.track_event.type = kind
        packet.track_event.track_uuid = 123
        if name:
            packet.track_event.name = name

    mark(0, 1, "doFrame")
    mark(10_000_000, 1, "draw")
    mark(20_000_000, 1, "gl")
    mark(40_000_000, 2)
    mark(60_000_000, 2)
    mark(100_000_000, 2)
    mark(200_000_000, 1, "doFrame")
    mark(210_000_000, 1, "draw")
    mark(280_000_000, 2)
    mark(300_000_000, 2)
    path.write_bytes(builder.serialize())


def test_trace_slice_flame() -> None:
    shell = bundled_shell()
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "demo.pftrace"
        _write_trace(path)
        config = TraceProcessorConfig(bin_path=shell) if shell else TraceProcessorConfig()
        processor = TraceProcessor(trace=str(path), config=config)
        try:
            flame = read_flame(processor, path.name)
        finally:
            processor.close()
        findings, notes, scanned, signals = scan_trace(path)
    assert flame and flame["root"], flame
    assert flame["kind"] == "切片耗时"
    assert scanned and scanned["root"]["value"] > 0
    names = _names(scanned["root"])
    assert scanned["root"]["value"] == 200
    frame = next(child for child in scanned["root"]["children"] if child["name"] == "doFrame")
    draw = next(child for child in frame["children"] if child["name"] == "draw")
    assert any(child["name"] == "gl" for child in draw["children"])
    assert isinstance(findings, list)
    assert isinstance(notes, list)
    assert signals == {
        "memory": False,
        "cpu_counter": False,
        "sched": False,
        "freq": False,
        "frame": False,
        "system": False,
    }
    from triage.advice import trace_analysis
    assert trace_analysis({"findings": [item.to_dict() for item in findings], "signals": signals})["directions"] == []
    print("trace flame ok", names, "value", scanned["root"]["value"])


def _names(node: dict) -> set[str]:
    found = {node["name"]}
    for child in node.get("children") or []:
        found.update(_names(child))
    return found


if __name__ == "__main__":
    test_build_flame_merges_same_stack()
    test_trace_slice_flame()
