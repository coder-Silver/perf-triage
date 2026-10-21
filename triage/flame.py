"""Build a flame graph from Perfetto call stacks, or from nested slices."""

from __future__ import annotations

MAX_NODES = 24
MIN_SHARE = 0.004


def build_flame(stacks: list[tuple[list[str], float]]) -> dict | None:
    """Collapse root-first stacks into an inclusive flame tree."""
    root = {"name": "all", "value": 0.0, "children": {}}
    for frames, weight in stacks:
        if weight <= 0 or not frames:
            continue
        node = root
        node["value"] += weight
        for name in frames:
            label = (name or "[unknown]").strip() or "[unknown]"
            child = node["children"].get(label)
            if child is None:
                child = {"name": label, "value": 0.0, "children": {}}
                node["children"][label] = child
            child["value"] += weight
            node = child
    if root["value"] <= 0:
        return None
    return _export(root)


def flame_from_slices(rows: list[dict]) -> dict | None:
    """rows: id, parent_id, name, value. value is already inclusive."""
    nodes: dict[int, dict] = {}
    for row in rows:
        try:
            ident = int(row["id"])
            value = float(row["value"])
        except (TypeError, ValueError, KeyError):
            continue
        if value <= 0:
            continue
        parent = row.get("parent_id")
        if parent is None or parent == "":
            parent_id = None
        else:
            try:
                parent_id = int(parent)
            except (TypeError, ValueError):
                parent_id = None
        nodes[ident] = {
            "name": str(row.get("name") or "[unknown]")[:120],
            "value": value,
            "parent_id": parent_id,
            "children": [],
        }
    if not nodes:
        return None
    roots = []
    for node in nodes.values():
        parent = nodes.get(node["parent_id"])
        if parent is None or parent is node:
            roots.append(node)
        else:
            parent["children"].append(node)
    merged = _merge_slices(roots)
    total = sum(item["value"] for item in merged)
    if total <= 0:
        return None
    return _export({"name": "all", "value": total, "children": {item["name"]: item for item in merged}})


def _merge_slices(nodes: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for node in nodes:
        name = node["name"]
        current = grouped.get(name)
        if current is None:
            current = {"name": name, "value": 0.0, "kids": []}
            grouped[name] = current
        current["value"] += node["value"]
        current["kids"].extend(node["children"])
    merged = []
    for item in grouped.values():
        children = _merge_slices(item["kids"])
        child_total = sum(child["value"] for child in children)
        value = max(item["value"], child_total)
        merged.append({"name": item["name"], "value": value, "children": children})
    merged.sort(key=lambda item: item["value"], reverse=True)
    return merged


def _export(node: dict) -> dict:
    if "children" in node and isinstance(node["children"], dict):
        children = list(node["children"].values())
    else:
        children = list(node.get("children") or [])
    children.sort(key=lambda item: item["value"], reverse=True)
    kept = []
    other = 0.0
    total = node["value"] or 1
    for child in children:
        share = child["value"] / total
        if len(kept) >= MAX_NODES or share < MIN_SHARE:
            other += child["value"]
            continue
        kept.append(_export(child))
    if other > 0:
        kept.append({"name": "其他", "value": round(other, 3), "children": []})
    return {"name": node["name"], "value": round(float(node["value"]), 3), "children": kept}


def read_flame(processor, filename: str) -> dict | None:
    stacks = _callstacks(processor)
    if stacks:
        tree = build_flame(stacks)
        if tree:
            return {
                "file": filename,
                "kind": "调用栈",
                "unit": "采样",
                "root": tree,
            }
    rows = _slice_rows(processor)
    tree = flame_from_slices(rows)
    if not tree:
        return {
            "file": filename,
            "kind": "",
            "unit": "",
            "root": None,
            "note": f"{filename} 已打开，但没有 CPU 调用栈采样，也没有可嵌套的切片，所以没有火焰图。",
        }
    return {
        "file": filename,
        "kind": "切片耗时",
        "unit": "ms",
        "root": tree,
        "note": f"{filename} 没有 CPU 调用栈采样，火焰图按切片的嵌套耗时绘制。",
    }


def _callstacks(processor) -> list[tuple[list[str], float]]:
    for table in ("cpu_profile_stack_sample", "perf_sample"):
        counts = _query(processor, f"SELECT callsite_id, COUNT(*) AS weight FROM {table} GROUP BY callsite_id")
        if not counts:
            continue
        frames = _query(
            processor,
            """
            SELECT spc.id AS id, spc.parent_id AS parent_id, IFNULL(spf.name, '') AS name
            FROM stack_profile_callsite spc
            LEFT JOIN stack_profile_frame spf ON spc.frame_id = spf.id
            """,
        )
        if not frames:
            continue
        nodes = {}
        for row in frames:
            nodes[int(row["id"])] = (row.get("parent_id"), str(row.get("name") or "") or "[unknown]")
        stacks = []
        for row in counts:
            try:
                leaf = int(row["callsite_id"])
                weight = float(row["weight"])
            except (TypeError, ValueError, KeyError):
                continue
            frames_up = []
            seen = set()
            current = leaf
            while current and current not in seen and current in nodes:
                seen.add(current)
                parent, name = nodes[current]
                frames_up.append(name)
                try:
                    current = int(parent) if parent not in (None, 0, "") else 0
                except (TypeError, ValueError):
                    current = 0
            if frames_up:
                stacks.append((list(reversed(frames_up)), weight))
        if stacks:
            return stacks
    return []


def _slice_rows(processor) -> list[dict]:
    rows = _query(
        processor,
        """
        SELECT s.id AS id, s.parent_id AS parent_id, s.name AS name, s.dur / 1e6 AS value
        FROM slice s
        WHERE s.dur >= 200000
        ORDER BY s.dur DESC
        LIMIT 20000
        """,
    )
    return rows


def _query(processor, sql: str) -> list[dict]:
    try:
        result = processor.query(sql)
    except Exception:
        return []
    columns = list(getattr(result, "column_names", []) or [])
    rows = []
    for row in result:
        if columns:
            rows.append({name: getattr(row, name, None) for name in columns})
        else:
            rows.append(dict(getattr(row, "__dict__", {})))
    return rows
