#!/usr/bin/env python3
"""Score the corrected address keyed structural prototype.

The scorer consumes only recovered facts.  Labels are intentionally handled by
the main ``evaluate_rankings.py`` evaluator.  Function IDs are entry addresses; names are used only when
resolving configured source and dangerous API rules.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path
from typing import Iterable


# Built-in legacy defaults. The archived experiment also supplies CSV rule
# extensions; callers must pass those files explicitly for the configured run.
DEFAULT_DANGEROUS: dict[str, tuple[str, str, float]] = {
    "gets": ("input", "CWE-120", 1.0),
    "strcpy": ("string-copy", "CWE-120", 1.0),
    "strcat": ("string-copy", "CWE-120", 0.95),
    "sprintf": ("format", "CWE-120,CWE-134", 0.95),
    "vsprintf": ("format", "CWE-120,CWE-134", 0.95),
    "printf": ("format", "CWE-134", 0.65),
    "fprintf": ("format", "CWE-134", 0.6),
    "scanf": ("input", "CWE-120", 0.75),
    "memcpy": ("memory-copy", "CWE-120,CWE-787", 0.8),
    "memmove": ("memory-copy", "CWE-120,CWE-787", 0.65),
    "system": ("command", "CWE-78", 1.0),
    "popen": ("command", "CWE-78", 0.95),
    "execve": ("command", "CWE-78", 0.85),
    "free": ("allocator", "CWE-415,CWE-416", 0.45),
    "malloc": ("allocator", "CWE-122,CWE-190", 0.35),
}
DEFAULT_SOURCES = {
    "read", "recv", "recvfrom", "scanf", "fscanf", "gets", "fgets",
    "getenv", "fread", "argv",
}
ALIASES = {
    "__isoc99_scanf": "scanf",
    "__isoc99_fscanf": "fscanf",
    "__isoc99_sscanf": "sscanf",
}
DEFAULT_CONFIG = {
    "weights": {"danger": 2.0, "reach": 1.5, "distance": 1.0, "path": 0.5, "cfg": 0.4},
    "semantic_weight": 1.5,
    "semantic_base": 0.85,
    "semantic_context_window": 8,
    "semantic_context_weight": 0.0,
    "semantic_context_policy": "register_mentions",
    "max_depth": 4,
    "alpha": 0.25,
    "top_k": 3,
    "path_cap": 10000,
    "search_state_cap": 100000,
    "path_normalizer": 10.0,
    "directional_weight": 0.0,
    "directional_max_depth": 4,
    "directional_replace_reach": False,
}


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Iterable[dict[str, object]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def norm_symbol(name: str) -> str:
    """Normalize resolver names without changing address identity."""
    value = (name or "").strip()
    for _ in range(3):
        normalized = re.sub(r"(?:@@?|\.)(?:GLIBC|GLIBCXX|plt)(?:[_A-Za-z0-9.]+)?$", "", value, flags=re.I)
        normalized = re.sub(r"@plt$|\.plt$", "", normalized, flags=re.I)
        if normalized == value:
            break
        value = normalized
    value = value.removeprefix("__GI_")
    return ALIASES.get(value, value)


def load_config(path: Path | None) -> dict[str, object]:
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if path:
        with path.open("r", encoding="utf-8") as handle:
            supplied = json.load(handle)
        for key, value in supplied.items():
            if key == "weights":
                config["weights"].update(value)
            else:
                config[key] = value
    config["max_depth"] = max(0, int(config["max_depth"]))
    config["alpha"] = float(config["alpha"])
    config["top_k"] = max(1, int(config["top_k"]))
    config["path_cap"] = max(1, int(config["path_cap"]))
    config["search_state_cap"] = max(1, int(config["search_state_cap"]))
    config["path_normalizer"] = max(1.0, float(config["path_normalizer"]))
    config["directional_weight"] = max(0.0, float(config["directional_weight"]))
    config["directional_max_depth"] = max(0, int(config["directional_max_depth"]))
    config["directional_replace_reach"] = bool(config["directional_replace_reach"])
    config["semantic_weight"] = max(0.0, float(config["semantic_weight"]))
    config["semantic_base"] = max(0.0, float(config["semantic_base"]))
    config["semantic_context_window"] = max(0, int(config["semantic_context_window"]))
    config["semantic_context_weight"] = max(0.0, float(config["semantic_context_weight"]))
    config["weights"] = {key: float(value) for key, value in config["weights"].items()}
    return config


def load_dangerous(path: Path | None) -> dict[str, tuple[str, str, float]]:
    rules = dict(DEFAULT_DANGEROUS)
    if not path:
        return rules
    if not path.is_file():
        raise FileNotFoundError(path)
    for row in read_csv(path):
        name = norm_symbol(row.get("name", ""))
        if not name:
            continue
        category = row.get("category", "unknown") or "unknown"
        cwe = row.get("cwe", "")
        raw_weight = (row.get("base_weight", "") or "").strip()
        base = float(raw_weight) if raw_weight else rules.get(name, ("", "", 0.5))[2]
        rules[name] = (category, cwe, base)
    return rules


def load_sources(path: Path | None) -> set[str]:
    sources = {norm_symbol(item) for item in DEFAULT_SOURCES}
    if path:
        if not path.is_file():
            raise FileNotFoundError(path)
        sources.update(norm_symbol(row.get("name", "")) for row in read_csv(path))
    return {item for item in sources if item}


def as_bool(row: dict[str, str], key: str) -> bool:
    return (row.get(key, "") or "").strip().lower() in {"1", "true", "yes"}


def is_candidate(row: dict[str, str]) -> bool:
    """Keep every genuine recovered executable body in the candidate universe."""
    if as_bool(row, "is_external") or as_bool(row, "is_thunk"):
        return False
    try:
        executable_size = int(float(row.get("executable_body_size", "0") or 0))
    except ValueError:
        executable_size = 0
    return bool(row.get("function_id") or row.get("entry_address")) and executable_size > 0


def function_id(row: dict[str, str]) -> str:
    return row.get("function_id", "") or row.get("entry_address", "") or row.get("function", "")


def function_name(row: dict[str, str]) -> str:
    return row.get("name", "") or row.get("function_name", "") or row.get("function", "")


def number(row: dict[str, str], key: str) -> float:
    try:
        return float(row.get(key, "") or 0)
    except ValueError:
        return 0.0


def cfg_complexity(row: dict[str, str]) -> float:
    bb = number(row, "bb_count")
    edges = number(row, "edge_count")
    if bb <= 0:
        return 0.0
    cyclomatic = max(1.0, edges - bb + 2.0)
    return min(1.0, math.log1p(cyclomatic) / math.log1p(20.0))


def aggregate_risks(risks: list[float], alpha: float, top_k: int) -> float:
    """Apply the fixed max-plus-top-k aggregation to a score interval side."""
    if not risks:
        return 0.0
    ordered = sorted(risks, reverse=True)
    top = ordered[:top_k]
    return ordered[0] + alpha * (sum(top) / len(top))


def evidence_tier(has_evidence: bool, function_reach: float,
                  directional_reach: int) -> int:
    """Classify provenance strength without treating a tier as a label."""
    if directional_reach:
        return 3
    if function_reach > 0:
        return 2
    return 1 if has_evidence else 0


UNVERIFIED_DIRECTION_STATUSES = {"unavailable_cfg", "no_source_callsite", "unavailable", ""}


def interval_status(lower: float, upper: float, directional_status: str,
                    path_truncated: bool = False, directional_truncated: bool = False) -> str:
    """Retain incomplete searches even when the two heuristic scores agree.

    A witness can coexist with a truncated search. ``bounded`` means endpoint
    agreement only; it does not certify complete program semantics.
    """
    if path_truncated or directional_truncated or directional_status == "search_truncated":
        return "search_truncated"
    if directional_status in UNVERIFIED_DIRECTION_STATUSES:
        return "unverified_direction"
    if abs(upper - lower) < 1e-9:
        return "bounded"
    return "directional_disagreement"


def aggregate_interval_provenance(
    lower: float, upper: float, rows: list[dict[str, object]]
) -> dict[str, object]:
    """Keep provenance from every evidence site, including sites outside top-k.

    Flags are independent of width and of each other. Directional truncation
    describes the shared bounded search, not a proven omission at each site.
    """
    path_truncated = int(any(int(row.get("path_truncated", 0)) for row in rows))
    directional_truncated = int(any(int(row.get("directional_truncated", 0)) for row in rows))
    search_truncated = int(path_truncated or directional_truncated or any(
        row.get("directional_status") == "search_truncated" for row in rows))
    direction_unverified = int(any(
        row.get("directional_status", "") in UNVERIFIED_DIRECTION_STATUSES for row in rows))
    if not rows:
        status = "no_evidence"
    elif search_truncated:
        status = "search_truncated"
    elif direction_unverified:
        status = "unverified_direction"
    else:
        status = "bounded" if lower == upper else "partial_uncertainty"
    return {
        "uncertainty_status": status,
        "path_truncated": path_truncated,
        "directional_truncated": directional_truncated,
        "search_truncated": search_truncated,
        "direction_unverified": direction_unverified,
    }


def build_graph(
    calls: list[dict[str, str]], candidate_ids_by_binary: dict[str, set[str]]
) -> dict[str, dict[str, tuple[str, ...]]]:
    by_binary: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for row in calls:
        binary = row.get("binary", "")
        caller = row.get("caller_id", "")
        callee = row.get("callee_id", "")
        candidate_ids = candidate_ids_by_binary.get(binary, set())
        if caller in candidate_ids and callee in candidate_ids:
            by_binary[binary][caller].add(callee)
    return {
        binary: {node: tuple(sorted(targets)) for node, targets in adjacency.items()}
        for binary, adjacency in by_binary.items()
    }


def bounded_paths(
    graph: dict[str, tuple[str, ...]],
    starts: set[str],
    target: str,
    max_depth: int,
    path_cap: int,
    state_cap: int,
) -> tuple[int, int | None, bool]:
    """Count deterministic simple paths with explicit cycle, depth and cap rules."""
    if not starts or not target:
        return 0, None, False
    if target in starts:
        # Compatibility rule: a source host is reachable from itself at d=0.
        return 1, 0, False
    count = 0
    best: int | None = None
    states = 0
    truncated = False
    stack = [(start, 0, (start,)) for start in sorted(starts) if start]
    while stack:
        node, depth, path = stack.pop()
        states += 1
        if states > state_cap:
            truncated = True
            break
        if depth >= max_depth:
            continue
        for nxt in reversed(graph.get(node, ())):
            if nxt in path:
                continue
            distance = depth + 1
            if nxt == target:
                count += 1
                best = distance if best is None else min(best, distance)
                if count >= path_cap:
                    truncated = True
                    return count, best, truncated
                continue
            stack.append((nxt, distance, path + (nxt,)))
    return count, best, truncated


def source_hosts(
    callsites: list[dict[str, str]], source_names: set[str], candidate_ids_by_binary: dict[str, set[str]]
) -> dict[str, set[str]]:
    hosts: dict[str, set[str]] = defaultdict(set)
    for row in callsites:
        host = row.get("caller_id", "") or row.get("host", "")
        binary = row.get("binary", "")
        if host not in candidate_ids_by_binary.get(binary, set()):
            continue
        if norm_symbol(row.get("callee_name", "")) in source_names:
            hosts[binary].add(host)
    return hosts


def address_value(raw: str) -> int | None:
    """Parse the hexadecimal address format emitted by the Ghidra exporter."""
    value = (raw or "").strip()
    if not value:
        return None
    value = value.rsplit(":", 1)[-1]
    try:
        return int(value, 16)
    except ValueError:
        return None


def directional_key(kind: str, row: dict[str, str | object]) -> tuple[str, str, str, str]:
    """Return an address-keyed identity for a callsite or inferred event."""
    if kind == "call":
        function = str(row.get("caller_id", "") or row.get("host", ""))
        identifier = str(row.get("callsite_id", "") or row.get("address", ""))
    else:
        function = str(row.get("function_id", ""))
        identifier = str(row.get("instruction", "") or row.get("address", ""))
    return kind, str(row.get("binary", "")), function, identifier


def _cfg_reachable(adjacency: dict[str, tuple[str, ...]], start: str | None,
                   target: str | None) -> bool:
    if not start or not target:
        return False
    if start == target:
        return True
    seen = {start}
    stack = [start]
    while stack:
        node = stack.pop()
        for nxt in adjacency.get(node, ()):
            if nxt == target:
                return True
            if nxt not in seen:
                seen.add(nxt)
                stack.append(nxt)
    return False


def build_directional_evidence(
    functions: list[dict[str, str]],
    callsites: list[dict[str, str]],
    basic_blocks: list[dict[str, str]],
    cfg_edges: list[dict[str, str]],
    semantic_events: list[dict[str, object]],
    source_names: set[str],
    dangerous_names: set[str],
    candidate_ids_by_binary: dict[str, set[str]],
    max_depth: int,
    path_cap: int,
    state_cap: int,
) -> dict[tuple[str, str, str, str], dict[str, object]]:
    """Find bounded, directionally ordered source-to-site witnesses.

    Function-level call-graph reachability is intentionally insufficient here:
    it can connect a source and sink that occur in reverse order or on mutually
    exclusive CFG branches. This routine first orders sites using recovered
    intra-function CFG edges, then follows resolved internal callsites into
    callee entry regions. It reports an explicit status when no witness is
    available; absence is never treated as positive evidence.
    """
    candidate_functions: dict[tuple[str, str], dict[str, str]] = {}
    for row in functions:
        identifier = function_id(row)
        binary = row.get("binary", "")
        if identifier in candidate_ids_by_binary.get(binary, set()):
            candidate_functions[(binary, identifier)] = row

    block_starts: dict[tuple[str, str], list[tuple[int, str]]] = defaultdict(list)
    for row in basic_blocks:
        binary = row.get("binary", "")
        function = row.get("function_id", "")
        block = row.get("block_id", "")
        address = address_value(block)
        if address is not None and (binary, function) in candidate_functions:
            block_starts[(binary, function)].append((address, block))
    for values in block_starts.values():
        values.sort()

    cfg: dict[tuple[str, str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for row in cfg_edges:
        key = (row.get("binary", ""), row.get("function_id", ""))
        if key not in candidate_functions:
            continue
        source = row.get("source_id", "")
        target = row.get("target_id", "")
        if source and target:
            cfg[key][source].add(target)
    cfg_tuple = {
        key: {source: tuple(sorted(targets)) for source, targets in adjacency.items()}
        for key, adjacency in cfg.items()
    }

    def block_for(binary: str, function: str, address: int | None) -> str | None:
        if address is None:
            return None
        values = block_starts.get((binary, function), [])
        selected = None
        for start, block in values:
            if start > address:
                break
            selected = block
        return selected

    sites: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for row in callsites:
        binary = row.get("binary", "")
        function = row.get("caller_id", "") or row.get("host", "")
        if function not in candidate_ids_by_binary.get(binary, set()):
            continue
        key = directional_key("call", row)
        callee = norm_symbol(row.get("callee_name", ""))
        address = address_value(row.get("address", ""))
        sites[key] = {
            "key": key, "binary": binary, "function": function,
            "address": address, "block": block_for(binary, function, address),
            "callee_id": row.get("callee_id", ""), "is_source": callee in source_names,
            "is_target": callee in dangerous_names, "kind": "call",
        }
    for row in semantic_events:
        binary = str(row.get("binary", ""))
        function = str(row.get("function_id", ""))
        if function not in candidate_ids_by_binary.get(binary, set()):
            continue
        key = directional_key("event", row)
        address = address_value(str(row.get("address", "")))
        sites[key] = {
            "key": key, "binary": binary, "function": function,
            "address": address, "block": block_for(binary, function, address),
            "callee_id": "", "is_source": False, "is_target": True, "kind": "event",
        }

    by_function: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for site in sites.values():
        by_function[(str(site["binary"]), str(site["function"]))].append(site)

    def ordered_before(left: dict[str, object], right: dict[str, object]) -> bool:
        if left["function"] != right["function"] or left["binary"] != right["binary"]:
            return False
        left_address = left["address"]
        right_address = right["address"]
        if not isinstance(left_address, int) or not isinstance(right_address, int):
            return False
        if left["block"] and left["block"] == right["block"]:
            return left_address <= right_address
        return _cfg_reachable(
            cfg_tuple.get((str(left["binary"]), str(left["function"])), {}),
            str(left["block"]) if left["block"] else None,
            str(right["block"]) if right["block"] else None,
        )

    entry_sites: dict[tuple[str, str], list[tuple[str, str, str, str]]] = defaultdict(list)
    for function_key, rows in by_function.items():
        function_row = candidate_functions.get(function_key, {})
        entry = address_value(function_row.get("entry_address", ""))
        entry_block = block_for(function_key[0], function_key[1], entry)
        if entry_block is None and block_starts.get(function_key):
            entry_block = block_starts[function_key][0][1]
        adjacency = cfg_tuple.get(function_key, {})
        for site in rows:
            if site["block"] and _cfg_reachable(adjacency, entry_block, str(site["block"])):
                entry_sites[function_key].append(site["key"])  # type: ignore[arg-type]

    successors: dict[tuple[str, str, str, str], list[tuple[tuple[str, str, str, str], int]]] = defaultdict(list)
    for rows in by_function.values():
        for left in rows:
            for right in rows:
                if left["key"] != right["key"] and ordered_before(left, right):
                    successors[left["key"]].append((right["key"], 0))  # type: ignore[arg-type]
    for site in sites.values():
        if site["kind"] != "call":
            continue
        callee = str(site["callee_id"] or "")
        function_key = (str(site["binary"]), callee)
        if callee in candidate_ids_by_binary.get(str(site["binary"]), set()):
            for target in entry_sites.get(function_key, []):
                if target != site["key"]:
                    successors[site["key"]].append((target, 1))  # type: ignore[arg-type]

    source_sites = [site["key"] for site in sites.values() if site["is_source"]]
    source_site_set = set(source_sites)
    target_sites = {site["key"] for site in sites.values() if site["is_target"]}
    counts: dict[tuple[str, str, str, str], int] = defaultdict(int)
    best: dict[tuple[str, str, str, str], int] = {}
    truncated = False
    states = 0
    stack: list[tuple[tuple[str, str, str, str], int, tuple[tuple[str, str, str, str], ...]]] = [
        (source, 0, (source,)) for source in source_sites
    ]
    while stack:
        node, depth, path = stack.pop()
        states += 1
        if states > state_cap:
            truncated = True
            break
        # A callsite that is both a source and a dangerous API is not a
        # source-to-sink witness by itself; require a distinct later site.
        if node in target_sites and node not in source_site_set:
            if counts[node] < path_cap:
                counts[node] += 1
                best[node] = min(depth, best.get(node, depth))
            else:
                truncated = True
        for nxt, hop in successors.get(node, ()):
            next_depth = depth + hop
            if next_depth > max_depth or nxt in path:
                continue
            stack.append((nxt, next_depth, path + (nxt,)))

    result: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for key in target_sites:
        site = sites[key]
        if counts.get(key, 0):
            status = "witness"
        elif not source_sites:
            status = "no_source_callsite"
        elif not site["block"]:
            status = "unavailable_cfg"
        elif truncated:
            status = "search_truncated"
        else:
            status = "not_reached"
        result[key] = {
            "directional_reach": int(bool(counts.get(key, 0))),
            "directional_path_count": counts.get(key, 0),
            "directional_distance": best.get(key, ""),
            "directional_truncated": int(truncated),
            "directional_status": status,
        }
    return result


def semantic_event_type(mnemonic: str) -> str | None:
    """Recognize architecture-level memory-transfer idioms conservatively.

    The exporter currently emits normalized Ghidra mnemonics without operands.
    These events are therefore evidence of a transfer/set operation, not proof
    of a particular destination, length, or bounds violation.
    """
    raw = (mnemonic or "").upper()
    value = re.sub(r"[^A-Z0-9]", "", raw)
    has_rep = "REP" in raw
    value = value.removeprefix("REP").removesuffix("REP")
    # MOVSD is ambiguous in x86: it can be scalar SSE move or string move.
    # Accept it only when the repeat marker disambiguates the string idiom.
    if value in {"MOVSB", "MOVSW", "MOVSQ", "MOVS"} or (value == "MOVSD" and has_rep):
        return "inline_copy"
    if value in {"STOSB", "STOSW", "STOSD", "STOSQ", "STOS"}:
        return "memory_set"
    return None


def collect_semantic_events(
    instructions: list[dict[str, str]],
    candidate_rows_by_binary: dict[str, dict[str, dict[str, str]]],
    context_window: int = 0,
    context_policy: str = "register_mentions",
    basic_blocks: list[dict[str, str]] | None = None,
) -> list[dict[str, object]]:
    """Collect transfer events and bounded register-setup context.

    The operand field is optional for backward compatibility with v0.4 facts.
    When present, the context is a syntactic window over the same recovered
    function. It is evidence that the compiler prepared implicit string-op
    registers, not a proof of value or memory-object flow.
    """
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in instructions:
        grouped[(row.get("binary", ""), row.get("caller_id", ""))].append(row)

    register_roles = {
        "count": ("RCX", "ECX", "CX", "CL"),
        "source": ("RSI", "ESI", "SI", "SIL"),
        "destination": ("RDI", "EDI", "DI", "DIL"),
    }
    setup_mnemonics = {"MOV", "LEA", "XOR", "SUB", "ADD", "POP", "INC", "DEC"}
    if context_policy not in {"register_mentions", "block_register_writes"}:
        raise ValueError(f"Unknown semantic context policy: {context_policy}")
    block_starts = defaultdict(list)
    if context_policy == "block_register_writes":
        for block in basic_blocks or []:
            block_starts[(block["binary"], block["function_id"])].append(int(block["block_id"].split(":")[-1], 16))
        for starts in block_starts.values():
            starts.sort()

    def has_register(text: str, names: tuple[str, ...]) -> bool:
        upper = text.upper()
        return any(re.search(rf"(?<![A-Z0-9]){name}(?![A-Z0-9])", upper)
                   for name in names)

    def context_for(rows: list[dict[str, str]], index: int, event_type: str) -> tuple[int, float, bool]:
        if not rows or "operand_text" not in rows[index]:
            return 0, 0.0, False
        roles = ("count", "source", "destination") if event_type == "inline_copy" else ("count", "destination")
        observed: set[str] = set()
        start = max(0, index - max(0, context_window))
        event = rows[index]
        strict = context_policy == "block_register_writes"
        starts = block_starts.get((event.get("binary", ""), event.get("caller_id", "")), [])
        if strict and not starts:
            return 0, 0.0, False
        event_address = int(event.get("address", "0").split(":")[-1], 16) if strict else 0
        block_index = bisect_right(starts, event_address) - 1 if strict else -1
        if strict and block_index < 0:
            return 0, 0.0, False
        next_address = event_address
        for prior in reversed(rows[start:index]):
            mnemonic = re.sub(r"[^A-Z0-9]", "", (prior.get("mnemonic", "") or "").upper())
            mnemonic = mnemonic.removeprefix("REP").removesuffix("REP")
            operands = prior.get("operand_text", "") or ""
            if strict:
                address = int(prior.get("address", "0").split(":")[-1], 16)
                if address < starts[block_index] or address + int(prior.get("length", "0")) != next_address:
                    break
                next_address = address
                if mnemonic.startswith(("J", "CALL", "RET", "LOOP")) or semantic_event_type(prior.get("mnemonic", "")):
                    break
                # Ghidra x86 operand order is destination first. Memory stores
                # and reads through a role register are not register writes.
                operands = re.split(r"[;,]", operands)[0].strip().upper()
                if not re.fullmatch(r"[RE](?:CX|SI|DI)", operands):
                    continue
            allowed = setup_mnemonics | {"AND", "OR", "SHL", "SHR", "SAL", "SAR"} if strict else setup_mnemonics
            if mnemonic not in allowed:
                continue
            for role in roles:
                if has_register(operands, register_roles[role]):
                    observed.add(role)
        return len(observed), len(observed) / len(roles), True

    events: list[dict[str, object]] = []
    positions: dict[tuple[str, str], int] = defaultdict(int)
    for row in instructions:
        binary = row.get("binary", "")
        host = row.get("caller_id", "")
        key = (binary, host)
        index = positions[key]
        positions[key] += 1
        if host not in candidate_rows_by_binary.get(binary, {}):
            continue
        event_type = semantic_event_type(row.get("mnemonic", ""))
        if event_type is None:
            continue
        setup_count, setup_score, operand_available = context_for(grouped[key], index, event_type)
        events.append({
            "binary": binary,
            "function_id": host,
            "function_name": row.get("caller_name", ""),
            "instruction": row.get("instruction_id", "") or row.get("address", ""),
            "address": row.get("address", ""),
            "mnemonic": row.get("mnemonic", ""),
            "event_type": event_type,
            "evidence_source": "inferred_instruction",
            "confidence": 0.8,
            "register_setup_count": setup_count,
            "register_context_score": round(setup_score, 6),
            "operand_context_available": int(operand_available),
        })
    return events


def score_features(
    features: Path,
    config: dict[str, object] | None = None,
    dangerous_path: Path | None = None,
    sources_path: Path | None = None,
) -> dict[str, list[dict[str, object]]]:
    config = config or load_config(None)
    functions = read_csv(features / "functions.csv")
    calls = read_csv(features / "calls.csv")
    callsites = read_csv(features / "callsites.csv")
    instructions = read_csv(features / "instructions.csv")
    basic_blocks = read_csv(features / "basic_blocks.csv")
    cfg_edges = read_csv(features / "cfg_edges.csv")
    dangerous = load_dangerous(dangerous_path)
    sources = load_sources(sources_path)
    candidate_rows_by_binary: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in functions:
        identifier = function_id(row)
        if is_candidate(row):
            candidate_rows_by_binary[row.get("binary", "")][identifier] = row
    candidate_ids_by_binary = {
        binary: set(rows) for binary, rows in candidate_rows_by_binary.items()
    }
    graph = build_graph(calls, candidate_ids_by_binary)
    source_by_binary = source_hosts(callsites, sources, candidate_ids_by_binary)
    weights = config["weights"]
    callsite_scores: list[dict[str, object]] = []
    semantic_events = collect_semantic_events(
        instructions,
        candidate_rows_by_binary,
        int(config["semantic_context_window"]),
        str(config.get("semantic_context_policy", "register_mentions")),
        basic_blocks,
    )
    directional_evidence = build_directional_evidence(
        functions,
        callsites,
        basic_blocks,
        cfg_edges,
        semantic_events,
        sources,
        set(dangerous),
        candidate_ids_by_binary,
        int(config.get("directional_max_depth", config["max_depth"])),
        int(config["path_cap"]),
        int(config["search_state_cap"]),
    )
    directional_weight = float(config.get("directional_weight", 0.0))
    directional_replace_reach = bool(config.get("directional_replace_reach", False))
    semantic_scores: list[dict[str, object]] = []
    source_rows: list[dict[str, object]] = []
    diagnostics: list[dict[str, object]] = []

    for row in callsites:
        binary = row.get("binary", "")
        host = row.get("caller_id", "") or row.get("host", "")
        if host not in candidate_ids_by_binary.get(binary, set()):
            continue
        callee = norm_symbol(row.get("callee_name", ""))
        function_row = candidate_rows_by_binary.get(binary, {}).get(host, {})
        if callee in sources:
            source_rows.append({
                "binary": binary, "function_id": host, "function_name": function_name(function_row),
                "source_api": callee,
                "source_host": 1, "path_count": "", "distance": "",
                "path_truncated": 0, "callsite": row.get("address", ""),
            })
        resolution = row.get("resolution_status", "") or "unknown"
        if resolution in {"unresolved", "partially_resolved", "unknown"}:
            diagnostics.append({
                "binary": binary, "kind": "unknown_call", "address": row.get("address", ""),
                "function_id": host, "resolution_status": resolution,
            })
        if callee not in dangerous:
            continue
        category, cwe, base = dangerous[callee]
        path_count, distance, truncated = bounded_paths(
            graph.get(binary, {}), source_by_binary.get(binary, set()), host,
            int(config["max_depth"]), int(config["path_cap"]), int(config["search_state_cap"]),
        )
        reach = 1.0 if path_count else 0.0
        distance_score = 1.0 / (1.0 + distance) if distance is not None else 0.0
        path_score = min(1.0, math.log1p(path_count) / math.log1p(float(config["path_normalizer"])))
        cfg = cfg_complexity(function_row)
        directional = directional_evidence.get(directional_key("call", row), {
            "directional_reach": 0,
            "directional_path_count": 0,
            "directional_distance": "",
            "directional_truncated": 0,
            "directional_status": "unavailable",
        })
        effective_reach = (float(directional["directional_reach"])
                           if directional_replace_reach else reach)
        structural_base = (
            weights["danger"] * base
            + weights["distance"] * distance_score
            + weights["path"] * path_score
            + weights["cfg"] * cfg
        )
        function_reach_risk = structural_base + weights["reach"] * reach
        directional_reach_risk = structural_base + weights["reach"] * float(
            directional["directional_reach"]
        )
        interval_lower = min(function_reach_risk, directional_reach_risk)
        interval_upper = max(function_reach_risk, directional_reach_risk)
        risk = (
            structural_base
            + weights["reach"] * effective_reach
            + directional_weight * float(directional["directional_reach"])
        )
        tier = evidence_tier(True, reach, int(directional["directional_reach"]))
        callsite_scores.append({
            "binary": binary, "function_id": host, "function": host,
            "function_name": function_name(function_row), "callsite": row.get("address", ""),
            "callee": callee, "category": category, "cwe": cwe,
            "risk": round(risk, 6), "risk_lower": round(interval_lower, 6),
            "risk_upper": round(interval_upper, 6),
            "uncertainty_width": round(interval_upper - interval_lower, 6),
            "evidence_tier": tier,
            "uncertainty_status": interval_status(
                interval_lower, interval_upper, str(directional["directional_status"]),
                truncated, bool(directional["directional_truncated"])),
            "base_danger": base, "reach": reach,
            "distance": "" if distance is None else distance, "path_count": path_count,
            "path_truncated": int(truncated), "cfg_score": round(cfg, 6),
            **directional,
            "evidence_source": "explicit_api_call",
        })

    semantic_weight = float(config["semantic_weight"])
    semantic_base = float(config["semantic_base"])
    semantic_context_weight = float(config["semantic_context_weight"])
    for event in semantic_events:
        binary = str(event["binary"])
        host = str(event["function_id"])
        function_row = candidate_rows_by_binary.get(binary, {}).get(host, {})
        path_count, distance, truncated = bounded_paths(
            graph.get(binary, {}), source_by_binary.get(binary, set()), host,
            int(config["max_depth"]), int(config["path_cap"]), int(config["search_state_cap"]),
        )
        reach = 1.0 if path_count else 0.0
        distance_score = 1.0 / (1.0 + distance) if distance is not None else 0.0
        path_score = min(1.0, math.log1p(path_count) / math.log1p(float(config["path_normalizer"])))
        cfg = cfg_complexity(function_row)
        directional = directional_evidence.get(directional_key("event", event), {
            "directional_reach": 0,
            "directional_path_count": 0,
            "directional_distance": "",
            "directional_truncated": 0,
            "directional_status": "unavailable",
        })
        effective_reach = (float(directional["directional_reach"])
                           if directional_replace_reach else reach)
        contextual_base = semantic_base * (
            1.0 + semantic_context_weight * float(event["register_context_score"])
        )
        structural_base = (
            semantic_weight * contextual_base
            + weights["distance"] * distance_score
            + weights["path"] * path_score
            + weights["cfg"] * cfg
        )
        function_reach_risk = structural_base + weights["reach"] * reach
        directional_reach_risk = structural_base + weights["reach"] * float(
            directional["directional_reach"]
        )
        interval_lower = min(function_reach_risk, directional_reach_risk)
        interval_upper = max(function_reach_risk, directional_reach_risk)
        risk = (
            structural_base
            + weights["reach"] * effective_reach
            + directional_weight * float(directional["directional_reach"])
        )
        tier = evidence_tier(True, reach, int(directional["directional_reach"]))
        semantic_scores.append({
            **event,
            "risk": round(risk, 6),
            "risk_lower": round(interval_lower, 6),
            "risk_upper": round(interval_upper, 6),
            "uncertainty_width": round(interval_upper - interval_lower, 6),
            "evidence_tier": tier,
            "uncertainty_status": interval_status(
                interval_lower, interval_upper, str(directional["directional_status"]),
                truncated, bool(directional["directional_truncated"])),
            "semantic_base": round(contextual_base, 6),
            "reach": reach,
            "distance": "" if distance is None else distance,
            "path_count": path_count,
            "path_truncated": int(truncated),
            "cfg_score": round(cfg, 6),
            **directional,
        })

    by_function: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in callsite_scores:
        by_function[(str(row["binary"]), str(row["function_id"]))].append(row)
    function_scores: list[dict[str, object]] = []
    for binary, identifier in sorted(by_function):
        rows = by_function[(binary, identifier)]
        function_row = candidate_rows_by_binary.get(binary, {}).get(identifier, {})
        risks = [float(row["risk"]) for row in rows]
        lower_risks = [float(row["risk_lower"]) for row in rows]
        upper_risks = [float(row["risk_upper"]) for row in rows]
        current = aggregate_risks(risks, float(config["alpha"]), int(config["top_k"]))
        lower = aggregate_risks(lower_risks, float(config["alpha"]), int(config["top_k"]))
        upper = aggregate_risks(upper_risks, float(config["alpha"]), int(config["top_k"]))
        tier = max(int(row["evidence_tier"]) for row in rows)
        function_scores.append({
            "binary": binary, "function_id": identifier, "function": identifier,
            "function_name": function_name(function_row),
            "risk": round(current, 6), "risk_lower": round(lower, 6),
            "risk_upper": round(upper, 6),
            "uncertainty_width": round(upper - lower, 6),
            "evidence_tier": tier,
            **aggregate_interval_provenance(lower, upper, rows),
            "dangerous_call_count": len(rows), "max_callsite_risk": round(max(risks), 6),
        })
    scored_keys = {(str(row["binary"]), str(row["function_id"])) for row in function_scores}
    # Emit zero rows too: model and every internal baseline share this universe.
    binaries = sorted(candidate_rows_by_binary)
    for binary in binaries:
        for identifier, row in sorted(candidate_rows_by_binary.get(binary, {}).items()):
            key = (binary, identifier)
            if key in scored_keys:
                continue
            function_scores.append({
                "binary": binary, "function_id": identifier, "function": identifier,
                "function_name": function_name(row), "risk": 0.0,
                "risk_lower": 0.0, "risk_upper": 0.0, "uncertainty_width": 0.0,
                "evidence_tier": 0, **aggregate_interval_provenance(0.0, 0.0, []),
                "dangerous_call_count": 0, "max_callsite_risk": 0.0,
            })
    function_scores.sort(key=lambda row: (str(row["binary"]), -float(row["risk"]), str(row["function_id"])))

    # The semantic fusion score uses the same max-plus-top-k aggregation as
    # the API score, but over both explicit and inferred evidence sites.
    evidence_by_function: dict[tuple[str, str], list[dict[str, object]]] = defaultdict(list)
    for row in callsite_scores + semantic_scores:
        evidence_by_function[(str(row["binary"]), str(row["function_id"]))].append(row)
    semantic_fusion_scores: list[dict[str, object]] = []
    for binary in binaries:
        for identifier, row in sorted(candidate_rows_by_binary.get(binary, {}).items()):
            evidence = evidence_by_function.get((binary, identifier), [])
            risks = [float(item["risk"]) for item in evidence]
            lower_risks = [float(item["risk_lower"]) for item in evidence]
            upper_risks = [float(item["risk_upper"]) for item in evidence]
            fused = aggregate_risks(risks, float(config["alpha"]), int(config["top_k"]))
            lower = aggregate_risks(lower_risks, float(config["alpha"]), int(config["top_k"]))
            upper = aggregate_risks(upper_risks, float(config["alpha"]), int(config["top_k"]))
            semantic_fusion_scores.append({
                "baseline": "semantic_fusion", "binary": binary,
                "function": identifier, "function_id": identifier,
                "function_name": function_name(row), "risk": round(fused, 6),
                "risk_lower": round(lower, 6), "risk_upper": round(upper, 6),
                "uncertainty_width": round(upper - lower, 6),
                "evidence_tier": max((int(item["evidence_tier"]) for item in evidence), default=0),
                **aggregate_interval_provenance(lower, upper, evidence),
            })

    baseline_rows: list[dict[str, object]] = []
    dangerous_by_function: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in callsites:
        host = row.get("caller_id", "") or row.get("host", "")
        callee = norm_symbol(row.get("callee_name", ""))
        binary = row.get("binary", "")
        if host in candidate_ids_by_binary.get(binary, set()) and callee in dangerous:
            dangerous_by_function[(binary, host)].append(dangerous[callee][2])
    for binary in binaries:
        for identifier, row in sorted(candidate_rows_by_binary.get(binary, {}).items()):
            values = dangerous_by_function.get((binary, identifier), [])
            base_sum = sum(values)
            reachable = 1.0 if values and bounded_paths(
                graph.get(binary, {}), source_by_binary.get(binary, set()), identifier,
                int(config["max_depth"]), int(config["path_cap"]),
                int(config["search_state_cap"]),
            )[0] else 0.0
            baselines = {
                "dangerous_match": 1.0 if values else 0.0,
                "dangerous_count": len(values) + 0.01 * base_sum,
                "callchain_reachability": reachable,
                "cfg_complexity": cfg_complexity(row),
                "dangerous_plus_callchain": base_sum + reachable,
                "directional_callchain_reachability": 1.0 if any(
                    int(item["directional_reach"]) for item in callsite_scores
                    if item["binary"] == binary and item["function_id"] == identifier
                ) else 0.0,
            }
            for baseline, risk in baselines.items():
                baseline_rows.append({
                    "baseline": baseline, "binary": binary, "function_id": identifier,
                    "function": identifier, "function_name": function_name(row),
                    "risk": round(risk, 6),
                })
    semantic_values: dict[tuple[str, str], list[float]] = defaultdict(list)
    fusion_by_function = {
        (str(row["binary"]), str(row["function_id"])): row for row in semantic_fusion_scores
    }
    for row in semantic_scores:
        semantic_values[(str(row["binary"]), str(row["function_id"]))].append(float(row["risk"]))
    for binary in binaries:
        for identifier, row in sorted(candidate_rows_by_binary.get(binary, {}).items()):
            values = semantic_values.get((binary, identifier), [])
            event_base = 1.0 if values else 0.0
            reachable = 1.0 if values and any(float(item["reach"]) > 0 for item in semantic_scores
                                               if item["binary"] == binary and item["function_id"] == identifier) else 0.0
            for baseline, risk in {
                "inline_memory_event": event_base,
                "semantic_event_plus_callchain": event_base + reachable,
                "semantic_fusion": float(fusion_by_function[(binary, identifier)]["risk"]),
            }.items():
                record = {
                    "baseline": baseline, "binary": binary, "function": identifier,
                    "risk": round(risk, 6), "function_id": identifier,
                    "function_name": function_name(row),
                }
                if baseline == "semantic_fusion":
                    record.update(fusion_by_function[(binary, identifier)])
                baseline_rows.append(record)
    quality_diagnostics = []
    for binary in binaries:
        for identifier, row in sorted(candidate_rows_by_binary[binary].items()):
            quality_diagnostics.append({
                "binary": binary,
                "function": identifier,
                "cfg_status": row.get("cfg_status", ""),
                "cfg_error_count": row.get("cfg_error_count", "") or 0,
                "cfg_boundary_blocks": row.get("cfg_boundary_blocks", "") or 0,
                "cfg_unmapped_edges": row.get("cfg_unmapped_edges", "") or 0,
                "cfg_excluded_call_edges": row.get("cfg_excluded_call_edges", "") or 0,
                "cfg_excluded_return_edges": row.get("cfg_excluded_return_edges", "") or 0,
                "cfg_excluded_interprocedural_edges": row.get("cfg_excluded_interprocedural_edges", "") or 0,
                "source_host": int(identifier in source_by_binary.get(binary, set())),
            })
    baseline_rows.sort(key=lambda row: (str(row["baseline"]), str(row["binary"]), -float(row["risk"]), str(row["function_id"])))
    return {
        "callsite_scores": callsite_scores,
        "semantic_events": semantic_events,
        "semantic_scores": semantic_scores,
        "semantic_fusion_scores": semantic_fusion_scores,
        "function_scores": function_scores,
        "baseline_function_scores": baseline_rows,
        "population": [
            {"binary": binary, "function": identifier, "function_name": function_name(row)}
            for binary in sorted(candidate_rows_by_binary)
            for identifier, row in sorted(candidate_rows_by_binary[binary].items())
        ],
        "sink_population": [
            {"binary": binary, "function": identifier, "function_name": function_name(row)}
            for (binary, identifier), values in sorted(dangerous_by_function.items())
            if values
            for row in [candidate_rows_by_binary[binary][identifier]]
        ],
        "quality_diagnostics": quality_diagnostics,
        "source_hosts": source_rows,
        "diagnostics": diagnostics,
    }


def write_outputs(out: Path, results: dict[str, list[dict[str, object]]]) -> None:
    write_csv(out / "callsite_scores.csv", results["callsite_scores"], [
        "binary", "function_id", "function", "function_name", "callsite", "callee",
        "category", "cwe", "risk", "risk_lower", "risk_upper", "uncertainty_width",
        "evidence_tier", "uncertainty_status", "base_danger", "reach", "distance", "path_count",
        "path_truncated", "cfg_score", "evidence_source",
        "directional_reach", "directional_path_count", "directional_distance",
        "directional_truncated", "directional_status",
    ])
    write_csv(out / "semantic_events.csv", results["semantic_events"], [
        "binary", "function_id", "function_name", "instruction", "address",
        "mnemonic", "event_type", "evidence_source", "confidence",
        "register_setup_count", "register_context_score", "operand_context_available",
        "directional_reach", "directional_path_count", "directional_distance",
        "directional_truncated", "directional_status",
    ])
    write_csv(out / "semantic_scores.csv", results["semantic_scores"], [
        "binary", "function_id", "function_name", "instruction", "address",
        "mnemonic", "event_type", "evidence_source", "confidence", "risk",
        "risk_lower", "risk_upper", "uncertainty_width", "evidence_tier", "uncertainty_status",
        "semantic_base", "reach", "distance", "path_count", "path_truncated", "cfg_score",
        "register_setup_count", "register_context_score", "operand_context_available",
        "directional_reach", "directional_path_count", "directional_distance",
        "directional_truncated", "directional_status",
    ])
    write_csv(out / "function_scores.csv", results["function_scores"], [
        "binary", "function", "risk", "function_id", "function_name",
        "risk_lower", "risk_upper", "uncertainty_width", "evidence_tier", "uncertainty_status",
        "dangerous_call_count", "max_callsite_risk", "path_truncated",
        "directional_truncated", "search_truncated", "direction_unverified",
    ])
    write_csv(out / "baseline_function_scores.csv", results["baseline_function_scores"], [
        "baseline", "binary", "function", "risk", "function_id", "function_name",
        "risk_lower", "risk_upper", "uncertainty_width", "evidence_tier", "uncertainty_status",
        "path_truncated", "directional_truncated", "search_truncated", "direction_unverified",
    ])
    write_csv(out / "population.csv", results["population"], ["binary", "function", "function_name"])
    write_csv(out / "sink_population.csv", results["sink_population"], ["binary", "function", "function_name"])
    write_csv(out / "quality_diagnostics.csv", results["quality_diagnostics"], [
        "binary", "function", "cfg_status", "cfg_error_count", "cfg_boundary_blocks",
        "cfg_unmapped_edges", "cfg_excluded_call_edges", "cfg_excluded_return_edges",
        "cfg_excluded_interprocedural_edges", "source_host",
    ])
    write_csv(out / "source_hosts.csv", results["source_hosts"], [
        "binary", "function_id", "function_name", "source_api", "source_host", "path_count",
        "distance", "path_truncated", "callsite",
    ])
    write_csv(out / "diagnostics.csv", results["diagnostics"], [
        "binary", "kind", "address", "function_id", "resolution_status",
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("config.json"))
    parser.add_argument("--dangerous", type=Path)
    parser.add_argument("--sources", type=Path)
    args = parser.parse_args()
    config = load_config(args.config)
    write_outputs(args.out, score_features(args.features, config, args.dangerous, args.sources))
    (args.out / "scoring_protocol.json").write_text(json.dumps({
        "features": str(args.features), "configuration": config,
        "dangerous_file": str(args.dangerous) if args.dangerous else None,
        "sources_file": str(args.sources) if args.sources else None,
        "resolved_dangerous_rules": load_dangerous(args.dangerous),
        "resolved_source_rules": sorted(load_sources(args.sources)),
    }, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
