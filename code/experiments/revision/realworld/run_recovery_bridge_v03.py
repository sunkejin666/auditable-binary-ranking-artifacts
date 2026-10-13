"""Run failure-preserving interval recovery actions serially on frozen facts.

This runner is a protocol hardening exercise.  Increasing the bounded-search
cap is still only a structural recovery action and does not confirm a defect.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REVISION = HERE.parent
sys.path.insert(0, str(REVISION))
sys.path.insert(0, str(REVISION / "address_model"))

from address_model import score  # noqa: E402
from recovery_bridge_v03 import AppendOnlyEventLog, UNKNOWN, make_event  # noqa: E402
from sound_interval_score import score_features  # noqa: E402


CLUSTERS = {
    "libpng": "libpng/CVE-2015-8126",
    "zlib": "zlib/CVE-2018-25032",
    "openssl": "openssl/CVE-2022-0778",
    "expat": "expat/CVE-2022-23852",
    "libarchive": "libarchive/CVE-2016-1541",
    "libjpeg-turbo": "libjpeg-turbo/CVE-2018-14498",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def read_metadata(facts: Path) -> dict[str, str]:
    with (facts / "metadata.csv").open(encoding="utf-8-sig", newline="") as handle:
        return next(csv.DictReader(handle))


def function_map(result: dict[str, list[dict[str, object]]]) -> dict[str, dict[str, object]]:
    return {str(row["function_id"]): row for row in result["function_scores"]}


def project_name(run_name: str) -> str:
    return next((name for name in sorted(CLUSTERS, key=len, reverse=True)
                 if run_name.startswith(name + "_")), run_name.split("_", 1)[0])


def run_one(facts: Path, config_path: Path, caps: list[int], out: Path) -> dict[str, object]:
    name = facts.parent.name
    project = project_name(name)
    variant = "stripped" if name.endswith("_stripped") else "unstripped"
    metadata = read_metadata(facts)
    binary_hash = metadata.get("executable_sha256", "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", binary_hash):
        raise ValueError(f"missing or invalid executable SHA-256 for {name}")

    source_hashes = {
        "scorer": sha(HERE / "sound_interval_score.py"),
        "runner": sha(Path(__file__)),
        "event_logger": sha(HERE / "recovery_bridge_v03.py"),
        "legacy_helpers": sha(REVISION / "address_model" / "score.py"),
    }
    tool_hash = canonical_sha(source_hashes)
    protocol = {
        "bridge": "sound-structural-search-cap-recovery-v0.3",
        "facts": str(facts),
        "caps": caps,
        "component": "declared_structural_score_interval",
        "failure_policy": "timeout, exception, invalid value, or non-nested proposal preserves the prior interval",
        "pool_policy": "emit candidate events only when adjacent successful caps have identical candidate pools",
        "cost_policy": "wall time is shared by all candidate events with the same shared_cost_group and is counted once",
    }
    protocol_hash = canonical_sha(protocol)
    base_config = score.load_config(config_path)
    run_root = out / name
    run_root.mkdir(parents=True, exist_ok=False)
    event_log = AppendOnlyEventLog(run_root / "recovery_events.jsonl")

    cap_maps: dict[int, dict[str, dict[str, object]]] = {}
    cap_meta: list[dict[str, object]] = []
    for cap in caps:
        cfg = dict(base_config)
        cfg["search_state_cap"] = cap
        start = time.perf_counter()
        try:
            result = score_features(facts, cfg)
            mapping = function_map(result)
            status, error = "ok", ""
        except Exception as exc:
            mapping = {}
            status, error = "error", repr(exc)
        elapsed = time.perf_counter() - start
        pool = sorted(mapping)
        cap_maps[cap] = mapping
        cap_meta.append({
            "cap": cap,
            "status": status,
            "seconds": elapsed,
            "error": error,
            "candidate_count": len(pool),
            "candidate_pool_sha256": canonical_sha(pool),
        })

    by_cap_meta = {int(row["cap"]): row for row in cap_meta}
    transitions = []
    event_count = contraction_count = invalid_contract_count = 0
    for before_cap, after_cap in zip(caps, caps[1:]):
        before_meta, after_meta = by_cap_meta[before_cap], by_cap_meta[after_cap]
        same_pool = (
            before_meta["candidate_pool_sha256"] == after_meta["candidate_pool_sha256"]
            and before_meta["candidate_count"] == after_meta["candidate_count"]
        )
        eligible = before_meta["status"] == after_meta["status"] == "ok" and same_pool
        transition = {
            "before_cap": before_cap,
            "after_cap": after_cap,
            "eligible": eligible,
            "same_candidate_pool": same_pool,
            "status": "ok" if eligible else "not_comparable",
            "event_count": 0,
        }
        if not eligible:
            transitions.append(transition)
            continue

        candidate_pool = sorted(cap_maps[before_cap])
        pool_hash = str(before_meta["candidate_pool_sha256"])
        action_id = f"{name}:search_state_cap:{before_cap}->{after_cap}"
        for candidate_id in candidate_pool:
            before = cap_maps[before_cap][candidate_id]
            after = cap_maps[after_cap][candidate_id]
            before_interval = (before["risk_lower"], before["risk_upper"])
            after_interval = (after["risk_lower"], after["risk_upper"])
            after_width = float(after_interval[1]) - float(after_interval[0])
            recovered = UNKNOWN
            after_status = str(after.get("uncertainty_status", "unknown"))
            if after_status == "bounded" and abs(after_width) < 1e-12:
                recovered = after.get("risk", UNKNOWN)
            event = make_event(
                binary_sha256=binary_hash,
                project_cve_cluster=CLUSTERS.get(project, project),
                variant=variant,
                candidate_id=candidate_id,
                component="declared_structural_score_interval",
                interval_before=before_interval,
                recovered_value=recovered,
                interval_after=after_interval,
                action_id=action_id,
                declared_cost=1,
                measured_wall_seconds=float(after_meta["seconds"]),
                tool_hash=tool_hash,
                container_hash="",
                timeout=False,
                exception="",
                extraction_status=after_status,
                candidate_pool_sha256=pool_hash,
                protocol_sha256=protocol_hash,
                shared_cost_group=action_id,
            )
            payload = event_log.append(event)
            event_count += 1
            transition["event_count"] += 1
            if not payload["contract_valid"]:
                invalid_contract_count += 1
            if payload["contract_valid"] and payload["interval_before"] != payload["interval_after"]:
                contraction_count += 1
        transitions.append(transition)

    summary = {
        "binary": name,
        "project_cve_cluster": CLUSTERS.get(project, project),
        "variant": variant,
        "binary_sha256": binary_hash,
        "event_count": event_count,
        "contraction_events": contraction_count,
        "invalid_contract_events": invalid_contract_count,
        "unique_action_groups": sum(int(row["eligible"]) for row in transitions),
        "caps": caps,
        "cap_runs": cap_meta,
        "transitions": transitions,
        "status": "ok" if all(row["eligible"] for row in transitions) else "partial_failure",
    }
    (run_root / "protocol.json").write_text(json.dumps({
        **protocol,
        "binary_sha256": binary_hash,
        "source_hashes": source_hashes,
        "combined_tool_sha256": tool_hash,
        "protocol_sha256": protocol_hash,
        "interpretation": "protocol hardening for a declared structural score; not vulnerability evidence",
    }, indent=2), encoding="utf-8")
    (run_root / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--facts-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--caps", type=int, nargs="+", default=[1000, 10000, 100000])
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    if args.caps != sorted(set(args.caps)) or len(args.caps) < 2:
        raise SystemExit("--caps must contain at least two strictly increasing values")
    args.out.mkdir(parents=True, exist_ok=False)
    directories = sorted(
        path for path in args.facts_root.iterdir()
        if path.is_dir() and (path / "facts").is_dir()
    )
    if args.limit is not None:
        directories = directories[:args.limit]
    summaries = []
    for directory in directories:
        print(f"BRIDGE_V03 {directory.name}", flush=True)
        summaries.append(run_one(directory / "facts", args.config, args.caps, args.out))
    aggregate = {
        "protocol": "sound-structural-search-cap-recovery-v0.3",
        "runs": summaries,
        "external_requests": 0,
        "scope": "existing real ELF facts; protocol smoke/development only",
    }
    (args.out / "summary.json").write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    print(json.dumps({
        "runs": len(summaries),
        "events": sum(int(row["event_count"]) for row in summaries),
        "contractions": sum(int(row["contraction_events"]) for row in summaries),
    }, indent=2))
    return 0 if all(row["status"] == "ok" for row in summaries) else 1


if __name__ == "__main__":
    raise SystemExit(main())
