"""Evaluate provenance-aware rank intervals on the address-keyed Juliet set."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "address_model"))

from address_model import score  # noqa: E402
from evaluate_rankings import target_metrics  # noqa: E402
from evaluate_uncertainty import interval_rank_bounds, top_k_fields  # noqa: E402


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"No rows for {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def latest_facts(root: Path, sample_id: str, condition: str) -> Path | None:
    run_root = root / "address_runs" / sample_id / condition
    ledger = run_root / "result.json"
    if not ledger.exists():
        return None
    run = json.loads(ledger.read_text(encoding="utf-8"))
    if run.get("status") != "ok":
        return None
    facts = root / run["attempt_dir"] / "facts"
    required = ("functions.csv", "calls.csv", "callsites.csv", "metadata.csv")
    return facts if all((facts / name).is_file() for name in required) else None


def family_name(manifest: dict[str, dict[str, str]], binary: str) -> str:
    source = Path(manifest[binary]["source_path"]).stem
    return source.rsplit("_", 1)[0] if "_" in source else source


def score_rows(results: dict[str, list[dict[str, object]]], scope: str) -> dict[str, dict[str, object]]:
    rows = results["function_scores"]
    if scope == "shared_sink":
        sink = {str(row["function"]) for row in results["sink_population"]}
        rows = [row for row in rows if str(row["function_id"]) in sink]
    output: dict[str, dict[str, object]] = {}
    for row in rows:
        identifier = str(row["function_id"] or row["function"])
        output[identifier] = row
    return output


def evaluate_one(
    mapping: dict[str, str],
    facts: Path,
    results: dict[str, list[dict[str, object]]],
    scope: str,
) -> dict[str, object]:
    rows = score_rows(results, scope)
    target = mapping.get(f"{mapping['condition']}_function_id", "")
    population = len(results["population"])
    point = target_metrics(
        {key: float(row["risk"]) for key, row in rows.items()}, target, population
    )
    interval = interval_rank_bounds(rows, target)
    record: dict[str, object] = {
        "dataset": "juliet200_address",
        "sample_id": mapping["sample_id"],
        "binary": mapping["binary"],
        "condition": mapping["condition"],
        "scope": scope,
        "cwe": mapping["vulnerable_cwe"],
        "family": mapping.get("family", ""),
        "target": target,
        "run_status": "ok",
        "population": population,
        "candidate_count": len(rows),
        "target_retrieved": point["retrieved"],
        "point_rank_min": point["rank_min"],
        "point_rank_max": point["rank_max"],
        **interval,
    }
    record.update(top_k_fields(interval["target_rank_best"], interval["target_rank_worst"]))
    return record


def failed_record(mapping: dict[str, str], condition: str, scope: str, error: str) -> dict[str, object]:
    target = mapping.get(f"{condition}_function_id", "")
    record: dict[str, object] = {
        "dataset": "juliet200_address",
        "sample_id": mapping.get("sample_id", ""),
        "binary": mapping.get("binary", ""),
        "condition": condition,
        "scope": scope,
        "cwe": mapping.get("vulnerable_cwe", ""),
        "family": mapping.get("family", ""),
        "target": target,
        "run_status": "failure",
        "error": error,
        "target_retrieved": 0,
        "point_rank_min": "",
        "point_rank_max": "",
        "target_rank_best": "",
        "target_rank_worst": "",
        "target_rank_interval_width": "",
        "target_uncertainty_width": "",
        "target_evidence_tier": "",
    }
    record.update(top_k_fields("", ""))
    return record


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        groups[(str(row["condition"]), str(row["scope"]), str(row["cwe"]))].append(row)
    fields = (
        "target_retrieved", "top1_possible", "top1_guaranteed",
        "top5_possible", "top5_guaranteed", "target_rank_best",
        "target_rank_worst", "target_rank_interval_width", "target_uncertainty_width",
    )
    output: list[dict[str, object]] = []
    for (condition, scope, cwe), values in sorted(groups.items()):
        record: dict[str, object] = {
            "dataset": "juliet200_address",
            "condition": condition,
            "scope": scope,
            "cwe": cwe,
            "n": len(values),
            "cluster_policy": "original and stripped observations are paired within each sample_id",
            "failures": sum(row["run_status"] != "ok" for row in values),
        }
        for field in fields:
            observed = [float(row[field]) for row in values
                        if row.get(field, "") not in ("", None)]
            denominator = len(values) if field.startswith("top") or field == "target_retrieved" else len(observed)
            record[field + "_mean"] = sum(observed) / denominator if denominator else ""
            record[field + "_n"] = denominator
        output.append(record)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mapping", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--dangerous", type=Path)
    parser.add_argument("--sources", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    mappings = read_csv(args.mapping)
    manifests = {row["binary"]: row for row in read_csv(args.manifest)}
    rows: list[dict[str, object]] = []
    for mapping in mappings:
        mapping = dict(mapping)
        mapping["family"] = family_name(manifests, mapping["binary"])
        for condition in ("original", "stripped"):
            mapping["condition"] = condition
            facts = latest_facts(args.root, mapping["sample_id"], condition)
            for scope in ("all_functions", "shared_sink"):
                if facts is None:
                    rows.append(failed_record(mapping, condition, scope, "missing_facts"))
                    continue
            if facts is not None:
                try:
                    results = score.score_features(
                        facts, score.load_config(args.config), args.dangerous, args.sources
                    )
                    for scope in ("all_functions", "shared_sink"):
                        rows.append(evaluate_one(mapping, facts, results, scope))
                except (OSError, ValueError, KeyError) as exc:
                    for scope in ("all_functions", "shared_sink"):
                        rows.append(failed_record(mapping, condition, scope, str(exc)))
    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(args.out / "per_binary.csv", rows)
    write_csv(args.out / "summary.csv", summarize(rows))
    (args.out / "protocol.json").write_text(json.dumps({
        "evaluation_type": "address_keyed_provenance_aware_target_rank_interval",
        "candidate_views": {
            "all_functions": "full recovered internal executable bodies",
            "shared_sink": "intersection by normalized dangerous-call host",
        },
        "cluster_policy": "original and stripped observations are paired within sample_id; source-template family is used for grouping only",
        "interval_interpretation": "lower and upper evidence bounds around the v0.5-compatible risk score; not probabilities or exploitability bounds",
        "missing_target_policy": "missing targets and failed analyses contribute zero Top-k hits; ranks remain missing",
        "rate_denominator": "all mapping rows in each group, including failures",
        "input_sha256": {
            str(args.mapping): hashlib.sha256(args.mapping.read_bytes()).hexdigest(),
            str(args.manifest): hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
            str(args.config): hashlib.sha256(args.config.read_bytes()).hexdigest(),
            str(Path(__file__)): hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
    }, indent=2), encoding="utf-8")
    print(json.dumps({"mappings": len(mappings), "rows": len(rows),
                      "ok": sum(row["run_status"] == "ok" for row in rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
