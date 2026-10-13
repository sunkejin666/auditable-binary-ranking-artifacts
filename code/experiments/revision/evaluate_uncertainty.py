"""Evaluate rank uncertainty from provenance-aware score intervals.

The interval is an audit envelope around the existing v0.5-compatible score:
the lower and upper values are evidence bounds, not calibrated probabilities.
This evaluator reports target retrieval and ranking uncertainty only.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

from evaluate_rankings import target_metrics


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


def number(row: dict[str, str], key: str) -> float:
    value = row.get(key, "")
    if value in (None, ""):
        raise ValueError(f"Missing {key}")
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"Non-finite {key}")
    return parsed


def load_interval_scores(path: Path, method: str) -> dict[str, dict[str, float | int | str]]:
    filename = "function_scores.csv" if method == "full_method" else "baseline_function_scores.csv"
    rows = read_csv(path / filename)
    if method != "full_method":
        rows = [row for row in rows if row.get("baseline") == method]
    output: dict[str, dict[str, float | int | str]] = {}
    for row in rows:
        identifier = row.get("function_id") or row.get("function") or ""
        if not identifier:
            raise ValueError(f"Missing function ID in {path / filename}")
        if identifier in output:
            raise ValueError(f"Duplicate function ID {identifier} in {path / filename}")
        lower = number(row, "risk_lower")
        upper = number(row, "risk_upper")
        if lower > upper + 1e-9:
            raise ValueError(f"Invalid interval for {identifier}: {lower}>{upper}")
        output[identifier] = {
            "risk": number(row, "risk"),
            "risk_lower": lower,
            "risk_upper": upper,
            "uncertainty_width": upper - lower,
            "evidence_tier": int(row.get("evidence_tier") or 0),
            "uncertainty_status": row.get("uncertainty_status", ""),
            # Old CSVs lack independent flags. Their labels are a compatibility
            # fallback only; lost historical provenance requires rescoring.
            "search_truncated": int(row.get("search_truncated") or
                                    (row.get("uncertainty_status") == "search_truncated")),
            "direction_unverified": int(row.get("direction_unverified") or
                                        (row.get("uncertainty_status") == "unverified_direction")),
        }
    return output


def interval_rank_bounds(
    scores: dict[str, dict[str, float | int | str]], target: str
) -> dict[str, object]:
    if target not in scores:
        return {
            "target_interval_status": "target_missing",
            "target_rank_best": "",
            "target_rank_worst": "",
            "target_rank_interval_width": "",
            "target_uncertainty_width": "",
            "target_evidence_tier": "",
        }
    target_row = scores[target]
    target_lower = float(target_row["risk_lower"])
    target_upper = float(target_row["risk_upper"])
    other_rows = [row for identifier, row in scores.items() if identifier != target]
    # Best rank assumes every interval takes the value most favorable to the
    # target; worst rank assumes every overlapping competitor can precede it.
    best = 1 + sum(float(row["risk_lower"]) > target_upper for row in other_rows)
    worst = 1 + sum(float(row["risk_upper"]) >= target_lower for row in other_rows)
    return {
        "target_interval_status": target_row["uncertainty_status"],
        "target_rank_best": best,
        "target_rank_worst": worst,
        "target_rank_interval_width": worst - best,
        "target_uncertainty_width": round(float(target_row["uncertainty_width"]), 6),
        "target_evidence_tier": int(target_row["evidence_tier"]),
    }


def top_k_fields(best: int | str, worst: int | str) -> dict[str, object]:
    fields: dict[str, object] = {}
    for k in (1, 3, 5, 10):
        if best == "" or worst == "":
            # Missing targets and failed analyses are unsuccessful retrievals.
            # Conditional ranks remain missing; hit rates keep every sample.
            fields[f"top{k}_possible"] = 0
            fields[f"top{k}_guaranteed"] = 0
        else:
            fields[f"top{k}_possible"] = int(int(best) <= k)
            fields[f"top{k}_guaranteed"] = int(int(worst) <= k)
    return fields


def failed_row(mapping: dict[str, str], method: str, error: str) -> dict[str, object]:
    row: dict[str, object] = {
        "dataset": mapping.get("dataset", ""),
        "project": mapping.get("project", ""),
        "cve": mapping.get("cve", ""),
        "version": mapping.get("version", ""),
        "label": mapping.get("label", ""),
        "condition": mapping.get("condition", ""),
        "method": method,
        "target_id": mapping.get("target_id", ""),
        "run_status": "failure",
        "error": error,
    }
    row.update({
        "target_retrieved": 0,
        "target_rank_best": "",
        "target_rank_worst": "",
        "target_rank_interval_width": "",
        "target_uncertainty_width": "",
        "target_evidence_tier": "",
    })
    row.update(top_k_fields("", ""))
    return row


def evaluate_case(
    mapping: dict[str, str], scores_path: Path, method: str
) -> dict[str, object]:
    try:
        scores = load_interval_scores(scores_path, method)
        population_rows = read_csv(scores_path / "population.csv")
        population_ids = {row.get("function", "") for row in population_rows}
        population_ids.discard("")
        if set(scores) != population_ids:
            raise ValueError("Score candidate universe mismatch")
        population = len(population_ids)
        declared_population = mapping.get("population", "")
        if declared_population and population != int(declared_population):
            raise ValueError(f"Population mismatch: observed={population}, declared={declared_population}")
        target = mapping.get("target_id", "")
        point = target_metrics(
            {identifier: float(row["risk"]) for identifier, row in scores.items()},
            target,
            population,
        )
        interval = interval_rank_bounds(scores, target)
        row: dict[str, object] = {
            "dataset": mapping.get("dataset", ""),
            "project": mapping.get("project", ""),
            "cve": mapping.get("cve", ""),
            "version": mapping.get("version", ""),
            "label": mapping.get("label", ""),
            "condition": mapping.get("condition", ""),
            "method": method,
            "target_id": target,
            "run_status": "ok",
            "error": "",
            "population": population,
            "target_retrieved": point["retrieved"],
            "point_rank_min": point["rank_min"],
            "point_rank_max": point["rank_max"],
            "target_interval_status": interval["target_interval_status"],
            "target_rank_best": interval["target_rank_best"],
            "target_rank_worst": interval["target_rank_worst"],
            "target_rank_interval_width": interval["target_rank_interval_width"],
            "target_uncertainty_width": interval["target_uncertainty_width"],
            "target_evidence_tier": interval["target_evidence_tier"],
        }
        row.update(top_k_fields(interval["target_rank_best"], interval["target_rank_worst"]))
        widths = [float(item["uncertainty_width"]) for item in scores.values()]
        row.update({
            "interval_exact_fraction": sum(width == 0.0 for width in widths) / len(widths),
            "function_interval_width_max": round(max(widths, default=0.0), 6),
            "function_partial_count": sum(width > 0.0 for width in widths),
            "function_search_truncated_count": sum(int(item["search_truncated"]) for item in scores.values()),
            "function_unverified_direction_count": sum(int(item["direction_unverified"]) for item in scores.values()),
        })
        return row
    except (OSError, ValueError, KeyError) as exc:
        return failed_row(mapping, method, str(exc))


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, str, str], list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        groups[(str(row["project"]), str(row["cve"]), str(row["method"]))].append(row)
    output: list[dict[str, object]] = []
    numeric_fields = (
        "target_retrieved", "top1_possible", "top1_guaranteed",
        "top3_possible", "top3_guaranteed", "top5_possible", "top5_guaranteed",
        "top10_possible", "top10_guaranteed", "interval_exact_fraction",
        "target_rank_best", "target_rank_worst", "target_rank_interval_width",
        "target_uncertainty_width", "function_interval_width_max",
        "function_partial_count", "function_search_truncated_count",
        "function_unverified_direction_count",
    )
    for (project, cve, method), values in sorted(groups.items()):
        record: dict[str, object] = {
            "project": project,
            "cve": cve,
            "method": method,
            "n": len(values),
            "cluster_policy": "version and strip variants are paired observations within one project/CVE cluster",
            "failures": sum(row["run_status"] != "ok" for row in values),
        }
        for field in numeric_fields:
            observed = [float(row[field]) for row in values
                        if row.get(field, "") not in ("", None)]
            # Legacy interval CSVs used blanks for unsuccessful Top-k hits.
            denominator = len(values) if field.startswith("top") or field == "target_retrieved" else len(observed)
            record[field + "_mean"] = sum(observed) / denominator if denominator else ""
            record[field + "_n"] = denominator
        output.append(record)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mapping", type=Path, required=True,
                        help="12-row real-world target mapping")
    parser.add_argument("--scores-root", type=Path, required=True,
                        help="directory containing project_version_condition score directories")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--method", default="full_method")
    args = parser.parse_args()

    mappings = read_csv(args.mapping)
    rows: list[dict[str, object]] = []
    for mapping in mappings:
        directory = args.scores_root / (
            f"{mapping['project']}_{mapping['version']}_{mapping['condition']}"
        )
        rows.append(evaluate_case(mapping, directory, args.method))
    if not rows:
        raise ValueError("No mapping rows")
    args.out.mkdir(parents=True, exist_ok=True)
    write_csv(args.out / "per_condition.csv", rows)
    write_csv(args.out / "summary.csv", summarize(rows))
    (args.out / "protocol.json").write_text(json.dumps({
        "evaluation_type": "provenance_aware_target_rank_interval",
        "method": args.method,
        "interval_interpretation": "lower and upper evidence bounds around the v0.5-compatible risk score; not probabilities or exploitability bounds",
        "best_rank": "1 plus competitors whose lower bound is strictly above the target upper bound",
        "worst_rank": "1 plus competitors whose upper bound is at least the target lower bound",
        "top_k_possible": "best rank <= k",
        "top_k_guaranteed": "worst rank <= k",
        "missing_target_policy": "missing targets and failed analyses contribute zero Top-k hits; ranks remain missing",
        "rate_denominator": "all mapping rows in each group, including failures",
        "cluster_policy": "the project/CVE is the independent cluster; version and strip variants are paired observations",
        "input_sha256": {
            str(args.mapping): hashlib.sha256(args.mapping.read_bytes()).hexdigest(),
            str(Path(__file__)): hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
    }, indent=2), encoding="utf-8")
    print(json.dumps({"mappings": len(mappings), "rows": len(rows),
                      "ok": sum(row["run_status"] == "ok" for row in rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
