"""Evaluate one independently labeled target per binary without name-based tie breaking.

Unretrieved targets remain failures in every denominator. This is target retrieval,
not precision over incompletely labeled functions and not vulnerability detection.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
from collections import defaultdict
from pathlib import Path

import numpy as np


def read_csv(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError(f"No rows for {path}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def target_metrics(scores, target, population):
    """Exact uniform-within-tie expectations; supports a single target only."""
    if population < len(scores) or population < 0:
        raise ValueError("Population must contain every scored function")
    if any(not math.isfinite(float(s)) for s in scores.values()):
        raise ValueError("Non-finite score")
    budgets = {"1": 1, "3": 3, "5": 5, "10": 10}
    budgets.update({f"pct{p}": max(1, math.ceil(population * p / 100)) for p in (1, 5, 10)})
    result = {"retrieved": int(target in scores), "population": population,
              "candidate_count": len(scores), "rank_min": "", "rank_max": "",
              "tie_count": "", "expected_rank_conditional": "", "rr_expected": 0.0,
              "effort_censored": float(population + 1),
              "candidate_fraction": len(scores) / population if population else 0.0}
    for suffix in budgets:
        result.update({f"hit_{suffix}_expected": 0.0, f"hit_{suffix}_worst": 0.0,
                       f"hit_{suffix}_best": 0.0})
    if target not in scores:
        return result
    value = scores[target]
    rank_min = 1 + sum(score > value for score in scores.values())
    count = sum(score == value for score in scores.values())
    rank_max = rank_min + count - 1
    expected_rank = (rank_min + rank_max) / 2
    result.update(rank_min=rank_min, rank_max=rank_max, tie_count=count,
                  expected_rank_conditional=expected_rank,
                  rr_expected=sum(1.0 / r for r in range(rank_min, rank_max + 1)) / count,
                  effort_censored=expected_rank)
    for suffix, k in budgets.items():
        result[f"hit_{suffix}_expected"] = min(count, max(0, k - rank_min + 1)) / count
        result[f"hit_{suffix}_worst"] = float(rank_max <= k)
        result[f"hit_{suffix}_best"] = float(rank_min <= k)
    return result


def summarize(rows):
    keys = ["retrieved", "population", "candidate_count", "rr_expected", "effort_censored",
            "candidate_fraction"] + [k for k in rows[0] if k.startswith("hit_")]
    groups = defaultdict(list)
    for row in rows:
        for cwe in ("ALL", row["cwe"]):
            groups[(row["dataset"], row["scope"], row["method"], cwe)].append(row)
    summaries = []
    for (dataset, scope, method, cwe), values in sorted(groups.items()):
        record = {"dataset": dataset, "scope": scope, "method": method, "cwe": cwe,
                  "n": len(values), "target_misses": sum(not v["retrieved"] for v in values)}
        record.update({key: float(np.mean([v[key] for v in values])) for key in keys})
        ranks = [float(v["rank_max"]) for v in values if v["rank_max"] != ""]
        record["rank_max_conditional_mean"] = float(np.mean(ranks)) if ranks else ""
        summaries.append(record)
    return summaries


def clustered_differences(rows, out, reference="full_method", iterations=10000,
                          scope="shared_sink"):
    """Family-resampled paired CIs, preserving all variants in a template family."""
    shared = [r for r in rows if r["scope"] == scope]
    by_method = defaultdict(dict)
    for row in shared:
        by_method[row["method"]][row["binary"]] = row
    if reference not in by_method:
        return
    result = []
    ref = by_method[reference]
    for method, others in sorted(by_method.items()):
        if method == reference:
            continue
        if set(ref) != set(others):
            raise ValueError("Cannot pair different sample sets")
        for metric in ("hit_1_expected", "hit_3_expected", "hit_5_expected", "rr_expected"):
            families = defaultdict(list)
            for binary, record in ref.items():
                families[record["family"]].append(record[metric] - others[binary][metric])
            values = list(families.values())
            sums = np.array([sum(x) for x in values])
            sizes = np.array([len(x) for x in values])
            rng = np.random.default_rng(20261006)
            index = rng.integers(0, len(values), size=(iterations, len(values)))
            boot = sums[index].sum(axis=1) / sizes[index].sum(axis=1)
            lo, hi = np.quantile(boot, [0.025, 0.975])
            result.append({"scope": scope, "reference": reference, "baseline": method, "metric": metric,
                           "delta": sums.sum()/sizes.sum(), "ci_low": lo, "ci_high": hi,
                           "n_binary": len(ref), "n_family": len(values),
                           "iterations": iterations, "seed": 20261006})
    if result:
        write_csv(out / "paired_family_bootstrap.csv", result)


def evaluate_archive(legacy, out):
    features = legacy / "features" / "batch200"
    functions = read_csv(features / "functions.csv")
    labels = read_csv(features / "labels.csv")
    manifest = {r["binary"]: r for r in read_csv(legacy / "manifests" / "batch200_manifest.csv")}
    if len({r["binary"] for r in labels}) != len(labels):
        raise ValueError("This protocol requires one target per binary; use a multi-target evaluator otherwise")
    population = defaultdict(set)
    for row in functions:
        population[row["binary"]].add(row["function"])
    all_scores = defaultdict(lambda: defaultdict(dict))
    scores = legacy / "scores" / "batch200"
    for row in read_csv(scores / "function_scores.csv"):
        all_scores["full_method"][row["binary"]][row["function"]] = float(row["risk"])
    for row in read_csv(scores / "baseline_function_scores.csv"):
        all_scores[row["baseline"]][row["binary"]][row["function"]] = float(row["risk"])
    records = []
    for label in labels:
        binary = label["binary"]
        family = re.sub(r"_\d+$", "", Path(manifest[binary]["source_path"]).stem)
        # The fair all-functions universe is the complete recovered/legacy
        # function population.  The shared-sink universe is the subset that
        # has at least one dangerous-call host in the full-method output.
        all_functions = set(population[binary])
        shared_sink = set(all_scores["full_method"][binary])
        for scope in ("all_functions", "shared_sink"):
            for method, binaries in sorted(all_scores.items()):
                pred = binaries.get(binary, {})
                if scope == "shared_sink":
                    pred = {k: pred.get(k, 0.0) for k in shared_sink}
                else:
                    pred = {k: pred.get(k, 0.0) for k in all_functions}
                record = {"dataset": "archived_juliet200", "scope": scope, "method": method,
                          "binary": binary, "cwe": label["vulnerable_cwe"], "family": family}
                record.update(target_metrics(pred, label["vulnerable_function"], len(population[binary])))
                records.append(record)
    write_csv(out / "per_binary_metrics.csv", records)
    write_csv(out / "summary.csv", summarize(records))
    clustered_differences(records, out)
    payload = {
        "evaluation_type": "dataset_target_retrieval",
        "not_detection_precision": True, "n_binary": len(labels),
        "n_source_template_family": len({r["family"] for r in records}),
        "function_identity": "legacy name-keyed; known thunk/external collisions, not corrected extraction",
        "candidate_policy": "all recovered legacy universes for diagnosis; shared dangerous-call hosts for fair ranking comparisons",
        "missing_targets": "hit=0, reciprocal rank=0, no conditional rank; censored effort=population+1",
        "tie_policy": "uniform random permutation inside each exactly equal stored-score group; analytic expectation",
        "effort_warning": "function count proxy, not measured analyst time; failure penalty explicitly censored",
        "labels_warning": "one designated Juliet bad function per ELF, not exhaustive vulnerability labels",
        "input_hashes": {str(p.resolve()): hashlib.sha256(p.read_bytes()).hexdigest()
                         for p in [features / "functions.csv", features / "labels.csv",
                                   scores / "function_scores.csv", scores / "baseline_function_scores.csv"]},
    }
    (out / "protocol.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", type=Path, default=Path(__file__).resolve().parent.parent / "legacy")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "results" / "archive_reanalysis")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    records = evaluate_archive(args.legacy, args.out)
    for row in summarize(records):
        if row["cwe"] == "ALL" and row["scope"] == "shared_sink":
            print(row["method"], "n=", row["n"], "miss=", row["target_misses"],
                  "EHit1=", round(row["hit_1_expected"], 4), "EMRR=", round(row["rr_expected"], 4))


if __name__ == "__main__":
    main()
