#!/usr/bin/env python3
"""Select a small Juliet pilot source subset with traceable labels.

This script copies a conservative subset of Juliet C single-file test cases
from a verified local extraction into the project directory. It does not
compile samples or produce experiment results.
"""

from __future__ import annotations

import argparse
import csv
import re
import shutil
from pathlib import Path


TARGETS = {
    "CWE-121": "CWE121_Stack_Based_Buffer_Overflow",
    "CWE-122": "CWE122_Heap_Based_Buffer_Overflow",
    "CWE-134": "CWE134_Uncontrolled_Format_String",
    "CWE-190": "CWE190_Integer_Overflow",
    "CWE-78": "CWE78_OS_Command_Injection",
}

DANGEROUS_SYMBOLS = [
    "gets",
    "strcpy",
    "strcat",
    "sprintf",
    "vsprintf",
    "printf",
    "fprintf",
    "scanf",
    "__isoc99_scanf",
    "memcpy",
    "memmove",
    "system",
    "popen",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execvp",
    "malloc",
]

INPUT_SOURCES = [
    "recv",
    "recvfrom",
    "read",
    "fgets",
    "fscanf",
    "scanf",
    "getenv",
    "connect_socket",
    "listen_socket",
    "argv",
]

PREFERRED_NAME_TOKENS = {
    "CWE-121": ["strcpy", "memcpy", "sprintf", "char"],
    "CWE-122": ["strcpy", "memcpy", "sprintf", "char"],
    "CWE-134": ["printf"],
    "CWE-190": ["malloc", "new"],
    "CWE-78": ["system", "popen", "execl", "exec"],
}

FIELDS = [
    "pilot_id",
    "cwe",
    "source_dataset",
    "source_path",
    "copied_source_path",
    "bad_function",
    "good_function",
    "dangerous_symbols",
    "input_sources",
    "label_source",
    "notes",
]


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def find_symbols(text: str, symbols: list[str]) -> list[str]:
    found: list[str] = []
    for sym in symbols:
        if re.search(rf"\b{re.escape(sym)}\s*\(", text):
            found.append(sym)
    return found


def extract_function(text: str, suffix: str) -> str:
    match = re.search(rf"\bvoid\s+([A-Za-z0-9_]+_{suffix})\s*\(", text)
    return match.group(1) if match else ""


def score_candidate(path: Path, text: str, cwe: str) -> tuple[int, str]:
    name = path.name
    score = 0
    reason: list[str] = []
    if re.search(r"_0[1-3]\.c$", name):
        score += 20
        reason.append("simple_flow")
    if re.search(r"_[0-9]+[a-z]\.c$", name):
        score -= 20
        reason.append("multi_file_variant")
    for token in PREFERRED_NAME_TOKENS.get(cwe, []):
        if token in name:
            score += 8
            reason.append(f"name:{token}")
    dangerous = find_symbols(text, DANGEROUS_SYMBOLS)
    sources = find_symbols(text, INPUT_SOURCES)
    score += 3 * len(dangerous)
    score += 2 * len(sources)
    if extract_function(text, "bad"):
        score += 10
        reason.append("bad_label")
    if extract_function(text, "good"):
        score += 5
        reason.append("good_label")
    return score, ";".join(reason)


def choose_sources(local_root: Path, per_cwe: int) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    testcases = local_root / "C" / "testcases"
    for cwe, dirname in TARGETS.items():
        root = testcases / dirname
        candidates: list[tuple[int, str, Path, str]] = []
        for path in sorted(root.rglob("*.c")) if root.exists() else []:
            if re.search(r"_[0-9]+[a-z]\.c$", path.name):
                continue
            text = read_text(path)
            bad_function = extract_function(text, "bad")
            if not bad_function:
                continue
            dangerous = find_symbols(text, DANGEROUS_SYMBOLS)
            if not dangerous:
                continue
            score, reason = score_candidate(path, text, cwe)
            candidates.append((score, reason, path, text))
        candidates.sort(key=lambda item: (-item[0], str(item[2])))
        for idx, (score, reason, path, text) in enumerate(candidates[:per_cwe], start=1):
            dangerous = find_symbols(text, DANGEROUS_SYMBOLS)
            sources = find_symbols(text, INPUT_SOURCES)
            rows.append(
                {
                    "pilot_id": f"{cwe.replace('-', '')}_{idx:02d}",
                    "cwe": cwe,
                    "source_dataset": "NIST SARD Juliet C/C++ v1.3",
                    "source_path": path.as_posix(),
                    "copied_source_path": "",
                    "bad_function": extract_function(text, "bad"),
                    "good_function": extract_function(text, "good"),
                    "dangerous_symbols": ";".join(dangerous),
                    "input_sources": ";".join(sources),
                    "label_source": "Juliet generated function naming: *_bad is treated as vulnerable target for pilot ranking.",
                    "notes": f"selection_score={score};{reason}",
                }
            )
    return rows


def copy_subset(project: Path, rows: list[dict[str, str]], local_root: Path) -> list[dict[str, str]]:
    out_root = project / "datasets" / "juliet_src" / "pilot_subset"
    support_src = local_root / "C" / "testcasesupport"
    support_dst = out_root / "testcasesupport"
    support_dst.mkdir(parents=True, exist_ok=True)
    for name in ["io.c", "std_thread.c", "std_testcase.h", "std_testcase_io.h", "std_thread.h"]:
        shutil.copyfile(support_src / name, support_dst / name)

    for row in rows:
        src = Path(row["source_path"])
        rel = src.relative_to(local_root / "C" / "testcases")
        dst = out_root / "testcases" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        row["copied_source_path"] = dst.relative_to(project).as_posix()
    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--local-root", type=Path, default=Path("/home/voidex/elf-risk-data/juliet"))
    parser.add_argument("--per-cwe", type=int, default=1)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    project = args.project.resolve()
    rows = choose_sources(args.local_root, args.per_cwe)
    rows = copy_subset(project, rows, args.local_root)
    out = args.out or project / "manifests" / "pilot_sources.csv"
    write_csv(out, rows)
    print(f"wrote {out} with {len(rows)} pilot source rows")
    for row in rows:
        print(f"{row['pilot_id']},{row['cwe']},{Path(row['source_path']).name},{row['dangerous_symbols']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
