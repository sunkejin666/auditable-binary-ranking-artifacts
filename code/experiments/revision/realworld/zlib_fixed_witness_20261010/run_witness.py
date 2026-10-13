from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[4]
REALWORLD = ROOT / "experiments" / "revision" / "realworld"
SRC_ROOT = REALWORLD / "projects_v0_4" / "source_trees"
OUT = pathlib.Path(__file__).resolve().parent
HARNESS = OUT / "zlib_fixed_witness.c"
RUNS = OUT / "runs"


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def wsl(path: pathlib.Path) -> str:
    # All project files are on the C: drive. Avoid invoking `wslpath` here:
    # this Windows installation emits a non-UTF-8 localhost banner on stderr.
    raw = str(path)
    if len(raw) < 3 or raw[1:3] != ":\\":
        raise ValueError(f"expected an absolute C: path, got {raw}")
    return "/mnt/c/" + raw[3:].replace("\\", "/")


def build(version: str) -> pathlib.Path:
    src = SRC_ROOT / f"zlib-{version}"
    build_dir = OUT / "build" / version
    build_dir.mkdir(parents=True, exist_ok=True)
    exe = build_dir / "witness"
    cmd = ["gcc", "-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined",
           "-fno-sanitize-recover=all", "-I", wsl(src), "-o", wsl(exe), wsl(HARNESS)]
    cmd += [wsl(src / name) for name in
            ["adler32.c", "compress.c", "crc32.c", "deflate.c", "gzclose.c", "gzlib.c",
             "gzread.c", "gzwrite.c", "infback.c", "inffast.c", "inflate.c", "inftrees.c",
             "trees.c", "uncompr.c", "zutil.c"]]
    subprocess.run(["wsl", "-d", "Ubuntu-24.04", "--"] + cmd, check=True)
    return exe


def cases():
    for n in (65536, 131072, 262144, 524288, 1048576):
        for mode in range(6):
            for seed in (1, 7, 101):
                for level in (1, 6, 9):
                    for mem in (1, 8, 9):
                        for chunk in (257, 4096, 16384, 65535):
                            yield (n, mode, seed, level, mem, 15, chunk, 0)
                            if mode in (3, 5):
                                yield (n, mode, seed, level, mem, 15, chunk, 1)


def main() -> int:
    RUNS.mkdir(exist_ok=True)
    manifest = {
        "protocol": "public-api-z_fixed-asan-v1",
        "source_root_sha256": {},
        "harness_sha256": sha256(HARNESS),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "results": [],
    }
    limit_text = os.environ.get("ZLIB_WITNESS_LIMIT", "")
    limit = int(limit_text) if limit_text else None
    for version in ("1.2.11", "1.2.12"):
        src = SRC_ROOT / f"zlib-{version}"
        manifest["source_root_sha256"][version] = {
            name: sha256(src / name) for name in
            ["ChangeLog", "deflate.c", "deflate.h", "trees.c", "zlib.h"]
        }
        exe = build(version)
        for idx, args in enumerate(cases()):
            if limit is not None and idx >= limit:
                break
            cmd = ["wsl", "-d", "Ubuntu-24.04", "--", wsl(exe)] + [str(x) for x in args]
            started = time.time()
            proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=20)
            row = {"version": version, "case_index": idx, "args": args,
                   "returncode": proc.returncode, "elapsed_seconds": time.time() - started,
                   "stdout": (proc.stdout or "")[-1000:], "stderr": (proc.stderr or "")[-4000:]}
            manifest["results"].append(row)
            if proc.returncode != 0:
                print(json.dumps(row, sort_keys=True), flush=True)
    manifest["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["case_limit_per_version"] = limit
    manifest_path = RUNS / (f"manifest_limit{limit}.json" if limit is not None else "manifest_full.json")
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    failures = [r for r in manifest["results"] if r["returncode"] != 0]
    print(json.dumps({"total": len(manifest["results"]), "failures": len(failures),
                      "manifest": str(manifest_path)}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
