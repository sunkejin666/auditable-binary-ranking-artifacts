"""Run one original ELF through Ghidra 12.1.2 using Windows Python and WSL."""

from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def wsl_path(path: Path, distro: str) -> str:
    return subprocess.check_output(
        ["wsl", "-d", distro, "--exec", "wslpath", "-a", "-u", path.resolve().as_posix()],
        encoding="utf-8",
    ).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="/home/voidex/pwn1/fds")
    parser.add_argument("--binary-id", default="original-local-fds")
    parser.add_argument("--out", type=Path, default=ROOT / "pilot")
    parser.add_argument("--distro", default="Ubuntu-24.04")
    parser.add_argument("--ghidra", default="/home/voidex/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless")
    parser.add_argument("--analysis-timeout", type=int, default=120)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    project = args.out / "projects"
    project.mkdir(exist_ok=True)
    prefix = ["wsl", "-d", args.distro, "--exec"]
    digest = subprocess.check_output(prefix + ["sha256sum", args.binary], encoding="utf-8").split()[0]
    command = prefix + [
        args.ghidra, wsl_path(project, args.distro), "address_pilot_" + str(time.time_ns()),
        "-import", args.binary,
        "-scriptPath", wsl_path(ROOT / "ghidra_scripts", args.distro),
        "-postScript", "ExportAddressFacts.java", wsl_path(args.out / "facts", args.distro), args.binary_id,
        "-analysisTimeoutPerFile", str(args.analysis_timeout), "-deleteProject",
    ]
    started = time.perf_counter()
    with (args.out / "ghidra.log").open("w", encoding="utf-8") as log:
        process = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    log = (args.out / "ghidra.log").read_text(encoding="utf-8", errors="replace")
    success = process.returncode == 0 and "ExportAddressFacts:" in log and "SCRIPT ERROR" not in log
    report = {
        "binary": args.binary_id, "original_path": args.binary, "original_sha256": digest,
        "command": command, "seconds": round(time.perf_counter() - started, 3),
        "returncode": process.returncode, "success": success,
        "scope": "export/score integration pilot; no effectiveness metrics",
    }
    (args.out / "run.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if not success:
        print(log[-6000:])
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
