"""Run the original saved-result verifier against the split repository layout."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    repository = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="binary-ranking-audit-") as temporary:
        audit_root = Path(temporary)
        for section in ("code", "data"):
            source_root = repository / section
            for source in sorted(source_root.rglob("*")):
                if not source.is_file():
                    continue
                relative = source.relative_to(source_root)
                if "__pycache__" in relative.parts or source.suffix == ".pyc":
                    continue
                destination = audit_root / relative
                if destination.exists():
                    raise RuntimeError(f"Overlapping artifact path: {relative}")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        subprocess.run(
            [sys.executable, str(audit_root / "verify_saved_results.py")],
            cwd=audit_root,
            check=True,
        )


if __name__ == "__main__":
    main()
