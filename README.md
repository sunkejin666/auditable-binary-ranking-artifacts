# Code and Data

Research artifacts for *Auditable Vulnerability Candidate Ranking and Failure Analysis for ELF Binaries*.

License: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/) (CC BY 4.0). Cite this archive using `CITATION.cff` and credit the listed authors when reusing its contents.

- `code/` contains 20 original Python and C source files, plus a repository verification entry point.
- `data/` contains 151 CSV, JSON, JSONL, and log files, plus two experiment protocol documents: configurations, manifests, saved observations, evaluation results, and audit records.

The 173 original code and data files are byte-for-byte copies from `Supplementary_Evidence.zip` (SHA-256: `b2f915c6a2473a40dba13b6b0ad437692677d36d0dab443b37ca561ed692d0828`). Their paths preserve their locations within that archive. The included `data/file_manifest.json` describes the original archive paths and hashes, not this split directory layout.

To audit saved results with Python 3 and the standard library, run from the repository root:

```console
python code/verify_repository.py
```

The entry point reconstructs the original archive layout in a temporary directory and runs the original verifier. It checks 169 manifest hashes, saved numerical summaries, and recovery-event hash chains. Successful output is `PASS: 77 saved-result checks; 169 copied file hashes.` Repository files remain unchanged.

This is a curated set of saved research artifacts. It does not include all source binaries, external tool images, or extracted fact tables required to rerun every experiment. Verification checks saved records; it does not rerun binary experiments or bootstrap resampling. Some historical records contain local absolute paths retained for provenance; those paths are not portable inputs.
