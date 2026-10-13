# Address-model handoff

Exporter source:

`experiments/revision/address_model/ghidra_scripts/ExportAddressFacts.java`

Ghidra 12.1.2 headless invocation from the WSL runner:

```text
/home/voidex/tools/ghidra_12.1.2_PUBLIC/support/analyzeHeadless <project_dir> <project_name> -import <binary> -scriptPath <workspace>/experiments/revision/address_model/ghidra_scripts -postScript ExportAddressFacts.java <facts_dir> <binary_id> -analysisTimeoutPerFile 120 -deleteProject
```

The Windows-side pilot wrapper uses the same command through `wsl -d Ubuntu-24.04 --exec`; see `run_pilot.py`.

Score one exported facts directory:

```text
python experiments/revision/address_model/score.py --features <facts_dir> --out <scores_dir> --config experiments/revision/address_model/config.json
```

The scorer does not read labels. It writes `function_scores.csv`, `baseline_function_scores.csv`, and `population.csv`; each score file uses `binary,function,risk`, where `function` is the recovered entry address ID. `population.csv` contains every internal, non-thunk recovered executable function, and every baseline has exactly that per-binary address set. `sink_population.csv` is the separately auditable C set of functions with at least one normalized dangerous API call; it must be used only for the shared-sink view. The all-functions view ranks the full `population.csv` F set and uses its size as the population/effort budget. A zero score in F is a real retained candidate and must not be used to infer membership in C.

The main evaluator should emit both views for every method: `scope=all_functions` over F and `scope=shared_sink` after filtering each method's scores to C, while retaining `population=len(F)` for the budget. Missing sink rows must remain missing in the C audit instead of being converted into zero-risk sink rows. The checked main evaluator currently uses the legacy scope label `archived_universes` for its full-population view; rename or alias that output to `all_functions` in the main-owned evaluator.

The exporter writes fresh CSVs for each binary. `callsites.csv` has one row per instruction address, and `calls.csv` preserves resolved multi-target edges. Unresolved and partially resolved calls remain marked in `instructions.csv`, `calls.csv`, and `callsites.csv`.
