import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import score


class AddressModelTests(unittest.TestCase):
    def write_features(self, root: Path, name: str, rows: list[dict[str, str]]) -> None:
        path = root / name
        fields = list(rows[0])
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def make_features(self, root: Path) -> None:
        self.write_features(root, "functions.csv", [
            {"binary": "b", "function_id": "ram:10", "name": "duplicate", "is_external": "false", "is_thunk": "false", "executable_body_size": "10", "bb_count": "3", "edge_count": "4"},
            {"binary": "b", "function_id": "ram:20", "name": "duplicate", "is_external": "false", "is_thunk": "false", "executable_body_size": "10", "bb_count": "1", "edge_count": "0"},
            {"binary": "b", "function_id": "ram:30", "name": "external", "is_external": "true", "is_thunk": "false", "executable_body_size": "0", "bb_count": "0", "edge_count": "0"},
            {"binary": "b", "function_id": "ram:40", "name": "thunk", "is_external": "false", "is_thunk": "true", "executable_body_size": "10", "bb_count": "1", "edge_count": "0"},
            # Same address, different binary and non-candidate status: it must not
            # inherit b's candidate status.
            {"binary": "b2", "function_id": "ram:10", "name": "external_duplicate", "is_external": "true", "is_thunk": "false", "executable_body_size": "0", "bb_count": "0", "edge_count": "0"},
        ])
        self.write_features(root, "calls.csv", [
            {"binary": "b", "caller_id": "ram:10", "callee_id": "ram:20"},
        ])
        self.write_features(root, "callsites.csv", [
            {"binary": "b", "caller_id": "ram:10", "callee_id": "api:scanf", "callee_name": "__isoc99_scanf@@GLIBC_2.7", "address": "ram:11", "resolution_status": "resolved"},
            {"binary": "b", "caller_id": "ram:10", "callee_id": "api:read", "callee_name": "read@GLIBC_2.2.5", "address": "ram:12", "resolution_status": "resolved"},
            {"binary": "b", "caller_id": "ram:20", "callee_id": "api:gets", "callee_name": "gets@plt", "address": "ram:21", "resolution_status": "resolved"},
            {"binary": "b", "caller_id": "ram:10", "callee_id": "", "callee_name": "", "address": "ram:13", "resolution_status": "unresolved"},
            {"binary": "b2", "caller_id": "ram:10", "callee_id": "api:gets", "callee_name": "gets", "address": "ram:31", "resolution_status": "resolved"},
        ])
        self.write_features(root, "instructions.csv", [
            {"binary": "b", "instruction_id": "ram:22", "address": "ram:22", "caller_id": "ram:20", "caller_name": "duplicate", "mnemonic": "MOVSQ.REP"},
        ])

    def test_address_identity_population_and_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            features = Path(directory) / "features"
            features.mkdir()
            self.make_features(features)
            result = score.score_features(features)
            population = {(row["binary"], row["function"]) for row in result["population"]}
            self.assertEqual(population, {("b", "ram:10"), ("b", "ram:20")})
            self.assertEqual(
                {(row["binary"], row["function"]) for row in result["sink_population"]},
                population,
            )
            self.assertEqual({row["function"] for row in result["function_scores"]}, {"ram:10", "ram:20"})
            baselines = {row["baseline"] for row in result["baseline_function_scores"]}
            for baseline in baselines:
                self.assertEqual(
                    {(row["binary"], row["function"]) for row in result["baseline_function_scores"] if row["baseline"] == baseline},
                    population,
                )
            scanf = next(row for row in result["callsite_scores"] if row["callee"] == "scanf")
            self.assertEqual(scanf["reach"], 1.0)
            self.assertEqual(scanf["distance"], 0)
            self.assertEqual(scanf["path_count"], 1)
            self.assertTrue(any(row["kind"] == "unknown_call" for row in result["diagnostics"]))
            events = result["semantic_events"]
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0]["event_type"], "inline_copy")
            semantic = [row for row in result["baseline_function_scores"]
                        if row["baseline"] == "semantic_fusion"]
            self.assertGreater(next(row["risk"] for row in semantic if row["function"] == "ram:20"), 0.0)

    def test_semantic_event_parser_rejects_unrelated_mnemonics(self) -> None:
        self.assertEqual(score.semantic_event_type("MOVSQ.REP"), "inline_copy")
        self.assertEqual(score.semantic_event_type("STOSQ.REP"), "memory_set")
        self.assertIsNone(score.semantic_event_type("MOVSD"))
        self.assertEqual(score.semantic_event_type("MOVSD.REP"), "inline_copy")
        self.assertIsNone(score.semantic_event_type("MOV"))

    def test_semantic_event_register_context_is_bounded_and_optional(self) -> None:
        candidate = {"b": {"ram:1": {}}}
        instructions = [
            {"binary": "b", "caller_id": "ram:1", "caller_name": "f",
             "instruction_id": "ram:1", "address": "ram:1", "mnemonic": "MOV",
             "operand_text": "RCX, RAX"},
            {"binary": "b", "caller_id": "ram:1", "caller_name": "f",
             "instruction_id": "ram:2", "address": "ram:2", "mnemonic": "LEA",
             "operand_text": "RSI, [RBP]"},
            {"binary": "b", "caller_id": "ram:1", "caller_name": "f",
             "instruction_id": "ram:3", "address": "ram:3", "mnemonic": "LEA",
             "operand_text": "RDI, [RSP]"},
            {"binary": "b", "caller_id": "ram:1", "caller_name": "f",
             "instruction_id": "ram:4", "address": "ram:4", "mnemonic": "MOVSQ.REP",
             "operand_text": ""},
        ]
        event = score.collect_semantic_events(instructions, candidate, 3)[0]
        self.assertEqual(event["register_setup_count"], 3)
        self.assertEqual(event["register_context_score"], 1.0)
        legacy = score.collect_semantic_events(
            [{key: value for key, value in row.items() if key != "operand_text"}
             for row in instructions], candidate, 3)[0]
        self.assertEqual(legacy["operand_context_available"], 0)
        self.assertEqual(legacy["register_context_score"], 0.0)

    def test_hardening_file_does_not_change_ranking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            features = Path(directory) / "features"
            features.mkdir()
            self.make_features(features)
            before = score.score_features(features)["function_scores"]
            self.write_features(features, "hardening.csv", [{"binary": "b", "nx": "false", "canary": "false", "pie": "false", "relro": "none"}])
            after = score.score_features(features)["function_scores"]
            self.assertEqual(before, after)

    def test_strict_context_rejects_register_reads_and_cross_block_writes(self):
        def instruction(address, mnemonic, operands):
            return {"binary": "b", "caller_id": "ram:10", "address": f"ram:{address:x}",
                    "mnemonic": mnemonic, "operand_text": operands, "length": "1"}
        rows = [instruction(16, "LEA", "RDI; [RAX]"),
                instruction(17, "MOV", "RCX; RAX"),
                instruction(18, "SUB", "RCX; RDI"),
                instruction(19, "MOV", "RSI; R12"),
                instruction(20, "MOVSQ.REP", "RDI; RSI")]
        blocks = [{"binary": "b", "function_id": "ram:10", "block_id": "ram:11"}]
        event = score.collect_semantic_events(rows, {"b": {"ram:10": {}}}, 8,
                                              "block_register_writes", blocks)[0]
        self.assertEqual(event["register_setup_count"], 2)
        self.assertAlmostEqual(event["register_context_score"], 2/3, places=6)
        event = score.collect_semantic_events(rows, {"b": {"ram:10": {}}}, 8,
                                              "block_register_writes", [])[0]
        self.assertEqual(event["operand_context_available"], 0)

    def test_bounded_paths_cycles_depth_and_cap(self) -> None:
        graph = {"a": ("b", "c"), "b": ("a", "d"), "c": ("d",)}
        self.assertEqual(score.bounded_paths(graph, {"a"}, "a", 4, 100, 100), (1, 0, False))
        self.assertEqual(score.bounded_paths(graph, {"a"}, "d", 4, 100, 100), (2, 2, False))
        count, distance, truncated = score.bounded_paths(graph, {"a"}, "d", 4, 1, 100)
        self.assertEqual((count, distance), (1, 2))
        self.assertTrue(truncated)

    def directional_case(self, callsites, blocks, edges, functions=None, dangerous_names=None):
        functions = functions or [
            {"binary": "b", "function_id": "ram:100", "entry_address": "ram:100"},
            {"binary": "b", "function_id": "ram:200", "entry_address": "ram:200"},
        ]
        candidates = {"b": {row["function_id"] for row in functions}}
        return score.build_directional_evidence(
            functions, callsites, blocks, edges, [], {"read"},
            dangerous_names or {"memcpy"},
            candidates, 4, 100, 100,
        )

    def test_directional_same_function_requires_forward_cfg_order(self) -> None:
        calls = [
            {"binary": "b", "callsite_id": "ram:101", "address": "ram:101",
             "caller_id": "ram:100", "callee_id": "api:read", "callee_name": "read"},
            {"binary": "b", "callsite_id": "ram:111", "address": "ram:111",
             "caller_id": "ram:100", "callee_id": "api:memcpy", "callee_name": "memcpy"},
        ]
        blocks = [
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:100"},
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:110"},
        ]
        edges = [{"binary": "b", "function_id": "ram:100", "source_id": "ram:100", "target_id": "ram:110"}]
        evidence = self.directional_case(calls, blocks, edges)
        sink = evidence[("call", "b", "ram:100", "ram:111")]
        self.assertEqual(sink["directional_reach"], 1)
        self.assertEqual(sink["directional_status"], "witness")

        reverse = [dict(calls[1]), dict(calls[0])]
        reverse[0]["callsite_id"] = reverse[0]["address"] = "ram:101"
        reverse[1]["callsite_id"] = reverse[1]["address"] = "ram:111"
        reverse[0]["callee_name"], reverse[0]["callee_id"] = "memcpy", "api:memcpy"
        reverse[1]["callee_name"], reverse[1]["callee_id"] = "read", "api:read"
        evidence = self.directional_case(reverse, blocks, edges)
        sink = evidence[("call", "b", "ram:100", "ram:101")]
        self.assertEqual(sink["directional_reach"], 0)
        self.assertEqual(sink["directional_status"], "not_reached")

    def test_directional_rejects_mutually_exclusive_cfg_branches(self) -> None:
        calls = [
            {"binary": "b", "callsite_id": "ram:111", "address": "ram:111",
             "caller_id": "ram:100", "callee_id": "api:read", "callee_name": "read"},
            {"binary": "b", "callsite_id": "ram:121", "address": "ram:121",
             "caller_id": "ram:100", "callee_id": "api:memcpy", "callee_name": "memcpy"},
        ]
        blocks = [
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:100"},
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:110"},
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:120"},
        ]
        edges = [
            {"binary": "b", "function_id": "ram:100", "source_id": "ram:100", "target_id": "ram:110"},
            {"binary": "b", "function_id": "ram:100", "source_id": "ram:100", "target_id": "ram:120"},
        ]
        evidence = self.directional_case(calls, blocks, edges)
        sink = evidence[("call", "b", "ram:100", "ram:121")]
        self.assertEqual(sink["directional_reach"], 0)
        self.assertEqual(sink["directional_status"], "not_reached")

    def test_directional_follows_resolved_internal_callsite(self) -> None:
        calls = [
            {"binary": "b", "callsite_id": "ram:101", "address": "ram:101",
             "caller_id": "ram:100", "callee_id": "api:read", "callee_name": "read"},
            {"binary": "b", "callsite_id": "ram:111", "address": "ram:111",
             "caller_id": "ram:100", "callee_id": "ram:200", "callee_name": "helper"},
            {"binary": "b", "callsite_id": "ram:211", "address": "ram:211",
             "caller_id": "ram:200", "callee_id": "api:memcpy", "callee_name": "memcpy"},
        ]
        blocks = [
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:100"},
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:110"},
            {"binary": "b", "function_id": "ram:200", "block_id": "ram:200"},
            {"binary": "b", "function_id": "ram:200", "block_id": "ram:210"},
        ]
        edges = [
            {"binary": "b", "function_id": "ram:100", "source_id": "ram:100", "target_id": "ram:110"},
            {"binary": "b", "function_id": "ram:200", "source_id": "ram:200", "target_id": "ram:210"},
        ]
        evidence = self.directional_case(calls, blocks, edges)
        sink = evidence[("call", "b", "ram:200", "ram:211")]
        self.assertEqual(sink["directional_reach"], 1)
        self.assertEqual(sink["directional_distance"], 1)

    def test_directional_rejects_function_only_reachability(self) -> None:
        calls = [
            {"binary": "b", "callsite_id": "ram:121", "address": "ram:121",
             "caller_id": "ram:100", "callee_id": "api:read", "callee_name": "read"},
            {"binary": "b", "callsite_id": "ram:111", "address": "ram:111",
             "caller_id": "ram:100", "callee_id": "ram:200", "callee_name": "helper"},
            {"binary": "b", "callsite_id": "ram:211", "address": "ram:211",
             "caller_id": "ram:200", "callee_id": "api:memcpy", "callee_name": "memcpy"},
        ]
        blocks = [
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:100"},
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:110"},
            {"binary": "b", "function_id": "ram:100", "block_id": "ram:120"},
            {"binary": "b", "function_id": "ram:200", "block_id": "ram:200"},
            {"binary": "b", "function_id": "ram:200", "block_id": "ram:210"},
        ]
        edges = [
            {"binary": "b", "function_id": "ram:100", "source_id": "ram:100", "target_id": "ram:110"},
            {"binary": "b", "function_id": "ram:100", "source_id": "ram:100", "target_id": "ram:120"},
            {"binary": "b", "function_id": "ram:200", "source_id": "ram:200", "target_id": "ram:210"},
        ]
        evidence = self.directional_case(calls, blocks, edges)
        sink = evidence[("call", "b", "ram:200", "ram:211")]
        self.assertEqual(sink["directional_reach"], 0)
        self.assertEqual(sink["directional_status"], "not_reached")

    def test_directional_does_not_accept_source_site_as_its_own_sink(self) -> None:
        calls = [{
            "binary": "b", "callsite_id": "ram:101", "address": "ram:101",
            "caller_id": "ram:100", "callee_id": "api:read", "callee_name": "read",
        }]
        blocks = [{"binary": "b", "function_id": "ram:100", "block_id": "ram:100"}]
        evidence = self.directional_case(calls, blocks, [], dangerous_names={"read"})
        sink = evidence[("call", "b", "ram:100", "ram:101")]
        self.assertEqual(sink["directional_reach"], 0)
        self.assertEqual(sink["directional_status"], "not_reached")

    def test_equal_score_endpoints_do_not_hide_incomplete_analysis(self) -> None:
        self.assertEqual(score.interval_status(1, 1, "search_truncated"), "search_truncated")
        self.assertEqual(score.interval_status(1, 1, "witness", directional_truncated=True),
                         "search_truncated")
        self.assertEqual(score.interval_status(1, 1, "not_reached", path_truncated=True),
                         "search_truncated")
        self.assertEqual(score.interval_status(1, 1, "no_source_callsite"), "unverified_direction")
        self.assertEqual(score.interval_status(1, 1, "unavailable"), "unverified_direction")
        self.assertEqual(score.interval_status(1, 1, "witness"), "bounded")

    def test_witness_and_truncation_survive_scoring_fusion_and_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_features(root)
            sites = score.read_csv(root / "callsites.csv")
            events = [{"binary": "b", "function_id": "ram:20", "address": "ram:22"}]
            directional = {
                score.directional_key(kind, row): {
                    "directional_reach": 1, "directional_path_count": 1,
                    "directional_distance": 0, "directional_truncated": 0,
                    "directional_status": "witness",
                }
                for kind, rows in (("call", sites), ("event", events)) for row in rows
            }
            with patch.object(score, "build_directional_evidence", return_value=directional):
                before = score.score_features(root)
                for row in directional.values():
                    row["directional_truncated"] = 1
                after = score.score_features(root)
            for table in ("callsite_scores", "semantic_scores", "function_scores",
                          "semantic_fusion_scores", "baseline_function_scores"):
                numeric = ("risk", "risk_lower", "risk_upper", "uncertainty_width", "evidence_tier")
                self.assertEqual([[row.get(k) for k in numeric] for row in before[table]],
                                 [[row.get(k) for k in numeric] for row in after[table]])
                selected = [row for row in after[table]
                            if table != "baseline_function_scores" or row["baseline"] == "semantic_fusion"]
                self.assertTrue(selected)
                self.assertTrue(all(row["uncertainty_width"] == 0 for row in selected))
                self.assertTrue(all(row["uncertainty_status"] == "search_truncated" for row in selected))
            out = root / "out"
            score.write_outputs(out, after)
            for name in ("function_scores.csv", "baseline_function_scores.csv"):
                rows = [row for row in score.read_csv(out / name)
                        if name == "function_scores.csv" or row["baseline"] == "semantic_fusion"]
                self.assertTrue(all(row["search_truncated"] == "1" for row in rows))
                self.assertTrue(all(row["directional_truncated"] == "1" for row in rows))

    def test_real_search_cap_and_missing_cfg_remain_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_features(root)
            config = score.load_config(None)
            config["search_state_cap"] = 0
            result = score.score_features(root, config)
            for row in result["callsite_scores"] + result["semantic_scores"]:
                self.assertEqual(row["directional_truncated"], 1)
                self.assertEqual(row["directional_status"], "unavailable_cfg")
                self.assertEqual(row["uncertainty_status"], "search_truncated")
            for row in result["function_scores"]:
                self.assertEqual(row["search_truncated"], 1)
                self.assertEqual(row["direction_unverified"], 1)

    def test_low_scoring_semantic_site_provenance_and_empty_functions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_features(root)
            functions = score.read_csv(root / "functions.csv")
            functions.append(dict(functions[0], function_id="ram:50", name="no_sites"))
            self.write_features(root, "functions.csv", functions)
            directional = {
                score.directional_key("call", row): {
                    "directional_reach": 1, "directional_path_count": 1,
                    "directional_distance": 0, "directional_truncated": 0,
                    "directional_status": "witness",
                } for row in score.read_csv(root / "callsites.csv")
            }
            directional[("event", "b", "ram:20", "ram:22")] = {
                "directional_reach": 0, "directional_path_count": 0,
                "directional_distance": "", "directional_truncated": 1,
                "directional_status": "search_truncated",
            }
            config = score.load_config(None)
            config["top_k"] = 1
            with patch.object(score, "build_directional_evidence", return_value=directional):
                result = score.score_features(root, config)
            api = {row["function_id"]: row for row in result["function_scores"]}
            fusion = {row["function_id"]: row for row in result["baseline_function_scores"]
                      if row["baseline"] == "semantic_fusion"}
            self.assertEqual(api["ram:20"]["search_truncated"], 0)
            self.assertEqual(api["ram:20"]["risk"], fusion["ram:20"]["risk"])
            self.assertEqual(fusion["ram:20"]["uncertainty_width"], 0)
            self.assertEqual(fusion["ram:20"]["search_truncated"], 1)
            for rows in (api, fusion):
                self.assertEqual(rows["ram:50"]["uncertainty_status"], "no_evidence")
                self.assertEqual(rows["ram:50"]["search_truncated"], 0)

    def test_declared_rules_are_loaded_and_missing_files_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rules = root / "rules.csv"
            self.write_features(root, "rules.csv", [{"name": "execvp", "category": "command",
                                                      "cwe": "CWE-78", "base_weight": ""}])
            self.assertNotIn("execvp", score.load_dangerous(None))
            self.assertEqual(score.load_dangerous(rules)["execvp"][2], 0.5)
            with self.assertRaises(FileNotFoundError):
                score.load_dangerous(root / "missing.csv")
            with self.assertRaises(FileNotFoundError):
                score.load_sources(root / "missing.csv")


if __name__ == "__main__":
    unittest.main()
