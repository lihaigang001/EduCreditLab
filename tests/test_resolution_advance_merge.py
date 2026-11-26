from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import unittest

from educreditlab import resolution_checkpoint
from educreditlab.cli import main
from educreditlab.merkle import MerkleTree, _appended_siblings, verify_multiproof
from educreditlab.model import LabError, digest, read_json
from educreditlab.resolution_checkpoint import (advance_and_merge_resolution_witnesses,
                                               audit_resolution_checkpoint, verify_resolution_batch)
from educreditlab.transport import gzip_proof, read_proof, write_proof


class ResolutionAdvanceMergeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        results = Path(__file__).resolve().parents[1] / "results"
        cls.fixture = results / "resolution-batch/handover"
        cls.pins = read_json(cls.fixture / "pins.json")
        cls.head = read_proof(cls.fixture / "base-head.json.gz")
        cls.delta = read_proof(cls.fixture / "delta.json.gz")
        cls.history = read_proof(results / "resolution-checkpoint-extension/short/history.json.gz")
        authority = cls.pins["initial_authority_sha256"]
        cls.base_pin = cls.pins["base_checkpoint_sha256"]
        cls.tip = cls.pins["latest_publication_sha256"]
        base_history = {**cls.history, "publications": cls.history["publications"][:31]}
        cls.base = audit_resolution_checkpoint(base_history, authority, cls.pins["base_publication_sha256"])
        cls.current = audit_resolution_checkpoint(cls.history, authority, cls.tip)
        cls.sources = [cls.base.batch_witness([1, 5]), cls.current.witness(39),
                       cls.base.witness(31), cls.current.batch_witness([5, 32])]
        cls.numbers = [1, 5, 31, 32, 39]

    def merge(self, witnesses, numbers=None, *, base_pin=None, tip=None, delta=None, new_publications=None):
        return advance_and_merge_resolution_witnesses(
            self.head, self.delta if delta is None else delta, witnesses,
            self.base_pin if base_pin is None else base_pin, self.tip if tip is None else tip,
            numbers=self.numbers if numbers is None else numbers, new_publications=new_publications)

    def test_mixed_witnesses_match_audit_and_keep_original_authorities(self):
        snapshot = deepcopy(self.sources)
        batch = self.merge(self.sources[::-1], self.numbers[::-1])
        self.assertEqual(batch, self.current.batch_witness(self.numbers))
        self.assertEqual(self.sources, snapshot)
        self.assertEqual(self.merge(self.sources), batch)
        checked = verify_resolution_batch(batch, self.pins["advanced_checkpoint_sha256"], numbers=self.numbers)
        self.assertEqual([entry["verified_authority_sha256"] for entry in checked["verified_publications"]],
                         [self.pins["initial_authority_sha256"]] * 3 + [self.pins["incoming_authority_sha256"]] * 2)

    def test_a_single_checkpoint_cohort_works_at_either_end(self):
        for sources, expected in ((self.sources[::2], [1, 5, 31]), (self.sources[1::2], [5, 32, 39]),
                                  (self.sources[1:2], [39])):
            with self.subTest(expected=expected):
                self.assertEqual(self.merge(sources, expected), self.current.batch_witness(expected))

    def test_extension_is_verified_once_for_multiple_archived_inputs(self):
        with patch.object(resolution_checkpoint, "_verify_publications",
                          wraps=resolution_checkpoint._verify_publications) as verify:
            batch = self.merge(self.sources + [self.base.witness(1), self.base.witness(5)])
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(batch, self.current.batch_witness(self.numbers))

    def test_a_valid_intermediate_checkpoint_requires_its_own_update(self):
        prefix = {**self.history, "publications": self.history["publications"][:32]}
        index = audit_resolution_checkpoint(prefix, self.pins["initial_authority_sha256"],
                                            digest(prefix["publications"][-1]["body"]))
        with self.assertRaisesRegex(LabError, "base or advanced publication checkpoint"):
            self.merge([*self.sources, index.witness(32)])

    def test_redundant_invalid_proofs_at_either_end_are_rejected(self):
        for candidate in (self.sources[2], self.sources[3]):
            invalid = deepcopy(candidate)
            invalid["siblings"][0] = "0" * 64
            with self.subTest(kind=candidate["kind"]), self.assertRaisesRegex(LabError, "Merkle"):
                self.merge([*self.sources, invalid])

    def test_exact_expected_union_is_required_without_implicit_head_entry(self):
        for numbers, message in (([1, 5, 31, 39], "exactly the expected"),
                                 ([1, 5, 31, 32, 33, 39], "exactly the expected"),
                                 ([1, 5, 31, 32, 39, 39], "must be distinct")):
            with self.subTest(numbers=numbers), self.assertRaisesRegex(LabError, message):
                self.merge(self.sources, numbers)
        batch = self.merge([self.sources[0], self.sources[3]], [1, 5, 32])
        self.assertEqual(batch, self.current.batch_witness([1, 5, 32]))

    def test_malformed_or_missing_source_and_expected_list_are_rejected(self):
        for witnesses, message in (([], "at least one publication witness"),
                                   (None, "at least one publication witness"),
                                   ([None], "base or advanced publication checkpoint")):
            with self.subTest(witnesses=witnesses), self.assertRaisesRegex(LabError, message):
                self.merge(witnesses)
        with self.assertRaisesRegex(LabError, "expected publication numbers"):
            advance_and_merge_resolution_witnesses(self.head, self.delta, self.sources,
                                                   self.base_pin, self.tip, numbers=None)

    def test_base_and_terminal_pins_are_independently_checked(self):
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            self.merge(self.sources, base_pin=self.pins["advanced_checkpoint_sha256"])
        with self.assertRaisesRegex(LabError, "independently expected latest publication"):
            self.merge(self.sources, tip=self.pins["base_publication_sha256"])
        truncated = {**self.delta, "publications": self.delta["publications"][:-1]}
        with self.assertRaisesRegex(LabError, "independently expected latest publication"):
            self.merge(self.sources, delta=truncated)

    def test_even_current_only_inputs_require_both_handover_thresholds(self):
        for role in ("outgoing", "incoming"):
            invalid = deepcopy(self.delta)
            invalid["publications"][0]["approvals"][role].pop()
            message = f"{role.capitalize()} authority approval failed"
            with self.subTest(role=role), self.assertRaisesRegex(LabError, message):
                self.merge(self.sources[1::2], [5, 32, 39], delta=invalid)

    def test_appended_frontier_matches_complete_trees_for_every_small_suffix_subset(self):
        entries = [{"number": index + 1} for index in range(38)]
        trees = [MerkleTree(entries[:count]) for count in range(39)]
        for size in range(1, 33):
            boundary = _appended_siblings(size, entries[size - 1], trees[size].path(size - 1))
            for count in range(1, 7):
                total = size + count
                tree = trees[total]
                leaves = [{"index": index, "entry": entries[index]} for index in range(size, total)]
                self.assertEqual(boundary, tree.multipath(range(size, total)), (size, total))
                for mask in range(1, 1 << count):
                    selected = [size + offset for offset in range(count) if mask & (1 << offset)]
                    projected = verify_multiproof(leaves, boundary, total, tree.root, project_indices=selected)
                    self.assertEqual(projected, tree.multipath(selected), (size, total, selected))

    def test_proves_a_suffix_subset_without_other_witnesses_or_implicit_head(self):
        wanted = [32, 35, 38]
        batch = self.merge([], wanted, new_publications=wanted[::-1])
        self.assertEqual(batch, self.current.batch_witness(wanted))
        checked = verify_resolution_batch(batch, self.pins["advanced_checkpoint_sha256"], numbers=wanted)
        self.assertEqual([r["verified_authority_sha256"] for r in checked["verified_publications"]],
                         [self.pins["incoming_authority_sha256"]] * len(wanted))

    def test_proves_all_additions_from_a_singleton_base(self):
        records = self.history["publications"]
        prefix = {**self.history, "publications": records[:1]}
        authority = self.pins["initial_authority_sha256"]
        first = audit_resolution_checkpoint(prefix, authority, digest(records[0]["body"]))
        continuation = resolution_checkpoint.resolution_checkpoint_delta(
            self.history, authority, self.tip, from_number=1)
        numbers = list(range(2, 40))
        batch = advance_and_merge_resolution_witnesses(first.witness(), continuation, [], first.fingerprint, self.tip,
                                                       numbers=numbers, new_publications=numbers)
        self.assertEqual(batch, self.current.batch_witness(numbers))

    def test_combines_base_witnesses_and_signed_additions_with_one_continuation_check(self):
        snapshot = deepcopy(self.delta)
        with patch.object(resolution_checkpoint, "_verify_publications",
                          wraps=resolution_checkpoint._verify_publications) as verify:
            batch = self.merge(self.sources[::2], new_publications=[39, 32])
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(batch, self.current.batch_witness(self.numbers))
        self.assertEqual(self.delta, snapshot)

    def test_new_proofs_can_overlap_current_sources_but_each_source_is_checked(self):
        batch = self.merge(self.sources, new_publications=[32, 39])
        self.assertEqual(batch, self.current.batch_witness(self.numbers))
        invalid = deepcopy(self.sources[1])
        invalid["siblings"][0] = "0" * 64
        with self.assertRaisesRegex(LabError, "Merkle"):
            self.merge([*self.sources, invalid], new_publications=[32, 39])

    def test_new_selection_is_distinct_within_the_signed_suffix_and_matches_exact_union(self):
        for selection, message in (([31], "after the base checkpoint"), ([40], "selected publication number"),
                                   ([True], "selected publication number"), ([], "expected publication numbers"),
                                   ([32, 32], "must be distinct")):
            with self.subTest(selection=selection), self.assertRaisesRegex(LabError, message):
                self.merge([], [32], new_publications=selection)
        for selection in ([32], [32, 33, 39]):
            with self.subTest(selection=selection), self.assertRaisesRegex(LabError, "exactly the expected"):
                self.merge(self.sources[::2], new_publications=selection)

    def test_derivation_alone_checks_both_handover_thresholds_and_independent_tip(self):
        for role in ("outgoing", "incoming"):
            invalid = deepcopy(self.delta)
            invalid["publications"][0]["approvals"][role].pop()
            with self.subTest(role=role), self.assertRaisesRegex(LabError, f"{role.capitalize()} authority approval failed"):
                self.merge([], [32], delta=invalid, new_publications=[32])
        with self.assertRaisesRegex(LabError, "independently expected latest publication"):
            self.merge([], [32], tip=self.pins["base_publication_sha256"], new_publications=[32])

    def test_cli_derives_suffix_only_proof_and_still_requires_expected_ordinals(self):
        with TemporaryDirectory() as directory:
            out = Path(directory) / "new.json.gz"
            arguments = ["resolution-history", "checkpoint-advance-merge-batch",
                         str(self.fixture / "base-head.json.gz"), str(self.fixture / "delta.json.gz"),
                         "--publication-checkpoint-trust", self.base_pin, "--publication-trust", self.tip, "--out", str(out)]
            expected = ["--publication", "32", "--publication", "38"]
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                self.assertEqual(main(arguments + expected), 2)
                self.assertIn("at least one publication witness", stderr.getvalue())
                self.assertFalse(out.exists())
                with self.assertRaises(SystemExit) as parse:
                    main(arguments + ["--include-new-publication", "32"])
                self.assertEqual(parse.exception.code, 2)
                self.assertFalse(out.exists())
                self.assertEqual(main([*arguments, *expected, "--include-new-publication", "38",
                                       "--include-new-publication", "32"]), 0, stderr.getvalue())
            self.assertEqual(json.loads(stdout.getvalue())["publications"], [32, 38])
            self.assertEqual(out.read_bytes(), gzip_proof(self.current.batch_witness([32, 38])))

    def test_cli_accepts_json_and_gzip_and_writes_only_a_verified_result(self):
        def command(*args, exit_code=0):
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                self.assertEqual(main(["resolution-history", *map(str, args)]), exit_code, stderr.getvalue())
                return json.loads(stdout.getvalue()) if exit_code == 0 else stderr.getvalue()

        with TemporaryDirectory() as directory:
            folder = Path(directory)
            sources = [folder / name for name in ("base.json", "current.json.gz", "old.json.gz", "new.json")]
            for path, source in zip(sources, self.sources, strict=True):
                write_proof(path, source)
            out = folder / "combined.json.gz"
            arguments = ("checkpoint-advance-merge-batch", self.fixture / "base-head.json.gz",
                         self.fixture / "delta.json.gz", *sources,
                         "--publication-checkpoint-trust", self.base_pin, "--publication-trust", self.tip)
            expected = [part for number in self.numbers for part in ("--publication", number)]
            self.assertIn("exactly the expected", command(*arguments, *expected[:-2], "--out", out, exit_code=2))
            self.assertFalse(out.exists())
            self.assertIn("separate from the input", command(*arguments, *expected, "--out", sources[0], exit_code=2))
            self.assertEqual(read_proof(sources[0]), self.sources[0])
            status = command(*arguments, *expected, "--out", out)
            self.assertEqual(status["publications"], self.numbers)
            self.assertEqual(out.read_bytes(), gzip_proof(self.current.batch_witness(self.numbers)))
            verified = command("checkpoint-verify-batch", out, *expected, "--publication-checkpoint-trust",
                               status["publication_checkpoint_sha256"])
            self.assertTrue(verified["publication_checkpoint_batch_verified"])


if __name__ == "__main__":
    unittest.main()
