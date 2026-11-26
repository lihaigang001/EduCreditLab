from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from educreditlab.cli import main
from educreditlab.merkle import MerkleTree, verify_multiproof
from educreditlab.model import LabError, digest, read_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, refresh_resolution_batch,
                                               select_resolution_witness, verify_checkpoint_resolution,
                                               verify_resolution_batch, verify_resolution_witness)
from educreditlab.transport import read_proof


class ResolutionSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        cls.short = cls.results / "resolution-batch/handover"
        cls.mixed = cls.results / "resolution-batch/mixed"
        cls.archives = cls.results / "resolution-checkpoint-extension"
        cls.pins = read_json(cls.short / "pins.json")
        cls.source = read_proof(cls.short / "refreshed-batch.json.gz")
        cls.numbers = cls.pins["expected_publications"]
        cls.trust = cls.pins["advanced_checkpoint_sha256"]
        cls.current = audit_resolution_checkpoint(read_proof(cls.archives / "short/history.json.gz"),
                                                  cls.pins["initial_authority_sha256"], cls.pins["latest_publication_sha256"])

    def select(self, numbers, *, source=None, expected=None, single=False, trust=None):
        return select_resolution_witness(self.source if source is None else source,
                                         self.trust if trust is None else trust,
                                         numbers=self.numbers if expected is None else expected,
                                         selected=numbers, single=single)

    def test_all_parent_and_child_sets_in_small_trees_match_fresh_paths(self):
        for size in range(1, 8):
            entries = [{"number": index + 1} for index in range(size)]
            tree = MerkleTree(entries)
            for parent in range(1, 1 << size):
                indices = [index for index in range(size) if parent & (1 << index)]
                leaves = [{"index": index, "entry": entries[index]} for index in indices]
                siblings = tree.multipath(indices)
                for child in range(1, 1 << len(indices)):
                    target = [index for offset, index in enumerate(indices) if child & (1 << offset)]
                    projected = verify_multiproof(leaves, siblings, size, tree.root, project_indices=target)
                    self.assertEqual(projected, tree.multipath(target), (size, parent, child))
                    if len(target) == 1:
                        self.assertEqual(projected, tree.path(target[0]))

    def test_projection_matches_complete_audit_and_keeps_only_the_selected_entries(self):
        projected = self.select([31, 1])
        self.assertEqual(projected, self.current.batch_witness([1, 31]))
        self.assertEqual(projected["entries"], [self.source["entries"][0], self.source["entries"][-1]])
        self.assertEqual(digest(projected["checkpoint"]), self.trust)
        status = verify_resolution_batch(projected, self.trust, numbers=[1, 31])
        self.assertEqual([entry["verified_publication"] for entry in status["verified_publications"]], [1, 31])
        self.assertEqual(self.select(list(reversed(self.numbers))), self.source)

    def test_single_output_matches_standard_witness_and_has_no_shared_mutable_fields(self):
        selected = self.select([31], single=True)
        self.assertEqual(selected, self.current.witness(31))
        ordinary = verify_resolution_witness(selected, self.trust, number=31)
        self.assertEqual(ordinary["verified_authority_sha256"], self.pins["initial_authority_sha256"])
        selected["entry"]["number"] = 30
        selected["checkpoint"]["publication_count"] = 30
        self.assertEqual(self.source["entries"][-1]["number"], 31)
        self.assertEqual(self.source["checkpoint"]["publication_count"], 39)

    def test_only_distinct_nonempty_subsets_of_the_expected_source_are_accepted(self):
        for target in ([], [5, 5], [39], [1, 8], [True], [40], [0]):
            with self.subTest(target=target), self.assertRaises(LabError):
                self.select(target)
        for expected in ([1, 31], [1, 5, 9, 13, 17, 21, 25, 30], [1] * len(self.numbers)):
            with self.subTest(expected=expected), self.assertRaises(LabError):
                self.select([1], expected=expected)
        with self.assertRaisesRegex(LabError, "A single witness requires exactly one"):
            self.select([1, 31], single=True)

    def test_omitted_entries_and_unused_source_hashes_must_still_verify(self):
        corrupted = deepcopy(self.source)
        corrupted["entries"][-1]["decision_sha256"] = "0" * 64
        with self.assertRaisesRegex(LabError, "does not match the trusted checkpoint"):
            self.select([1], source=corrupted)
        for siblings in (self.source["siblings"][:-1], [*self.source["siblings"], "0" * 64]):
            with self.subTest(length=len(siblings)), self.assertRaises(LabError):
                self.select([1], source={**self.source, "siblings": siblings})
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            self.select([1], trust=self.pins["base_checkpoint_sha256"])

    def test_an_omitted_head_still_has_to_match_the_descriptor_endpoint(self):
        source = self.current.batch_witness([1, 39])
        source["checkpoint"]["latest_publication_sha256"] = "0" * 64
        with self.assertRaisesRegex(LabError, "head publication does not match"):
            self.select([1], source=source, expected=[1, 39], trust=digest(source["checkpoint"]))

    def test_successive_narrowing_matches_direct_projection(self):
        initial = self.select([1, 9, 21, 31])
        later = self.select([31, 1], source=initial, expected=[1, 9, 21, 31])
        self.assertEqual(later, self.select([1, 31]))
        self.assertEqual(self.select([31], source=later, expected=[1, 31], single=True), self.current.witness(31))

    def test_project_then_refresh_matches_refresh_then_project(self):
        target = [1, 31]
        base_batch = read_proof(self.short / "base-batch.json.gz")
        filtered = self.select(target, source=base_batch, trust=self.pins["base_checkpoint_sha256"])
        head = read_proof(self.short / "base-head.json.gz")
        delta = read_proof(self.short / "delta.json.gz")
        advanced = refresh_resolution_batch(head, delta, filtered, self.pins["base_checkpoint_sha256"],
                                            self.pins["latest_publication_sha256"], numbers=target)
        self.assertEqual(advanced, self.select(target))

    def test_derived_proofs_preserve_authorities_on_either_side_of_handover(self):
        pins = read_json(self.mixed / "pins.json")
        source = read_proof(self.mixed / "refreshed-batch.json.gz")
        projected = self.select([1024, 1], source=source, expected=pins["expected_publications"],
                                trust=pins["advanced_checkpoint_sha256"])
        status = verify_resolution_batch(projected, pins["advanced_checkpoint_sha256"], numbers=[1, 1024])
        self.assertEqual([p["verified_authority_sha256"] for p in status["verified_publications"]],
                         [pins["initial_authority_sha256"], pins["incoming_authority_sha256"]])
        single = self.select([1024], source=projected, expected=[1, 1024], trust=pins["advanced_checkpoint_sha256"],
                             single=True)
        packet = read_proof(self.archives / "incoming-resolution.json.gz")
        review = verify_checkpoint_resolution(single, packet, pins["advanced_checkpoint_sha256"], number=1024)
        self.assertTrue(review["policy_resolution_verified"])

    def test_cli_writes_subset_only_after_source_and_selection_checks(self):
        def cli(*args, status=0):
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                self.assertEqual(main(["resolution-history", *map(str, args)]), status, err.getvalue())
                return json.loads(out.getvalue()) if status == 0 else err.getvalue()

        with TemporaryDirectory() as directory:
            output = Path(directory) / "subset.json.gz"
            source = self.short / "refreshed-batch.json.gz"
            expected = tuple(part for number in self.numbers for part in ("--publication", number))
            request = ("checkpoint-select-batch", source, "--publication-checkpoint-trust", self.trust,
                       *expected, "--select-publication", 31)
            cli(*request, "--select-publication", 32, "--out", output, status=2)
            self.assertFalse(output.exists())
            cli(*request, "--out", source, status=2)
            self.assertEqual(read_proof(source), self.source)
            exported = cli(*request, "--select-publication", 1, "--out", output)
            self.assertEqual(exported["publications"], [1, 31])
            self.assertEqual(read_proof(output), self.current.batch_witness([1, 31]))
            single = Path(directory) / "single.json.gz"
            cli(*request, "--single", "--out", single)
            self.assertEqual(read_proof(single), self.current.witness(31))


if __name__ == "__main__":
    unittest.main()
