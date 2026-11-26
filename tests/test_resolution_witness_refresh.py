from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from educreditlab.cli import main
from educreditlab.merkle import MerkleTree, _refresh_path, verify_path
from educreditlab.model import LabError, digest, read_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, extend_resolution_checkpoint,
                                               refresh_resolution_witness, resolution_checkpoint_delta,
                                               verify_checkpoint_resolution, verify_resolution_witness)
from educreditlab.transport import read_proof, write_proof


class ResolutionWitnessRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        cls.source = cls.results / "resolution-checkpoint-extension"
        cls.short = cls.source / "short"
        cls.pins = read_json(cls.short / "pins.json")
        cls.history = read_proof(cls.short / "history.json.gz")
        cls.head = read_proof(cls.short / "base-witness.json.gz")
        cls.delta = read_proof(cls.short / "delta.json.gz")
        base = {**cls.history, "publications": cls.history["publications"][:31]}
        cls.base = audit_resolution_checkpoint(base, cls.initial_pin(), cls.pins["base_publication_sha256"])
        cls.full = audit_resolution_checkpoint(cls.history, cls.initial_pin(), cls.pins["latest_publication_sha256"])

    @classmethod
    def initial_pin(cls):
        return cls.pins["initial_authority_sha256"]

    def refresh(self, archived=None, *, number=1, head=None, delta=None, tip=None):
        retained = self.base.witness(1) if archived is None else archived
        return refresh_resolution_witness(
            self.head if head is None else head, self.delta if delta is None else delta, retained,
            self.pins["base_checkpoint_sha256"], self.pins["latest_publication_sha256"] if tip is None else tip,
            number=number)

    def test_every_old_leaf_path_matches_full_trees_across_binary_boundaries(self):
        leaves = [{"number": index + 1} for index in range(80)]
        trees = [MerkleTree(leaves[:size]) for size in range(81)]
        for size in range(1, 65):
            for index in range(size):
                prior = trees[size].path(index)
                for added in (1, 2, 5, 16):
                    end = size + added
                    refreshed = _refresh_path(index, prior, size, leaves[size - 1],
                                              trees[size].path(size - 1), leaves[size:end])
                    self.assertEqual(refreshed, trees[end].path(index), (size, index, added))
                    verify_path(leaves[index], index, refreshed, end, trees[end].root)

    def test_refreshed_early_publication_retains_its_authority_and_decision(self):
        retained = self.base.witness(1)
        advanced = self.refresh(retained)
        self.assertEqual(advanced, self.full.witness(1))
        self.assertEqual(advanced["entry"], retained["entry"])
        self.assertEqual(advanced["checkpoint"], read_proof(self.short / "advanced-witness.json.gz")["checkpoint"])
        result = verify_resolution_witness(advanced, self.pins["advanced_checkpoint_sha256"], number=1)
        self.assertFalse(result["is_checkpoint_head"])
        self.assertEqual(result["verified_authority_sha256"], self.initial_pin())
        self.assertEqual(result["publication_count"], 39)

    def test_sequential_refresh_matches_applying_the_whole_update(self):
        intermediate = {**self.history, "publications": self.history["publications"][:35]}
        tip = digest(intermediate["publications"][-1]["body"])
        first = resolution_checkpoint_delta(intermediate, self.initial_pin(), tip, from_number=31)
        head = extend_resolution_checkpoint(self.head, first, self.base.fingerprint, tip)
        retained = self.base.witness(27)
        early = self.refresh(retained, number=27, delta=first, tip=tip)
        self.assertEqual(early["checkpoint"], head["checkpoint"])
        second = resolution_checkpoint_delta(self.history, self.initial_pin(), self.full.descriptor["latest_publication_sha256"],
                                             from_number=35)
        advanced = refresh_resolution_witness(head, second, early, digest(head["checkpoint"]),
                                             self.full.descriptor["latest_publication_sha256"], number=27)
        self.assertEqual(advanced, self.refresh(retained, number=27))
        self.assertEqual(advanced, self.full.witness(27))

    def test_a_base_head_can_become_a_historical_witness(self):
        refreshed = self.refresh(self.head, number=31)
        self.assertEqual(refreshed, self.full.witness(31))
        with self.assertRaisesRegex(LabError, "selected publication number"):
            verify_resolution_witness(refreshed, self.full.fingerprint)
        result = verify_resolution_witness(refreshed, self.full.fingerprint, number=31)
        self.assertEqual(result["verified_publication_sha256"], self.pins["base_publication_sha256"])
        self.assertFalse(result["is_checkpoint_head"])

    def test_number_must_be_explicit_and_match_even_for_repeated_decisions(self):
        other = self.base.witness(2)
        self.assertEqual(other["entry"]["decision_sha256"], self.base.witness(1)["entry"]["decision_sha256"])
        for ordinal in (1, True, None, 0, 32):
            with self.subTest(ordinal=ordinal), self.assertRaisesRegex(LabError, "selected publication number"):
                self.refresh(other, number=ordinal)

    def test_both_witnesses_must_match_the_pinned_base(self):
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            self.refresh(self.full.witness(1))
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            self.refresh(head=self.full.witness())
        with self.assertRaisesRegex(LabError, "selected publication number"):
            self.refresh(head=self.base.witness(1))

    def test_changed_path_or_authority_cannot_be_refreshed(self):
        original = self.base.witness(1)
        for document in ({**original, "siblings": ["0" * 64, *original["siblings"][1:]]},
                         {**original, "entry": {**original["entry"], "authority_sha256": self.pins["incoming_authority_sha256"]}}):
            with self.assertRaisesRegex(LabError, "Merkle path"):
                self.refresh(document)

    def test_delta_must_include_valid_thresholds_and_expected_endpoint(self):
        with self.assertRaisesRegex(LabError, "independently expected latest publication"):
            self.refresh(delta={**self.delta, "publications": self.delta["publications"][:-1]})
        for role in ("outgoing", "incoming"):
            insufficient = deepcopy(self.delta)
            insufficient["publications"][0]["approvals"][role].pop()
            with self.subTest(role=role), self.assertRaisesRegex(LabError, f"{role.capitalize()} authority approval failed"):
                self.refresh(delta=insufficient)

    def test_resolution_and_joint_confirmation_stay_bound_to_original_authority(self):
        refreshed = self.refresh()
        outgoing = read_proof(self.source / "outgoing-resolution.json.gz")
        left = read_proof(self.results / "policy-divergence/long/left-quorum.json.gz")
        verified = verify_checkpoint_resolution(refreshed, outgoing, self.full.fingerprint, number=1, bundle=left)
        self.assertEqual(verified["receipt_count"], 128)
        self.assertEqual(verified["verified_authority_sha256"], self.initial_pin())
        with self.assertRaises(LabError):
            verify_checkpoint_resolution(refreshed, read_proof(self.source / "incoming-resolution.json.gz"),
                                         self.full.fingerprint, number=1)
        right = read_proof(self.results / "policy-divergence/long/right-quorum.json.gz")
        with self.assertRaises(LabError):
            verify_checkpoint_resolution(refreshed, outgoing, self.full.fingerprint, number=1, bundle=right)

    def test_cli_outputs_only_after_verification_and_keeps_its_inputs(self):
        def cli(*args, status=0):
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                self.assertEqual(main(["resolution-history", *map(str, args)]), status, err.getvalue())
            return json.loads(out.getvalue()) if status == 0 else err.getvalue()

        with TemporaryDirectory() as directory:
            root = Path(directory)
            previous, output = root / "old.json.gz", root / "refreshed.json.gz"
            write_proof(previous, self.base.witness(1))
            flags = ("checkpoint-refresh", self.short / "base-witness.json.gz", self.short / "delta.json.gz", previous,
                     "--publication-checkpoint-trust", self.base.fingerprint)
            end = ("--publication-trust", self.full.descriptor["latest_publication_sha256"])
            self.assertIn("selected publication number", cli(*flags, *end, "--publication", 2, "--out", output, status=2))
            self.assertFalse(output.exists())
            self.assertIn("separate from the input", cli(*flags, *end, "--publication", 1, "--out", previous, status=2))
            self.assertEqual(read_proof(previous), self.base.witness(1))
            result = cli(*flags, *end, "--publication", 1, "--out", output)
            self.assertEqual(result["refreshed_publication"], 1)
            self.assertEqual(result["verified_new_publications"], 8)
            self.assertEqual(result["publication_checkpoint_sha256"], self.full.fingerprint)
            self.assertEqual(read_proof(output), self.full.witness(1))
            verdict = cli("checkpoint-verify", output, "--publication-checkpoint-trust", self.full.fingerprint,
                          "--publication", 1)
            self.assertEqual(verdict["verified_authority_sha256"], self.initial_pin())


if __name__ == "__main__":
    unittest.main()
