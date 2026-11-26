from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from educreditlab.cli import main
from educreditlab.merkle import MerkleTree, _append_to_last_path, _leaf, verify_path
from educreditlab.model import LabError, digest, read_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, extend_resolution_checkpoint,
                                               resolution_checkpoint_delta, verify_checkpoint_resolution)
from educreditlab.transport import read_proof


class ResolutionCheckpointExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        cls.source = cls.results / "resolution-handover"
        cls.previous = cls.results / "resolution-checkpoint"
        cls.prior = read_proof(cls.source / "prior-history.json.gz")
        cls.short = read_proof(cls.source / "short/history.json.gz")
        cls.long = read_proof(cls.source / "long/history.json.gz")
        cls.initial, cls.short_tip = cls.history_pins("short")
        _, cls.long_tip = cls.history_pins("long")
        cls.prior_tip = read_json(cls.source / "prior-pins.json")["latest_publication_sha256"]
        cls.prior_index = audit_resolution_checkpoint(cls.prior, cls.initial, cls.prior_tip)
        cls.short_pin = read_json(cls.previous / "short/pins.json")["publication_checkpoint_sha256"]
        cls.short_witness = read_proof(cls.previous / "short/head-witness.json.gz")
        cls.delta = resolution_checkpoint_delta(cls.short, cls.initial, cls.short_tip, from_number=1)

    @classmethod
    def history_pins(cls, name):
        pins = read_json(cls.source / name / "pins.json")
        return pins["initial_authority_sha256"], pins["latest_publication_sha256"]

    def extend_prior(self, delta, tip=None):
        return extend_resolution_checkpoint(self.prior_index.witness(), delta, self.prior_index.fingerprint,
                                            self.short_tip if tip is None else tip)

    def test_last_path_extension_matches_complete_merkle_trees(self):
        leaves = [{"index": number} for number in range(80)]
        trees = [MerkleTree(leaves[:size]) for size in range(81)]
        for size in range(1, 65):
            path = trees[size].path(size - 1)
            verify_path(leaves[size - 1], size - 1, path, size, trees[size].root)
            for increment in (1, 2, 5, 16):
                end = size + increment
                actual = _append_to_last_path(leaves[size - 1], path, size, leaves[size:end])
                self.assertEqual(actual, (trees[end].root, trees[end].path(end - 1)), (size, end))

    def test_append_records_only_the_new_leaf_hashes_in_their_original_order(self):
        leaves = [{"number": number} for number in range(1, 46)]
        for size in (1, 7, 8, 9, 15, 16, 17, 31, 32, 33):
            base = MerkleTree(leaves[:size])
            full = MerkleTree(leaves)
            recorded = []
            result = _append_to_last_path(leaves[size - 1], base.path(size - 1), size,
                                          iter(leaves[size:]), recorded_hashes=recorded)
            self.assertEqual(result, (full.root, full.path(len(leaves) - 1)))
            self.assertEqual(recorded, [_leaf(entry) for entry in leaves[size:]])

    def test_singleton_base_can_cross_handover_and_chain_from_its_output(self):
        handover = {**self.short, "publications": self.short["publications"][:2]}
        handover_tip = digest(handover["publications"][-1]["body"])
        first = resolution_checkpoint_delta(handover, self.initial, handover_tip, from_number=1)
        witness = self.extend_prior(first, handover_tip)
        self.assertEqual(witness, audit_resolution_checkpoint(handover, self.initial, handover_tip).witness())
        new_packet = read_proof(self.source / "incoming-resolution.json.gz")
        handover_pin = digest(witness["checkpoint"])
        handover_result = verify_checkpoint_resolution(witness, new_packet, handover_pin)
        self.assertEqual(handover_result["verified_publication"], 2)
        self.assertEqual(handover_result["verified_authority_sha256"], digest(handover["publications"][-1]["body"]["successor_authority"]))
        second = resolution_checkpoint_delta(self.short, self.initial, self.short_tip, from_number=2)
        self.assertEqual(digest(second["base_authority"]), handover_result["verified_authority_sha256"])
        result = extend_resolution_checkpoint(witness, second, handover_pin, self.short_tip)
        self.assertEqual(result, self.extend_prior(self.delta))

    def test_packaged_v117_witness_extends_to_the_packaged_later_witness(self):
        delta = resolution_checkpoint_delta(self.long, self.initial, self.long_tip, from_number=3)
        result = extend_resolution_checkpoint(self.short_witness, delta, self.short_pin, self.long_tip)
        self.assertEqual(result, read_proof(self.previous / "long/head-witness.json.gz"))
        supplied = self.short_witness["checkpoint"]
        self.assertEqual(supplied["publication_count"], 3)
        self.assertEqual(supplied["latest_publication_sha256"], self.short_tip)
        self.assertEqual(digest(supplied), self.short_pin)

    def test_schema_one_history_can_extend_with_regular_publications(self):
        source = self.results / "resolution-history"
        history = read_proof(source / "long/history.json.gz")
        pins = read_json(source / "long/pins.json")
        initial, tip = pins["authority_sha256"], pins["latest_publication_sha256"]
        base = {**history, "publications": history["publications"][:7]}
        index = audit_resolution_checkpoint(base, initial, digest(base["publications"][-1]["body"]))
        delta = resolution_checkpoint_delta(history, initial, tip, from_number=7)
        witness = extend_resolution_checkpoint(index.witness(), delta, index.fingerprint, tip)
        self.assertEqual(witness, audit_resolution_checkpoint(history, initial, tip).witness())

    def test_export_needs_a_nonempty_base_and_nonempty_suffix_at_pinned_tip(self):
        for number in (0, True, 3):
            with self.subTest(number=number), self.assertRaises(LabError):
                resolution_checkpoint_delta(self.short, self.initial, self.short_tip, from_number=number)
        with self.assertRaisesRegex(LabError, "independently expected latest publication"):
            resolution_checkpoint_delta(self.short, self.initial, self.long_tip, from_number=1)
        with self.assertRaisesRegex(LabError, "nonempty base"):
            resolution_checkpoint_delta(self.prior, self.initial, self.prior_tip, from_number=1)

    def test_extension_requires_the_pinned_rightmost_leaf(self):
        old = read_proof(self.previous / "short/archived-witness.json.gz")
        delta = resolution_checkpoint_delta(self.long, self.initial, self.long_tip, from_number=3)
        with self.assertRaisesRegex(LabError, "selected publication number"):
            extend_resolution_checkpoint(old, delta, self.short_pin, self.long_tip)
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            extend_resolution_checkpoint(self.short_witness, delta, self.prior_index.fingerprint, self.long_tip)
        modified = {**self.short_witness, "siblings": ["0" * 64]}
        with self.assertRaisesRegex(LabError, "Merkle path"):
            extend_resolution_checkpoint(modified, delta, self.short_pin, self.long_tip)

    def test_mismatched_base_and_substituted_authority_fail(self):
        incoming = read_json(self.source / "incoming-authority.json")
        for fields, message in (({"base_publication_count": 2}, "delta base publication count"),
                                ({"base_publication_count": True}, "delta base publication count"),
                                ({"base_publication_sha256": "0" * 64}, "does not match the checkpoint head"),
                                ({"base_authority": incoming}, "trusted fingerprint")):
            with self.subTest(fields=list(fields)), self.assertRaisesRegex(LabError, message):
                self.extend_prior({**self.delta, **fields})

    def test_truncated_and_out_of_order_updates_fail(self):
        handover, next_entry = self.delta["publications"]
        for publications, message in (([], "new resolution publications"),
                                      ([handover], "independently expected latest publication"),
                                      ([next_entry, handover], "publication number"),
                                      ([next_entry], "publication number"),
                                      ([handover, handover], "publication number")):
            with self.subTest(publications=len(publications)), self.assertRaisesRegex(LabError, message):
                self.extend_prior({**self.delta, "publications": publications})
        modified = deepcopy(self.delta)
        modified["publications"][0]["body"]["previous_publication_sha256"] = "0" * 64
        with self.assertRaisesRegex(LabError, "history and preceding entry"):
            self.extend_prior(modified)

    def test_both_handover_thresholds_and_later_authority_apply(self):
        for role in ("outgoing", "incoming"):
            incomplete = deepcopy(self.delta)
            incomplete["publications"][0]["approvals"][role].pop()
            with self.subTest(role=role), self.assertRaisesRegex(LabError, f"{role.capitalize()} authority approval failed"):
                self.extend_prior(incomplete)
        outdated = deepcopy(self.delta)
        outdated["publications"][1]["approvals"] = self.prior["publications"][0]["approvals"]
        with self.assertRaisesRegex(LabError, "outside the trusted authority roster"):
            self.extend_prior(outdated)

    def test_cli_exports_and_extends_without_requiring_the_base_history(self):
        def cli(*args, exit_code=0):
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as error:
                self.assertEqual(main(["resolution-history", *map(str, args)]), exit_code, error.getvalue())
                return json.loads(out.getvalue()) if exit_code == 0 else error.getvalue()

        with TemporaryDirectory() as directory:
            delta = Path(directory) / "delta.json.gz"
            output = Path(directory) / "witness.json.gz"
            exported = cli("checkpoint-delta", self.source / "long/history.json.gz", "--from-publication", 3,
                           "--authority-trust", self.initial, "--publication-trust", self.long_tip, "--out", delta)
            self.assertEqual(exported["exported_publications"], 24)
            base = self.previous / "short/head-witness.json.gz"
            args = ("checkpoint-extend", base, delta, "--publication-checkpoint-trust", self.short_pin)
            cli(*args, "--publication-trust", self.short_tip, "--out", output, exit_code=2)
            self.assertFalse(output.exists())
            cli(*args, "--publication-trust", self.long_tip, "--out", delta, exit_code=2)
            self.assertIn("publications", read_proof(delta))
            result = cli(*args, "--publication-trust", self.long_tip, "--out", output)
            self.assertEqual(result["verified_new_publications"], 24)
            self.assertEqual(read_proof(output), read_proof(self.previous / "long/head-witness.json.gz"))
            checked = cli("checkpoint-verify", output, "--publication-checkpoint-trust",
                          result["publication_checkpoint_sha256"], "--resolution", self.source / "incoming-resolution.json.gz")
            self.assertTrue(checked["policy_resolution_verified"])
            self.assertEqual(checked["verified_publication"], 27)


if __name__ == "__main__":
    unittest.main()
