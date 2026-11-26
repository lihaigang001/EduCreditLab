from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from educreditlab import merkle, resolution_checkpoint
from educreditlab.cli import main
from educreditlab.merkle import MerkleTree, _refresh_frontier, verify_multiproof
from educreditlab.model import LabError, digest, read_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, refresh_resolution_batch,
                                               resolution_checkpoint_delta, verify_checkpoint_batch_resolution,
                                               verify_resolution_batch)
from educreditlab.transport import read_proof, write_proof


class ResolutionBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        cls.fixtures = cls.results / "resolution-checkpoint-extension"
        cls.short = cls.fixtures / "short"
        cls.pins = read_json(cls.short / "pins.json")
        cls.history = read_proof(cls.short / "history.json.gz")
        cls.head = read_proof(cls.short / "base-witness.json.gz")
        cls.delta = read_proof(cls.short / "delta.json.gz")
        cls.initial = cls.pins["initial_authority_sha256"]
        cls.tip = cls.pins["latest_publication_sha256"]
        cls.full = audit_resolution_checkpoint(cls.history, cls.initial, cls.tip)
        cls.base = cls.prefix(31)[0]
        cls.numbers = [1, 7, 31]
        cls.archived = cls.base.batch_witness(cls.numbers)

    @classmethod
    def prefix(cls, count):
        history = {**cls.history, "publications": cls.history["publications"][:count]}
        tip = digest(history["publications"][-1]["body"])
        return audit_resolution_checkpoint(history, cls.initial, tip), history, tip

    def refresh(self, archived=None, *, numbers=None, head=None, delta=None, tip=None):
        return refresh_resolution_batch(
            self.head if head is None else head, self.delta if delta is None else delta,
            self.archived if archived is None else archived,
            self.base.fingerprint, self.tip if tip is None else tip, numbers=self.numbers if numbers is None else numbers)

    def test_all_nonempty_small_sets_refresh_to_the_full_tree_paths(self):
        leaves = [{"number": index + 1} for index in range(24)]
        trees = [MerkleTree(leaves[:count]) for count in range(25)]
        for base in range(1, 9):
            for mask in range(1, 1 << base):
                indices = [index for index in range(base) if mask & (1 << index)]
                selected = [{"index": index, "entry": leaves[index]} for index in indices]
                for appended in (1, 2, 5, 16):
                    total = base + appended
                    siblings = _refresh_frontier(indices, trees[base].multipath(indices), base, leaves[base - 1],
                                                  trees[base].path(base - 1), leaves[base:total])
                    self.assertEqual(siblings, trees[total].multipath(indices), (base, mask, appended))
                    verify_multiproof(selected, siblings, total, trees[total].root)

    def test_shared_roots_match_full_trees_for_odd_sizes_and_source_orders(self):
        leaves = [{"number": number} for number in range(1, 66)]
        trees = [MerkleTree(leaves[:count]) for count in range(66)]
        for total in (3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65):
            counts = list(range(1, total))
            for order in (counts, list(reversed(counts)), counts[::2] + counts[1::2]):
                final_subtrees = {}
                for base in order:
                    indices = sorted({0, base // 2, base - 1})
                    siblings = _refresh_frontier(indices, trees[base].multipath(indices), base, leaves[base - 1],
                                                  trees[base].path(base - 1), leaves[base:total],
                                                  final_subtrees=final_subtrees)
                    self.assertEqual(siblings, trees[total].multipath(indices), (base, total, order))

    def test_shared_final_siblings_reduce_leaf_hash_calls_for_overlapping_ranges(self):
        leaves = [{"number": number} for number in range(1, 97)]
        bases = (8, 16, 23, 32)
        trees = {base: MerkleTree(leaves[:base]) for base in bases}
        expected = MerkleTree(leaves).multipath([0])

        def refresh_all(shared):
            with patch.object(merkle, "_leaf", wraps=merkle._leaf) as leaf:
                for base, tree in trees.items():
                    actual = _refresh_frontier([0], tree.multipath([0]), base, leaves[base - 1],
                                               tree.path(base - 1), leaves[base:], final_subtrees=shared)
                    self.assertEqual(actual, expected)
                return leaf.call_count

        self.assertLess(refresh_all({}), refresh_all(None))

    def test_batches_are_canonical_and_prove_exact_expected_numbers(self):
        shuffled = [31, 1, 7]
        self.assertEqual(self.base.batch_witness(shuffled), self.archived)
        status = verify_resolution_batch(self.archived, self.base.fingerprint, numbers=shuffled)
        self.assertEqual([entry["verified_publication"] for entry in status["verified_publications"]], self.numbers)
        self.assertTrue(status["verified_publications"][-1]["is_checkpoint_head"])
        for numbers in ([], [1, 7], [1, 7, 30], [1, 7, 31, 30], [1, 7, 7], [True, 7, 31], [1, 7, 32]):
            with self.subTest(numbers=numbers), self.assertRaises(LabError):
                verify_resolution_batch(self.archived, self.base.fingerprint, numbers=numbers)

    def test_invalid_frontier_and_entries_reject_the_whole_batch(self):
        changes = [
            {"entries": list(reversed(self.archived["entries"]))},
            {"entries": [self.archived["entries"][0]] * 3},
            {"entries": [{**self.archived["entries"][0], "authority_sha256": self.pins["incoming_authority_sha256"]},
                         *self.archived["entries"][1:]]},
            {"siblings": ["0" * 64, *self.archived["siblings"][1:]]},
            {"siblings": self.archived["siblings"][:-1]},
            {"siblings": [*self.archived["siblings"], "0" * 64]},
        ]
        for changeset in changes:
            with self.assertRaises(LabError):
                verify_resolution_batch({**self.archived, **changeset}, self.base.fingerprint, numbers=self.numbers)

    def test_batch_refresh_checks_the_continuation_once_and_keeps_every_leaf(self):
        with patch.object(resolution_checkpoint, "_verify_publications",
                          wraps=resolution_checkpoint._verify_publications) as verify:
            refreshed = self.refresh()
            self.assertEqual(verify.call_count, 1)
        self.assertEqual(refreshed, self.full.batch_witness(self.numbers))
        self.assertEqual(refreshed["entries"], self.archived["entries"])
        self.assertEqual(refreshed["checkpoint"], read_proof(self.short / "advanced-witness.json.gz")["checkpoint"])
        status = verify_resolution_batch(refreshed, self.full.fingerprint, numbers=self.numbers)
        self.assertFalse(status["verified_publications"][-1]["is_checkpoint_head"])

    def test_single_member_and_all_members_refresh(self):
        for numbers in ([31], list(range(1, 32))):
            with self.subTest(count=len(numbers)):
                archived = self.base.batch_witness(numbers)
                refreshed = self.refresh(archived, numbers=numbers)
                self.assertEqual(refreshed, self.full.batch_witness(numbers))

    def test_refresh_requires_pinned_base_and_signature_thresholds(self):
        for archived, head, delta, tip in (
                (self.full.batch_witness(self.numbers), None, None, None),
                (None, self.full.witness(), None, None),
                (None, self.base.witness(7), None, None),
                (None, None, None, self.pins["base_publication_sha256"]),
                (None, None, {**self.delta, "publications": self.delta["publications"][:-1]}, None)):
            with self.assertRaises(LabError):
                self.refresh(archived, head=head, delta=delta, tip=tip)
        for role in ("outgoing", "incoming"):
            insufficient = deepcopy(self.delta)
            insufficient["publications"][0]["approvals"][role].pop()
            with self.assertRaisesRegex(LabError, f"{role.capitalize()} authority approval failed"):
                self.refresh(delta=insufficient)

    def test_successive_refreshes_match_one_step_and_full_audit(self):
        mid, history, tip = self.prefix(35)
        first = resolution_checkpoint_delta(history, self.initial, tip, from_number=31)
        partial = self.refresh(delta=first, tip=tip)
        second = resolution_checkpoint_delta(self.history, self.initial, self.tip, from_number=35)
        advanced = refresh_resolution_batch(mid.witness(), second, partial, mid.fingerprint, self.tip,
                                             numbers=self.numbers)
        self.assertEqual(advanced, self.refresh())
        self.assertEqual(advanced, self.full.batch_witness(self.numbers))

    def test_batch_review_uses_the_authority_at_each_position(self):
        base = self.prefix(35)[0]
        delta = resolution_checkpoint_delta(self.history, self.initial, self.tip, from_number=35)
        numbers = [1, 31, 32, 35]
        refreshed = refresh_resolution_batch(base.witness(), delta, base.batch_witness(numbers),
                                              base.fingerprint, self.tip, numbers=numbers)
        status = verify_resolution_batch(refreshed, self.full.fingerprint, numbers=numbers)
        incoming = self.pins["incoming_authority_sha256"]
        self.assertEqual([entry["verified_authority_sha256"] for entry in status["verified_publications"]],
                         [self.initial, self.initial, incoming, incoming])
        outgoing_packet = read_proof(self.fixtures / "outgoing-resolution.json.gz")
        incoming_packet = read_proof(self.fixtures / "incoming-resolution.json.gz")
        for number, packet, branch in ((31, outgoing_packet, "left"), (32, incoming_packet, "right")):
            confirmation = self.results / f"policy-divergence/long/{branch}-quorum.json.gz"
            review = verify_checkpoint_batch_resolution(refreshed, packet, self.full.fingerprint, numbers=numbers,
                                                        number=number, bundle=read_proof(confirmation))
            self.assertEqual(review["verified_publication"], number)
            self.assertEqual(review["receipt_count"], 128)
        with self.assertRaises(LabError):
            verify_checkpoint_batch_resolution(refreshed, incoming_packet, self.full.fingerprint, numbers=numbers, number=31)
        with self.assertRaisesRegex(LabError, "must be in the verified batch"):
            verify_checkpoint_batch_resolution(refreshed, incoming_packet, self.full.fingerprint, numbers=numbers, number=39)

    def test_cli_can_export_refresh_and_verify_selected_batch(self):
        def cli(*args, status=0):
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as err:
                self.assertEqual(main(["resolution-history", *map(str, args)]), status, err.getvalue())
                return json.loads(out.getvalue()) if status == 0 else err.getvalue()

        with TemporaryDirectory() as path:
            root = Path(path)
            expected = ("--publication", 31, "--publication", 1, "--publication", 7)
            current = root / "full.json.gz"
            out = root / "refreshed.json.gz"
            retained = root / "retained.json.gz"
            write_proof(retained, self.archived)
            export = cli("checkpoint-batch", self.short / "history.json.gz", "--authority-trust", self.initial,
                         "--publication-trust", self.tip, *expected, "--out", current)
            self.assertEqual(export["publications"], self.numbers)
            refresh = ("checkpoint-refresh-batch", self.short / "base-witness.json.gz", self.short / "delta.json.gz", retained,
                       "--publication-checkpoint-trust", self.base.fingerprint, "--publication-trust", self.tip)
            cli(*refresh, "--publication", 7, "--out", out, status=2)
            self.assertFalse(out.exists())
            cli(*refresh, *expected, "--out", retained, status=2)
            self.assertEqual(read_proof(retained), self.archived)
            cli(*refresh, *expected, "--out", out)
            self.assertEqual(out.read_bytes(), current.read_bytes())
            verify = ("checkpoint-verify-batch", out, "--publication-checkpoint-trust", self.full.fingerprint, *expected)
            status = cli(*verify)
            self.assertEqual([entry["verified_publication"] for entry in status["verified_publications"]], self.numbers)
            cli(*verify, "--select-publication", 1, status=2)
            review = cli(*verify, "--select-publication", 1, "--resolution", self.fixtures / "outgoing-resolution.json.gz")
            self.assertTrue(review["policy_resolution_verified"])


if __name__ == "__main__":
    unittest.main()
