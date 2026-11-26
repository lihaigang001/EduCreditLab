from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from itertools import combinations
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from educreditlab.checkpoint import audit_checkpoint, workspace_checkpoint
from educreditlab.cli import main
from educreditlab.custody_demo import run_demo
from educreditlab.lab import Lab, bundled_data, verify_review
from educreditlab.merkle import MerkleTree, verify_multiproof
from educreditlab.model import LabError, canonical, read_json
from educreditlab.transport import read_proof


class MultiproofTests(unittest.TestCase):
    def test_all_selections_through_eight_leaves_recover_the_same_root(self):
        for size in range(1, 9):
            entries = [{"value": i} for i in range(size)]
            tree = MerkleTree(entries)
            for count in range(1, size + 1):
                for selected in combinations(range(size), count):
                    leaves = [{"index": i, "entry": entries[i]} for i in selected]
                    siblings = tree.multipath(selected)
                    verify_multiproof(leaves, siblings, size, tree.root)
                    self.assertLessEqual(len(siblings), sum(len(tree.path(i)) for i in selected))

    def test_multiproof_requires_exact_order_positions_and_siblings(self):
        tree = MerkleTree(list(range(7)))
        leaves = [{"index": i, "entry": i} for i in (1, 4)]
        siblings = tree.multipath([1, 4])
        cases = (
            (leaves[::-1], siblings), (leaves[:1] * 2, siblings),
            ([{"index": True, "entry": 1}, leaves[1]], siblings),
            (leaves, siblings[:-1]), (leaves, siblings + ["0" * 64]),
            (leaves, ["0" * 64, *siblings[1:]]),
        )
        for selected, path in cases:
            with self.assertRaises(LabError):
                verify_multiproof(selected, path, 7, tree.root)


class BatchProofTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = Lab(self.root / "state", "central")
        self.lab.seed()
        transcript = bundled_data("cases.json")[0]["transcript"]
        date = "2023-06-15"
        self.before = self.lab.issue_workbench_receipt(transcript, "uc-irvine", "cse-bs", date)["receipt_sha256"]
        self.merced = self.lab.issue_workbench_receipt(transcript, "uc-merced", "cse-bs", date)["receipt_sha256"]
        self.lab.seed_amendment()
        self.after = self.lab.issue_workbench_receipt(transcript, "uc-irvine", "cse-bs", date)["receipt_sha256"]
        self.references = [self.before, self.merced, self.after]
        self.evidence = {ref: self.lab.ledger.artifact(ref, "receipt") for ref in self.references}
        index, archive = workspace_checkpoint(self.lab.ledger)
        self.trust = self.lab.ledger.fingerprint
        self.index = audit_checkpoint(archive, self.trust)
        self.assertEqual(self.index.fingerprint, index.fingerprint)

    def verify(self, proof, **options):
        return verify_review(proof, self.trust, trusted_checkpoint=self.index.fingerprint, **options)

    def test_batch_replays_each_historical_policy_across_two_scopes(self):
        proof = self.index.batch_proof(self.references, self.evidence)
        reverse = self.index.batch_proof(self.references[::-1], self.evidence)
        self.assertEqual(canonical(proof), canonical(reverse))
        self.assertEqual(len(proof["policies"]), 3)
        self.assertEqual(sum(row["entry"]["kind"] == "policy-scope" for row in proof["leaves"]), 2)
        verified = self.verify(proof, expected_receipts=self.references)
        self.assertEqual(verified["receipt_count"], 3)
        self.assertEqual([r["decision"]["recognized_units"] for r in verified["receipts"]], [1600, 2000, 400])
        for row in verified["receipts"]:
            ref = row["receipt_sha256"]
            single = self.verify(self.index.proof(ref, self.evidence[ref]))
            self.assertEqual(row, {key: single[key] for key in row})

    def test_anchor_batch_has_no_grades_and_requires_the_two_pins(self):
        proof = self.index.batch_proof(self.references)
        self.assertEqual(set(proof), {"schema", "manifest", "checkpoint", "leaves", "siblings"})
        self.assertNotIn(b'"attempts"', canonical(proof))
        checked = self.verify(proof)
        self.assertTrue(all(row["anchor_verified"] and not row["replayed"] for row in checked["receipts"]))
        with self.assertRaisesRegex(LabError, "independent manifest and checkpoint"):
            verify_review(proof, self.trust)
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            verify_review(proof, self.trust, trusted_checkpoint="0" * 64)

    def test_independently_expected_set_rejects_a_valid_incomplete_batch(self):
        partial = self.index.batch_proof([self.before])
        self.assertEqual(self.verify(partial)["receipt_count"], 1)
        with self.assertRaisesRegex(LabError, "expected receipt set"):
            self.verify(partial, expected_receipts=self.references)
        with self.assertRaisesRegex(LabError, "distinct commitments"):
            self.verify(partial, expected_receipts=[self.before, self.before])

    def test_export_requires_unique_members_within_the_checkpoint(self):
        with self.assertRaisesRegex(LabError, "distinct commitments"):
            self.index.batch_proof([self.before, self.before])
        with self.assertRaisesRegex(LabError, "not included"):
            self.index.batch_proof(["0" * 64])
        with self.assertRaisesRegex(LabError, "exactly the evidence"):
            self.index.batch_proof(self.references, {self.before: self.evidence[self.before]})

    def test_batch_verification_rejects_invalid_or_unbound_evidence(self):
        proof = self.index.batch_proof(self.references, self.evidence)
        missing, altered, swapped = (deepcopy(proof) for _ in range(3))
        missing["evidence"].pop(self.after)
        altered["evidence"][self.after]["receipt"]["signature"] = "0" * 128
        swapped["evidence"][self.before], swapped["evidence"][self.after] = (
            swapped["evidence"][self.after], swapped["evidence"][self.before])
        for modified in (missing, altered, swapped):
            with self.assertRaises(LabError):
                self.verify(modified)

    def test_batch_replays_receipts_across_actor_and_validator_rotations(self):
        directory = self.root / "managed"
        run_demo(directory)
        trust = (directory / "trusted-manifest-sha256.txt").read_text().strip()
        originals = [read_json(directory / f"proof-{side}-rotation.json") for side in ("before", "after")]
        index = audit_checkpoint(originals[-1], trust)
        artifacts = {}
        for original in originals:
            reference = verify_review(original, trust)["receipt_sha256"]
            artifacts[reference] = {key: original[key] for key in ("policy", "transcript", "receipt")}
        batch = index.batch_proof(list(artifacts), artifacts)
        result = verify_review(batch, trust, trusted_checkpoint=index.fingerprint)
        self.assertEqual(len(batch["policies"]), 1)
        self.assertEqual([r["height"] for r in result["receipts"]], [4, 7])
        self.assertEqual([r["decision"]["recognized_units"] for r in result["receipts"]], [1600, 1600])
        keys = [leaf["entry"]["actor_keys"]["uc-irvine"] for leaf in batch["leaves"] if leaf["entry"]["kind"] == "receipt"]
        self.assertNotEqual(keys[0], keys[1])

    def test_cli_exports_gzip_and_checks_the_exact_requested_receipts(self):
        target = self.root / "batch.json.gz"
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(["--workspace", str(self.root / "state"), "bundle-batch", *self.references,
                                   "--out", str(target)]), 0)
            command = ["verify", str(target), "--trust", self.trust, "--checkpoint-trust", self.index.fingerprint]
            self.assertEqual(main([*command, "--expect-receipt", self.before]), 2)
            stdout.seek(0)
            stdout.truncate()
            expected = [argument for ref in self.references for argument in ("--expect-receipt", ref)]
            self.assertEqual(main([*command, *expected]), 0)
        self.assertEqual(read_proof(target)["schema"], 3)
        self.assertEqual(json.loads(stdout.getvalue())["receipt_count"], 3)


if __name__ == "__main__":
    unittest.main()
