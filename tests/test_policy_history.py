from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import BytesIO, StringIO, TextIOWrapper
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from educreditlab.cli import main
from educreditlab.keys import public_key, save_private_key
from educreditlab.model import LabError, digest, read_json
from educreditlab.policy_history import (append_policy_change, approve_policy_change, init_policy_history,
                                        verify_policy_history, verify_review_at_revision)
from educreditlab.review_attestation import attest_review, reviewer_fingerprint
from educreditlab.review_quorum import bundle_quorum, make_quorum_policy
from educreditlab.transport import read_proof, write_proof


class ReviewerPolicyHistoryTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(__file__).resolve().parents[1] / "results/review-plan/demo"
        self.pins = read_json(self.data / "pins.json")
        self.keys = [Ed25519PrivateKey.generate() for _ in range(5)]
        self.roster = [reviewer_fingerprint(public_key(key)) for key in self.keys]
        plan = self.pins["review_plan_sha256"]
        self.initial = make_quorum_policy(plan, self.roster[:4], 3)
        self.replacement = make_quorum_policy(plan, self.roster[1:], 3)
        self.reduced = make_quorum_policy(plan, self.roster[1:], 2)
        self.root = digest(self.initial)
        self.started = init_policy_history(self.initial, self.root)

    def approvals(self, history, current, proposed, signers):
        return [approve_policy_change(history, proposed, self.keys[index], self.root, current) for index in signers]

    def extend(self, history, current, proposed, signers):
        return append_policy_change(history, proposed, self.approvals(history, current, proposed, signers),
                                    self.root, current)

    def rotated(self):
        return self.extend(self.started, self.root, self.replacement, (0, 1, 2, 4))

    def advanced(self):
        history, pin = self.rotated()
        return self.extend(history, pin, self.reduced, (1, 2, 4))

    def test_rotates_roster_then_changes_threshold_and_preserves_prior_history(self):
        self.assertEqual(verify_policy_history(self.started, self.root, self.root)["latest_revision"], 1)
        history, tip = self.advanced()
        result = verify_policy_history(history, self.root, tip)
        self.assertEqual((result["latest_revision"], result["threshold"], result["reviewer_count"]), (3, 2, 4))
        self.assertEqual(result["current_policy_sha256"], digest(self.reduced))
        self.assertEqual(self.started["changes"], [])
        self.assertNotEqual(tip, digest(self.reduced))

    def test_both_rosters_must_meet_their_thresholds(self):
        for signers, failure in (((1, 2, 4), "Preceding"), ((0, 1, 2), "Successor")):
            with self.subTest(signers=signers), self.assertRaisesRegex(LabError, failure + " policy signature threshold"):
                self.extend(self.started, self.root, self.replacement, signers)
        history, tip = self.rotated()
        with self.assertRaisesRegex(LabError, "Preceding policy signature threshold"):
            self.extend(history, tip, self.reduced, (1, 2))

    def test_duplicate_or_outside_signer_is_rejected(self):
        with self.assertRaisesRegex(LabError, "distinct keys"):
            self.extend(self.started, self.root, self.replacement, (0, 1, 2, 2, 4))
        with self.assertRaisesRegex(LabError, "outside both reviewer rosters"):
            approve_policy_change(self.started, self.replacement, Ed25519PrivateKey.generate(), self.root, self.root)

    def test_signed_body_binds_parent_number_and_successor(self):
        history, tip = self.advanced()
        for field, changed in (("previous_revision_sha256", self.root), ("revision", 4),
                               ("policy", self.replacement)):
            with self.subTest(field=field):
                modified = deepcopy(history)
                modified["changes"][1]["body"][field] = changed
                with self.assertRaises(LabError):
                    verify_policy_history(modified, self.root, tip)
        modified = deepcopy(history)
        modified["changes"][1]["approvals"][0]["signature"] = "0" * 128
        with self.assertRaisesRegex(LabError, "Invalid review-policy-change signature"):
            verify_policy_history(modified, self.root, tip)

    def test_independent_fingerprints_reject_stale_and_unrelated_histories(self):
        history, tip = self.advanced()
        earlier, earlier_pin = self.rotated()
        for document, pin in ((earlier, tip), (history, earlier_pin)):
            with self.assertRaisesRegex(LabError, "expected latest revision"):
                verify_policy_history(document, self.root, pin)
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            verify_policy_history(history, "0" * 64, tip)

    def test_plan_is_fixed_and_restored_policy_content_has_a_new_revision_id(self):
        next_plan = make_quorum_policy("0" * 64, self.roster[:4], 3)
        with self.assertRaisesRegex(LabError, "must keep the independently agreed review plan"):
            self.extend(self.started, self.root, next_plan, (0, 1, 2))
        history, pin = self.rotated()
        reinstated, tip = self.extend(history, pin, self.initial, (0, 1, 2, 4))
        self.assertNotEqual(self.root, tip)
        self.assertEqual(verify_policy_history(reinstated, self.root, tip)["current_policy_sha256"], self.root)

    def test_review_uses_selected_policy_and_can_recheck_original_proof(self):
        proof = read_proof(self.data / "review.json.gz")
        manifest, checkpoint, plan = (self.pins[name] for name in
                                      ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256"))
        statements = [attest_review(proof, key, manifest, checkpoint, plan) for key in self.keys]
        historical = bundle_quorum(self.initial, statements[:3], self.root)
        current = bundle_quorum(self.reduced, [statements[1], statements[4]], digest(self.reduced))
        history, tip = self.advanced()
        result = verify_review_at_revision(history, historical, self.root, tip, revision=1)
        self.assertEqual((result["policy_revision"], result["latest_revision"]), (1, 3))
        self.assertFalse(result["proof_rechecked"])
        with self.assertRaisesRegex(LabError, "Reviewer policy does not match"):
            verify_review_at_revision(history, historical, self.root, tip)
        with self.assertRaisesRegex(LabError, "selected policy revision"):
            verify_review_at_revision(history, current, self.root, tip, revision=4)
        checked = verify_review_at_revision(history, current, self.root, tip, proof=proof,
                                            trusted_manifest=manifest, trusted_checkpoint=checkpoint)
        self.assertTrue(checked["proof_rechecked"])
        self.assertEqual((checked["policy_revision"], checked["signer_count"]), (3, 2))
        self.assertEqual(checked["result_sha256"], result["result_sha256"])

    def test_cli_initializes_signs_appends_and_verifies_portable_history(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            policy, successor = folder / "initial.json", folder / "successor.json"
            started, rotated = folder / "initial.json.gz", folder / "rotated.json.gz"
            write_proof(policy, self.initial)
            write_proof(successor, self.replacement)

            def cli(*args):
                with redirect_stdout(StringIO()) as output:
                    self.assertEqual(main(["policy-history", *map(str, args)]), 0)
                return json.loads(output.getvalue())

            cli("init", policy, "--policy-trust", self.root, "--out", started)
            trust = ["--initial-trust", self.root, "--revision-trust", self.root]
            approvals = []
            for index in (0, 1, 2, 4):
                key = folder / f"reviewer-{index}.pem"
                approval = folder / f"approval-{index}.json"
                save_private_key(key, self.keys[index], b"synthetic-test-key")
                with TextIOWrapper(BytesIO(b"synthetic-test-key\n")) as passphrase, patch("sys.stdin", passphrase):
                    cli("approve", started, successor, *trust, "--key", key, "--passphrase-stdin", "--out", approval)
                approvals.append(approval)
            result = cli("append", started, successor, *approvals, *trust, "--out", rotated)
            self.assertEqual(cli("verify", rotated, "--initial-trust", self.root, "--revision-trust",
                                 result["latest_revision_sha256"])["latest_revision"], 2)
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["policy-history", "append", str(started), str(successor),
                                       *map(str, approvals), *trust, "--out", str(started)]), 2)
            self.assertEqual(read_proof(started)["changes"], [])


if __name__ == "__main__":
    unittest.main()
