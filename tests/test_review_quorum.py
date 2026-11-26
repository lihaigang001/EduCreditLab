from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from educreditlab.cli import main
from educreditlab.keys import public_key, sign
from educreditlab.model import LabError, digest, read_json
from educreditlab.review_attestation import SIGNING_DOMAIN, attest_review, reviewer_fingerprint, verify_attestation
from educreditlab.review_quorum import _recheck_signed_result, bundle_quorum, make_quorum_policy, verify_quorum
from educreditlab.transport import read_proof, write_proof


class ReviewQuorumTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(__file__).resolve().parents[1] / "results/review-plan/demo"
        self.proof = read_proof(self.data / "review.json.gz")
        pins = read_json(self.data / "pins.json")
        self.manifest = pins["manifest_sha256"]
        self.checkpoint = pins["checkpoint_sha256"]
        self.plan = pins["review_plan_sha256"]
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.roster = [reviewer_fingerprint(public_key(key)) for key in self.keys]
        self.policy = make_quorum_policy(self.plan, self.roster, 2)
        self.policy_pin = digest(self.policy)
        self.statements = [self.attest(key) for key in self.keys]

    def attest(self, key):
        return attest_review(self.proof, key, self.manifest, self.checkpoint, self.plan)

    def bundle(self):
        return bundle_quorum(self.policy, self.statements[:2], self.policy_pin)

    def test_accepted_quorum_is_order_independent_and_rechecks_the_proof_once(self):
        packet = self.bundle()
        self.assertEqual(packet, bundle_quorum(self.policy, self.statements[:2][::-1], self.policy_pin))
        self.assertEqual(self.policy, make_quorum_policy(self.plan, self.roster[::-1], 2))
        with patch("educreditlab.review_quorum._recheck_signed_result", wraps=_recheck_signed_result) as recheck:
            signed = verify_quorum(packet, self.policy_pin)
            self.assertFalse(signed["proof_rechecked"])
            recheck.assert_not_called()
            checked = verify_quorum(packet, self.policy_pin, proof=self.proof, trusted_manifest=self.manifest,
                                    trusted_checkpoint=self.checkpoint)
            recheck.assert_called_once()
        self.assertTrue(checked["quorum_verified"] and checked["proof_rechecked"])
        self.assertEqual(checked["reviewers"], sorted(self.roster[:2]))
        self.assertEqual((checked["signer_count"], checked["threshold"]), (2, 2))
        self.assertEqual((checked["replay_count"], checked["anchor_count"]), (2, 1))
        self.assertEqual(checked["proof_sha256"], digest(self.proof))
        self.assertEqual(checked["result_sha256"], self.statements[0]["body"]["result_sha256"])

    def test_only_valid_rosters_and_thresholds_are_allowed(self):
        with self.assertRaisesRegex(LabError, "unique and sorted"):
            make_quorum_policy(self.plan, [self.roster[0]] * 2, 1)
        for threshold in (0, 4, True):
            with self.assertRaisesRegex(LabError, "signature threshold"):
                make_quorum_policy(self.plan, self.roster, threshold)

    def test_below_threshold_duplicates_and_reordered_wrappers_fail(self):
        with self.assertRaisesRegex(LabError, "threshold has not been met"):
            bundle_quorum(self.policy, self.statements[:1], self.policy_pin)
        with self.assertRaisesRegex(LabError, "distinct reviewers"):
            bundle_quorum(self.policy, self.statements[:1] * 2, self.policy_pin)
        packet = self.bundle()
        packet["attestations"].reverse()
        with self.assertRaisesRegex(LabError, "fingerprint order"):
            verify_quorum(packet, self.policy_pin)

    def test_unlisted_key_and_outdated_policy_pin_fail(self):
        outsider = self.attest(Ed25519PrivateKey.generate())
        with self.assertRaisesRegex(LabError, "outside the trusted policy"):
            bundle_quorum(self.policy, [self.statements[0], outsider], self.policy_pin)
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            verify_quorum(self.bundle(), "0" * 64)
        changed = {**self.bundle(), "policy": {**self.policy, "threshold": 1}}
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            verify_quorum(changed, self.policy_pin)

    def test_authenticated_statements_must_agree_and_belong_to_the_pinned_plan(self):
        for field in ("proof_sha256", "result_sha256", "checkpoint_sha256"):
            with self.subTest(field=field):
                body = {**self.statements[1]["body"], field: "0" * 64}
                differing = {"body": body, "signature": sign(self.keys[1], SIGNING_DOMAIN, body)}
                self.assertTrue(verify_attestation(differing, self.roster[1], self.plan)["signature_verified"])
                with self.assertRaisesRegex(LabError, "disagree"):
                    bundle_quorum(self.policy, [self.statements[0], differing], self.policy_pin)
        body = {**self.statements[1]["body"], "review_plan_sha256": "0" * 64}
        other_plan = {"body": body, "signature": sign(self.keys[1], SIGNING_DOMAIN, body)}
        with self.assertRaisesRegex(LabError, "review_plan_sha256"):
            bundle_quorum(self.policy, [self.statements[0], other_plan], self.policy_pin)

    def test_one_invalid_signature_fails_even_with_enough_others(self):
        changed = {**self.statements[2], "signature": "0" * 128}
        with self.assertRaisesRegex(LabError, "Invalid review-attestation signature"):
            bundle_quorum(self.policy, [*self.statements[:2], changed], self.policy_pin)

    def test_independent_recheck_demands_pins_and_exact_original_proof(self):
        packet = self.bundle()
        with self.assertRaisesRegex(LabError, "Independent manifest and checkpoint"):
            verify_quorum(packet, self.policy_pin, proof=self.proof)
        with self.assertRaisesRegex(LabError, "proof_sha256"):
            verify_quorum(packet, self.policy_pin, expected_proof="0" * 64)
        changed = deepcopy(self.proof)
        changed["siblings"] = []
        with self.assertRaisesRegex(LabError, "attested proof fingerprint"):
            verify_quorum(packet, self.policy_pin, proof=changed, trusted_manifest=self.manifest,
                          trusted_checkpoint=self.checkpoint)

    def test_cli_offline_workflow_and_explicit_proof_input(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy, bundle = root / "policy.json", root / "quorum.json.gz"
            statements = [root / f"{i}.json.gz" for i in range(2)]
            for path, signed in zip(statements, self.statements):
                write_proof(path, signed)
            roster = [arg for key in self.roster for arg in ("--reviewer-trust", key)]
            with redirect_stdout(StringIO()) as generated:
                self.assertEqual(main(["review-quorum", "--plan-trust", self.plan, "--threshold", "2",
                                       "--out", str(policy), *roster]), 0)
            pin = json.loads(generated.getvalue())["policy_sha256"]
            common = ["--policy-trust", pin]
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["bundle-quorum", str(policy), str(statements[0]), *common,
                                       "--out", str(bundle)]), 2)
            self.assertFalse(bundle.exists())
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["bundle-quorum", str(policy), *map(str, statements), *common,
                                       "--out", str(bundle)]), 0)
            null = root / "null.json"
            null.write_text("null", encoding="utf-8")
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["verify-quorum", str(bundle), *common, "--proof", str(null)]), 2)
            with redirect_stdout(StringIO()) as result:
                self.assertEqual(main(["verify-quorum", str(bundle), *common, "--proof",
                                       str(self.data / "review.json.gz"), "--trust", self.manifest,
                                       "--checkpoint-trust", self.checkpoint]), 0)
            self.assertTrue(json.loads(result.getvalue())["proof_rechecked"])


if __name__ == "__main__":
    unittest.main()
