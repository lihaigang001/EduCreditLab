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
from educreditlab.keys import sign
from educreditlab.lab import verify_review
from educreditlab.model import LabError, canonical, digest, read_json
from educreditlab.review_attestation import SIGNING_DOMAIN, attest_review, reviewer_fingerprint, verify_attestation
from educreditlab.transport import read_proof


class ReviewAttestationTests(unittest.TestCase):
    def setUp(self):
        self.data = Path(__file__).resolve().parents[1] / "results/review-plan/demo"
        self.proof = read_proof(self.data / "review.json.gz")
        hashes = read_json(self.data / "pins.json")
        self.manifest = hashes["manifest_sha256"]
        self.checkpoint = hashes["checkpoint_sha256"]
        self.plan = hashes["review_plan_sha256"]
        self.key = Ed25519PrivateKey.generate()
        self.statement = attest_review(self.proof, self.key, self.manifest, self.checkpoint, self.plan)
        self.reviewer = reviewer_fingerprint(self.statement["body"]["reviewer_public_key"])

    def test_signature_only_requires_no_private_artifacts(self):
        with patch("educreditlab.review_attestation.verify_review", side_effect=AssertionError("unexpected replay")):
            result = verify_attestation(self.statement, self.reviewer, self.plan)
        self.assertTrue(result["signature_verified"])
        self.assertFalse(result["proof_rechecked"])
        self.assertEqual((result["receipt_count"], result["replay_count"], result["anchor_count"]), (3, 2, 1))
        serialized = canonical(self.statement)
        for key in (b'"evidence"', b'"transcript"', b'"attempts"', b'"decision"', b'"receipts"'):
            self.assertNotIn(key, serialized)

    def test_independent_recheck_matches_the_exact_proof_and_verified_result(self):
        bound = verify_attestation(self.statement, self.reviewer, self.plan, proof=self.proof,
                                   trusted_manifest=self.manifest, trusted_checkpoint=self.checkpoint)
        self.assertTrue(bound["proof_rechecked"])
        observed = verify_review(self.proof, self.manifest, trusted_checkpoint=self.checkpoint,
                                 trusted_plan=self.plan)
        self.assertEqual(bound["result_sha256"], digest(observed))
        self.assertEqual(bound["proof_sha256"], digest(self.proof))

    def test_wrong_reviewer_wrong_plan_and_wrong_expected_proof_are_rejected(self):
        with self.assertRaisesRegex(LabError, "Reviewer key"):
            verify_attestation(self.statement, "0" * 64, self.plan)
        with self.assertRaisesRegex(LabError, "review_plan_sha256"):
            verify_attestation(self.statement, self.reviewer, "0" * 64)
        with self.assertRaisesRegex(LabError, "proof_sha256"):
            verify_attestation(self.statement, self.reviewer, self.plan, expected_proof="0" * 64)

    def test_signed_counts_cannot_be_edited_and_unsigned_extra_fields_fail(self):
        changed = deepcopy(self.statement)
        changed["body"].update(replay_count=1, anchor_count=2)
        with self.assertRaisesRegex(LabError, "Invalid review-attestation signature"):
            verify_attestation(changed, self.reviewer, self.plan)
        changed["body"]["extra"] = "record"
        with self.assertRaisesRegex(LabError, "exactly these fields"):
            verify_attestation(changed, self.reviewer, self.plan)

    def test_recheck_requires_correct_original_and_independent_context(self):
        with self.assertRaisesRegex(LabError, "Independent manifest and checkpoint"):
            verify_attestation(self.statement, self.reviewer, self.plan, proof=self.proof)
        changed = deepcopy(self.proof)
        changed["siblings"] = []
        with self.assertRaisesRegex(LabError, "attested proof fingerprint"):
            verify_attestation(self.statement, self.reviewer, self.plan, proof=changed,
                               trusted_manifest=self.manifest, trusted_checkpoint=self.checkpoint)

    def test_recheck_rejects_valid_signature_over_incorrect_result_commitment(self):
        body = {**self.statement["body"], "result_sha256": "0" * 64}
        statement = {"body": body, "signature": sign(self.key, SIGNING_DOMAIN, body)}
        self.assertFalse(verify_attestation(statement, self.reviewer, self.plan)["proof_rechecked"])
        with self.assertRaisesRegex(LabError, "Recomputed review result"):
            verify_attestation(statement, self.reviewer, self.plan, proof=self.proof,
                               trusted_manifest=self.manifest, trusted_checkpoint=self.checkpoint)

    def test_signing_requires_a_verified_plan_bound_proof(self):
        with self.assertRaisesRegex(LabError, "plan-bound proof"):
            attest_review({"schema": 3}, self.key, self.manifest, self.checkpoint, self.plan)
        without_evidence = {**self.proof, "evidence": {}}
        with self.assertRaisesRegex(LabError, "requested replay set"):
            attest_review(without_evidence, self.key, self.manifest, self.checkpoint, self.plan)

    def test_cli_key_generation_signing_and_explicit_optional_recheck(self):
        with TemporaryDirectory() as folder:
            folder = Path(folder)
            key = folder / "reviewer.pem"
            output = folder / "attestation.json.gz"
            null_proof = folder / "null.json"
            null_proof.write_text("null", encoding="utf-8")
            passphrase = ["--key", str(key), "--passphrase-stdin"]
            with redirect_stdout(StringIO()) as created, patch("sys.stdin", TextIOWrapper(BytesIO(b"test-only\n"))):
                self.assertEqual(main(["review-keygen", *passphrase]), 0)
            reviewer = json.loads(created.getvalue())["reviewer_sha256"]
            self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", key.read_bytes())
            pins = ["--trust", self.manifest, "--checkpoint-trust", self.checkpoint]
            with redirect_stdout(StringIO()), patch("sys.stdin", TextIOWrapper(BytesIO(b"test-only\n"))):
                self.assertEqual(main(["review-attest", str(self.data / "review.json.gz"), *passphrase, *pins,
                                       "--plan-trust", self.plan, "--out", str(output)]), 0)
            base = ["verify-attestation", str(output), "--reviewer-trust", reviewer, "--plan-trust", self.plan]
            with redirect_stderr(StringIO()):
                self.assertEqual(main([*base, "--proof", str(null_proof), *pins]), 2)
            with redirect_stdout(StringIO()) as accepted:
                self.assertEqual(main([*base, "--proof", str(self.data / "review.json.gz"), *pins]), 0)
            self.assertTrue(json.loads(accepted.getvalue())["proof_rechecked"])


if __name__ == "__main__":
    unittest.main()
