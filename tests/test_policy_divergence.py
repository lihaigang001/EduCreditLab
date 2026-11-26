from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from http.server import ThreadingHTTPServer
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from educreditlab.cli import main
from educreditlab.keys import public_key
from educreditlab.lab import Lab
from educreditlab.model import LabError, canonical, digest
from educreditlab.policy_divergence import compare_policy_histories, verify_policy_divergence
from educreditlab.policy_history import append_policy_change, approve_policy_change, init_policy_history
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.review_quorum import make_quorum_policy
from educreditlab.server import _handler
from educreditlab.transport import gzip_proof, read_proof, write_proof


class PolicyDivergenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        keys = [Ed25519PrivateKey.generate() for _ in range(5)]
        fps = [reviewer_fingerprint(public_key(key)) for key in keys]

        def policy(roster, threshold):
            return make_quorum_policy("a" * 64, [fps[i] for i in roster], threshold)

        original = policy((0, 1, 2, 3), 2)
        shared = policy((0, 1, 2, 3), 3)
        cls.root = digest(original)
        cls.started = init_policy_history(original, cls.root)

        def advance(previous, pin, successor, indices):
            signatures = [approve_policy_change(previous, successor, keys[i], cls.root, pin) for i in indices]
            return append_policy_change(previous, successor, signatures, cls.root, pin)

        cls.common, cls.common_pin = advance(cls.started, cls.root, shared, (0, 1, 2))
        cls.alternate_common, alternate_pin = advance(cls.started, cls.root, shared, (1, 2, 3))
        assert alternate_pin == cls.common_pin
        cls.left, cls.left_pin = advance(cls.common, cls.common_pin, policy((0, 1, 2, 4), 3), (0, 1, 2, 4))
        cls.right, cls.right_pin = advance(cls.alternate_common, cls.common_pin, policy((0, 2, 3, 4), 3), (0, 2, 3, 4))
        cls.left_final, cls.left_final_pin = advance(cls.left, cls.left_pin, shared, (0, 1, 2, 3))
        cls.right_final, cls.right_final_pin = advance(cls.right, cls.right_pin, shared, (0, 1, 2, 3))
        cls.overlap = sorted((fps[0], fps[2]))

    def compare(self, left, right, left_pin, right_pin):
        return compare_policy_histories(left, right, self.root, left_pin, right_pin)

    def evidence(self):
        return self.compare(self.left, self.right, self.left_pin, self.right_pin)[1]

    def test_different_approval_sets_for_the_same_revision_are_identical(self):
        self.assertNotEqual(self.common["changes"], self.alternate_common["changes"])
        compared, evidence = self.compare(self.common, self.alternate_common, self.common_pin, self.common_pin)
        self.assertEqual((compared["relationship"], compared["shared_revision"]), ("identical", 2))
        self.assertIsNone(evidence)

    def test_both_histories_verify_even_when_their_revision_bodies_match(self):
        altered = deepcopy(self.alternate_common)
        altered["changes"][0]["approvals"][0]["signature"] = "0" * 128
        with self.assertRaisesRegex(LabError, "Invalid review-policy-change signature"):
            self.compare(self.common, altered, self.common_pin, self.common_pin)

    def test_proper_prefixes_are_distinguished_from_divergence(self):
        compared, evidence = self.compare(self.started, self.left, self.root, self.left_pin)
        self.assertEqual((compared["relationship"], compared["shared_revision"]), ("left_prefix", 1))
        self.assertIsNone(evidence)
        compared, evidence = self.compare(self.left, self.alternate_common, self.left_pin, self.common_pin)
        self.assertEqual((compared["relationship"], compared["shared_revision"]), ("right_prefix", 2))
        self.assertIsNone(evidence)

    def test_matching_policies_at_the_tips_preserve_evidence_of_the_first_divergence(self):
        self.assertEqual(self.left_final["changes"][-1]["body"]["policy"], self.right_final["changes"][-1]["body"]["policy"])
        verdict, evidence = self.compare(self.left_final, self.right_final, self.left_final_pin, self.right_final_pin)
        self.assertEqual((verdict["relationship"], verdict["shared_revision"], verdict["divergent_revision"]),
                         ("diverged", 2, 3))
        self.assertEqual(verdict["left_latest_revision"], 4)
        self.assertEqual(evidence, self.evidence())
        self.assertEqual(len(evidence["shared_history"]["changes"]), 1)
        checked = verify_policy_divergence(evidence, self.root)
        self.assertTrue(checked["policy_divergence_verified"])
        self.assertEqual(checked["evidence_sha256"], verdict["evidence_sha256"])
        self.assertEqual((checked["left_successor_sha256"], checked["right_successor_sha256"]),
                         (self.left_pin, self.right_pin))
        self.assertEqual(checked["shared_predecessor_approvers"], self.overlap)

    def test_full_comparison_requires_both_expected_endpoint_fingerprints(self):
        for left, right in ((self.common_pin, self.right_pin), (self.left_pin, self.common_pin)):
            with self.subTest(left=left, right=right), self.assertRaisesRegex(LabError, "expected latest revision"):
                self.compare(self.left, self.right, left, right)

    def test_evidence_requires_two_distinct_successors_of_the_shared_revision(self):
        evidence = self.evidence()
        duplicate = {**evidence, "right_change": evidence["left_change"]}
        with self.assertRaisesRegex(LabError, "two distinct successors"):
            verify_policy_divergence(duplicate, self.root)
        wrong_predecessor = deepcopy(evidence)
        wrong_predecessor["right_change"]["body"]["previous_revision_sha256"] = self.left_pin
        with self.assertRaisesRegex(LabError, "preceding revision"):
            verify_policy_divergence(wrong_predecessor, self.root)

    def test_evidence_verifies_initial_rule_and_both_signature_thresholds(self):
        evidence = self.evidence()
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            verify_policy_divergence(evidence, "0" * 64)
        changed = deepcopy(evidence)
        changed["right_change"]["approvals"] = []
        with self.assertRaisesRegex(LabError, "signature threshold"):
            verify_policy_divergence(changed, self.root)

    def test_cli_exports_only_divergent_histories_and_protects_both_inputs(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            left, right, evidence = (folder / name for name in ("left.json", "right.json.gz", "evidence.json.gz"))
            write_proof(left, self.left)
            write_proof(right, self.right)
            arguments = ["policy-history", "compare", str(left), str(right), "--initial-trust", self.root,
                         "--left-trust", self.left_pin, "--right-trust", self.right_pin]
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(main([*arguments, "--out", str(evidence)]), 0)
            result = json.loads(output.getvalue())
            with redirect_stdout(StringIO()) as checked:
                self.assertEqual(main(["policy-history", "verify-divergence", str(evidence),
                                       "--initial-trust", self.root]), 0)
            self.assertEqual(json.loads(checked.getvalue())["evidence_sha256"], result["evidence_sha256"])
            with redirect_stderr(StringIO()) as error:
                self.assertEqual(main([*arguments, "--out", str(right)]), 2)
            self.assertIn("separate from the input files", error.getvalue())
            self.assertEqual(read_proof(right), self.right)
            write_proof(right, self.left)
            absent = folder / "absent.json"
            with redirect_stderr(StringIO()) as error:
                self.assertEqual(main([*arguments[:-1], self.left_pin, "--out", str(absent)]), 2)
            self.assertIn("Export requires divergence", error.getvalue())
            self.assertFalse(absent.exists())

    def test_loopback_import_uses_the_same_verifier_for_both_transports(self):
        evidence = self.evidence()
        expected = verify_policy_divergence(evidence, self.root)
        with TemporaryDirectory() as directory, ThreadingHTTPServer(
                ("127.0.0.1", 0), _handler(Lab.workbench(directory, "consortium", seed=True))) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            address = f"http://127.0.0.1:{server.server_port}"
            try:
                for mime, payload in (("application/json", canonical(evidence)), ("application/gzip", gzip_proof(evidence))):
                    request = Request(address + "/api/verify-policy-divergence", payload,
                                      {"Content-Type": mime, "Origin": address, "X-EduCredit-Initial-Policy": self.root})
                    with urlopen(request, timeout=5) as response:
                        self.assertEqual(json.load(response), expected)
                request = Request(address + "/api/verify-policy-divergence", gzip_proof(evidence),
                                  {"Content-Type": "application/gzip", "X-EduCredit-Initial-Policy": "0" * 64})
                with self.assertRaises(HTTPError) as failed:
                    urlopen(request, timeout=5)
                with failed.exception as response:
                    self.assertEqual(response.status, 400)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
