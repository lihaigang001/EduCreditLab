from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from http.server import ThreadingHTTPServer
from io import BytesIO, StringIO, TextIOWrapper
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from educreditlab.cli import main
from educreditlab.keys import public_key, save_private_key
from educreditlab.lab import Lab
from educreditlab.model import LabError, canonical, digest, read_json
from educreditlab.policy_history import (append_policy_change, approve_policy_change, attest_review_at_revision,
                                        bundle_review_at_revision, init_policy_history, verify_review_at_revision)
from educreditlab.review_attestation import attest_review, reviewer_fingerprint, verify_attestation
from educreditlab.review_quorum import bundle_quorum, make_quorum_policy, verify_quorum
from educreditlab.server import _handler
from educreditlab.transport import gzip_proof, read_proof, write_proof


class RevisionReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = Path(__file__).resolve().parents[1] / "results/review-plan/demo"
        cls.proof_path = data / "review.json.gz"
        cls.proof = read_proof(cls.proof_path)
        pins = read_json(data / "pins.json")
        cls.manifest, cls.checkpoint, cls.plan = (pins[name] for name in
                                                ("manifest_sha256", "checkpoint_sha256", "review_plan_sha256"))
        cls.keys = [Ed25519PrivateKey.generate() for _ in range(5)]
        roster = [reviewer_fingerprint(public_key(key)) for key in cls.keys]
        cls.policy = make_quorum_policy(cls.plan, roster[:4], 3)
        reduced = make_quorum_policy(cls.plan, roster[1:], 2)
        cls.root = digest(cls.policy)
        cls.before = init_policy_history(cls.policy, cls.root)

        def advance(history, pin, successor, indices):
            approvals = [approve_policy_change(history, successor, cls.keys[i], cls.root, pin) for i in indices]
            return append_policy_change(history, successor, approvals, cls.root, pin)

        cls.intermediate, cls.middle_pin = advance(cls.before, cls.root, reduced, (0, 1, 2, 4))
        cls.history, cls.latest = advance(cls.intermediate, cls.middle_pin, cls.policy, (0, 1, 2))
        cls.earlier, cls.current = [[
            attest_review_at_revision(history, cls.proof, key, cls.root, pin,
                                      trusted_manifest=cls.manifest, trusted_checkpoint=cls.checkpoint)
            for key in cls.keys[:3]
        ] for history, pin in ((cls.before, cls.root), (cls.history, cls.latest))]
        cls.old_packet = bundle_review_at_revision(cls.history, cls.earlier, cls.root, cls.latest, revision=1)
        cls.new_packet = bundle_review_at_revision(cls.history, cls.current, cls.root, cls.latest)
        legacy = [attest_review(cls.proof, key, cls.manifest, cls.checkpoint, cls.plan) for key in cls.keys[:3]]
        cls.legacy_packet = bundle_quorum(cls.policy, legacy, cls.root)

    def verify(self, bundle, **kwargs):
        return verify_review_at_revision(self.history, bundle, self.root, self.latest, **kwargs)

    def test_earlier_and_current_attestations_apply_to_their_signed_revisions(self):
        earlier = self.verify(self.old_packet, revision=1, require_revision_binding=True)
        current = self.verify(self.new_packet, require_revision_binding=True)
        self.assertTrue(earlier["revision_binding_verified"] and current["revision_binding_verified"])
        self.assertEqual((earlier["policy_revision"], current["policy_revision"]), (1, 3))
        self.assertEqual(earlier["policy_sha256"], current["policy_sha256"])
        self.assertEqual(earlier["result_sha256"], current["result_sha256"])
        self.assertNotEqual(earlier["policy_revision_sha256"], current["policy_revision_sha256"])

    def test_restoring_identical_policy_requires_new_signatures_for_the_new_revision(self):
        self.assertEqual(self.old_packet["policy"], self.new_packet["policy"])
        for packet, revision in ((self.old_packet, None), (self.new_packet, 1)):
            with self.subTest(revision=revision), self.assertRaisesRegex(LabError, "selected reviewer policy revision"):
                self.verify(packet, revision=revision)

    def test_different_revisions_cannot_satisfy_one_joint_signature_threshold(self):
        mixed = [self.earlier[0], *self.current[1:]]
        with self.assertRaisesRegex(LabError, "selected reviewer policy revision"):
            bundle_review_at_revision(self.history, mixed, self.root, self.latest)

    def test_policy_revision_digest_is_covered_by_the_signature(self):
        changed = deepcopy(self.old_packet)
        changed["attestations"][0]["body"]["policy_revision_sha256"] = self.latest
        with self.assertRaisesRegex(LabError, "Invalid review-attestation-revision signature"):
            self.verify(changed)

    def test_legacy_confirmation_remains_readable_with_an_explicit_binding_verdict(self):
        self.assertFalse(self.verify(self.legacy_packet, revision=1)["revision_binding_verified"])
        self.assertFalse(self.verify(self.legacy_packet)["revision_binding_verified"])
        self.assertTrue(verify_quorum(self.legacy_packet, self.root)["quorum_verified"])
        with self.assertRaisesRegex(LabError, "requires signatures that bind"):
            self.verify(self.legacy_packet, require_revision_binding=True)
        with self.assertRaisesRegex(LabError, "joint review attestation schema"):
            verify_quorum(self.new_packet, self.root)
        with self.assertRaisesRegex(LabError, "signed review summary"):
            verify_attestation(self.current[0], reviewer_fingerprint(public_key(self.keys[0])), self.plan)

    def test_issuance_validates_the_current_roster_and_expected_history_endpoint(self):
        for history, pin, reason in (
                (self.intermediate, self.middle_pin, "outside the current reviewer roster"),
                (self.before, self.latest, "expected latest revision")):
            with self.subTest(reason=reason), self.assertRaisesRegex(LabError, reason):
                attest_review_at_revision(history, self.proof, self.keys[0], self.root, pin,
                                          trusted_manifest=self.manifest, trusted_checkpoint=self.checkpoint)

    def test_bound_confirmation_rechecks_the_original_evidence(self):
        result = self.verify(self.new_packet, require_revision_binding=True, proof=self.proof,
                             trusted_manifest=self.manifest, trusted_checkpoint=self.checkpoint)
        self.assertTrue(result["proof_rechecked"] and result["revision_binding_verified"])
        self.assertEqual((result["replay_count"], result["anchor_count"]), (2, 1))
        with self.assertRaisesRegex(LabError, "Independent manifest and checkpoint"):
            self.verify(self.new_packet, proof=self.proof)

    def test_cli_issuance_collection_and_strict_review(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            history = folder / "history.json.gz"
            joint = folder / "joint.json.gz"
            write_proof(history, self.history)
            trust = ["--initial-trust", self.root, "--revision-trust", self.latest]
            statements = []
            for i, key in enumerate(self.keys[:3]):
                secret, statement = (folder / f"{i}.pem", folder / f"{i}.json.gz")
                save_private_key(secret, key, b"fixture-passphrase")
                args = ["policy-history", "attest", str(history), str(self.proof_path), *trust,
                        "--trust", self.manifest, "--checkpoint-trust", self.checkpoint,
                        "--key", str(secret), "--passphrase-stdin", "--out", str(statement)]
                with TextIOWrapper(BytesIO(b"fixture-passphrase\n")) as stream, patch("sys.stdin", stream):
                    with redirect_stdout(StringIO()):
                        self.assertEqual(main(args), 0)
                statements.append(str(statement))
            with redirect_stdout(StringIO()):
                self.assertEqual(main(["policy-history", "bundle", str(history), *statements, *trust,
                                       "--out", str(joint)]), 0)
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(main(["policy-history", "review", str(history), str(joint), *trust,
                                       "--require-revision-binding"]), 0)
            self.assertTrue(json.loads(output.getvalue())["revision_binding_verified"])
            with redirect_stderr(StringIO()) as error:
                self.assertEqual(main(["policy-history", "review", str(history), str(joint), *trust, "--revision", "1"]), 2)
            self.assertIn("selected reviewer policy revision", error.getvalue())

    def test_loopback_multipart_upload_enforces_the_signed_revision(self):
        with TemporaryDirectory() as workspace, ThreadingHTTPServer(
                ("127.0.0.1", 0), _handler(Lab.workbench(workspace, "consortium", seed=True))) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            address = f"http://127.0.0.1:{server.server_port}"

            def upload(packet, revision=None, *, name="bundle"):
                boundary = "EduCreditLab-test-uploads"
                data = b""
                for part, contents in (("history", gzip_proof(self.history)), (name, canonical(packet))):
                    header = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{part}\"; "
                              "filename=\"file\"\r\nContent-Type: application/octet-stream\r\n\r\n")
                    data += header.encode("ascii") + contents + b"\r\n"
                data += f"--{boundary}--\r\n".encode("ascii")
                headers = {"Content-Type": f"multipart/form-data; boundary={boundary}",
                           "Origin": address, "X-EduCredit-Initial-Policy": self.root,
                           "X-EduCredit-Revision": self.latest}
                if revision is not None:
                    headers["X-EduCredit-Review-Revision"] = revision
                req = Request(address + "/api/verify-revision-review", data, headers)
                try:
                    response = urlopen(req, timeout=5)
                except HTTPError as exc:
                    response = exc
                with response:
                    return response.status, json.load(response)

            try:
                status, result = upload(self.old_packet, "1")
                self.assertEqual(status, 200)
                self.assertTrue(result["revision_binding_verified"])
                self.assertEqual(upload(self.new_packet)[1]["policy_revision"], 3)
                self.assertEqual(upload(self.old_packet)[0], 400)
                self.assertEqual(upload(self.legacy_packet, "1")[0], 400)
                self.assertEqual(upload(self.old_packet, "0")[0], 400)
                self.assertEqual(upload(self.new_packet, name="history")[0], 400)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
