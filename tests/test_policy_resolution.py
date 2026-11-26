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
from educreditlab.policy_divergence import compare_policy_histories
from educreditlab.policy_history import append_policy_change, approve_policy_change, init_policy_history
from educreditlab.policy_resolution import (bundle_policy_resolution, make_resolution_authority,
                                             sign_policy_resolution, verify_policy_resolution, verify_resolved_review)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.review_quorum import make_quorum_policy
from educreditlab.server import _handler
from educreditlab.transport import gzip_proof, read_proof, write_proof


class PolicyResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        cls.case = cls.results / "policy-divergence"
        pins = read_json(cls.case / "long/pins.json")
        cls.root = pins["initial_policy_sha256"]
        cls.left_pin, cls.right_pin = (pins[name] for name in
                                     ("left_latest_revision_sha256", "right_latest_revision_sha256"))
        cls.left, cls.right = (read_proof(cls.case / "long" / name) for name in ("left.json.gz", "right.json.gz"))
        cls.evidence = read_proof(cls.case / "divergence.json.gz")
        cls.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        cls.roster = [reviewer_fingerprint(public_key(key)) for key in cls.keys]
        cls.authority = make_resolution_authority(cls.root, cls.roster, 2)
        cls.authority_pin = digest(cls.authority)
        cls.approvals, cls.alternate_approvals = [[
            sign_policy_resolution(cls.authority, cls.evidence, history, key, cls.authority_pin, tip)
            for key in cls.keys[:2]
        ] for history, tip in ((cls.left, cls.left_pin), (cls.right, cls.right_pin))]
        cls.packet, cls.alternate = [
            bundle_policy_resolution(cls.authority, cls.evidence, history, approvals, cls.authority_pin, tip)
            for history, approvals, tip in ((cls.left, cls.approvals, cls.left_pin),
                                            (cls.right, cls.alternate_approvals, cls.right_pin))
        ]
        cls.pin, cls.alternate_pin = (digest(item["decision"]) for item in (cls.packet, cls.alternate))

    def verify(self, packet, authority=None, decision=None):
        return verify_policy_resolution(packet, authority or self.authority_pin, decision or self.pin)

    def test_verified_resolution_names_the_exact_selected_endpoint(self):
        result = self.verify(self.packet)
        self.assertTrue(result["policy_resolution_verified"])
        self.assertEqual(result["decision_sha256"], self.pin)
        self.assertEqual(result["selected_revision"], 27)
        self.assertEqual(result["selected_revision_sha256"], self.left_pin)
        self.assertEqual((result["resolution_threshold"], result["resolution_signer_count"]), (2, 2))

    def test_independent_pins_prevent_substituting_another_signed_decision(self):
        self.assertEqual(self.verify(self.alternate, decision=self.alternate_pin)["selected_revision_sha256"], self.right_pin)
        with self.assertRaisesRegex(LabError, "independently expected decision"):
            self.verify(self.alternate)
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            self.verify(self.packet, authority="0" * 64)

    def test_distinct_authorized_keys_must_sign_the_same_decision(self):
        for approvals, error in (
                (self.approvals[:1], "signature threshold"),
                (self.approvals[:1] * 2, "distinct keys"),
                ([self.approvals[0], self.alternate_approvals[1]], "Invalid review-policy-resolution signature")):
            with self.subTest(error=error), self.assertRaisesRegex(LabError, error):
                bundle_policy_resolution(self.authority, self.evidence, self.left, approvals,
                                         self.authority_pin, self.left_pin)
        with self.assertRaisesRegex(LabError, "outside the trusted resolution authority"):
            sign_policy_resolution(self.authority, self.evidence, self.left, Ed25519PrivateKey.generate(),
                                   self.authority_pin, self.left_pin)

    def test_authority_roster_is_pinned_to_its_scope_and_threshold(self):
        with self.assertRaisesRegex(LabError, "distinct keys"):
            make_resolution_authority(self.root, [self.roster[0]] * 2, 2)
        with self.assertRaisesRegex(LabError, "resolution signature threshold"):
            make_resolution_authority(self.root, self.roster, 4)
        changed = deepcopy(self.packet)
        changed["authority"]["threshold"] = 1
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            self.verify(changed)

    def test_resolution_commits_to_the_evidence_and_full_selected_endpoint(self):
        reordered = deepcopy(self.packet)
        exhibit = reordered["divergence"]
        exhibit["left_change"], exhibit["right_change"] = exhibit["right_change"], exhibit["left_change"]
        with self.assertRaisesRegex(LabError, "does not match the verified evidence"):
            self.verify(reordered)
        for history in (read_proof(self.case / "short/left.json.gz"), self.right):
            with self.subTest(length=len(history["changes"])), self.assertRaisesRegex(LabError, "expected latest revision"):
                self.verify({**self.packet, "selected_history": history})
        truncated = {**self.left, "changes": self.left["changes"][:1]}
        pin = digest(truncated["changes"][0]["body"])
        with self.assertRaisesRegex(LabError, "ends before the demonstrated divergence"):
            sign_policy_resolution(self.authority, self.evidence, truncated, self.keys[0], self.authority_pin, pin)

    def test_a_valid_history_outside_the_demonstrated_successors_is_ineligible(self):
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        roster = [reviewer_fingerprint(public_key(key)) for key in keys]
        plan = "a" * 64
        initial = make_quorum_policy(plan, roster, 2)
        root = digest(initial)
        started = init_policy_history(initial, root)

        def branch(threshold):
            policy = make_quorum_policy(plan, roster, threshold)
            signatures = [approve_policy_change(started, policy, key, root, root) for key in keys]
            return append_policy_change(started, policy, signatures, root, root)

        left, left_pin = branch(1)
        right, right_pin = branch(2)
        third, third_pin = branch(3)
        _, evidence = compare_policy_histories(left, right, root, left_pin, right_pin)
        authority = make_resolution_authority(root, self.roster, 2)
        with self.assertRaisesRegex(LabError, "must descend from a demonstrated successor"):
            sign_policy_resolution(authority, evidence, third, self.keys[0], digest(authority), third_pin)

    def test_resolved_review_replays_the_selected_evidence_and_rejects_the_other_branch(self):
        folder = self.case / "long"
        selected = read_proof(folder / "left-quorum.json.gz")
        other = read_proof(folder / "right-quorum.json.gz")
        self.assertEqual(selected["policy"], other["policy"])
        proof = read_proof(self.results / "review-plan/review-128.json.gz")
        pins = read_json(self.results / "revision-bound-review/128/pins.json")
        result = verify_resolved_review(self.packet, selected, self.authority_pin, self.pin, proof=proof,
                                        trusted_manifest=pins["manifest_sha256"],
                                        trusted_checkpoint=pins["checkpoint_sha256"])
        self.assertTrue(result["revision_binding_verified"] and result["proof_rechecked"])
        self.assertEqual((result["replay_count"], result["anchor_count"]), (16, 112))
        self.assertEqual(result["result_sha256"], pins["result_sha256"])
        with self.assertRaisesRegex(LabError, "selected reviewer policy revision"):
            verify_resolved_review(self.packet, other, self.authority_pin, self.pin)

    def test_a_resolved_review_requires_revision_bound_signatures(self):
        bundle = read_proof(self.case / "long/left-quorum.json.gz")
        with self.assertRaisesRegex(LabError, "requires signatures that bind"):
            verify_resolved_review(self.packet, {**bundle, "schema": 1}, self.authority_pin, self.pin)

    def test_cli_creates_signs_collects_and_checks_a_resolution(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            profile, packet = folder / "profile.json", folder / "resolution.json.gz"
            roster_flags = [flag for key in self.roster for flag in ("--resolver-trust", key)]
            with redirect_stdout(StringIO()) as created:
                self.assertEqual(main(["policy-history", "resolution-authority", "--initial-trust", self.root,
                                       *roster_flags, "--threshold", "2", "--out", str(profile)]), 0)
            self.assertEqual(json.loads(created.getvalue())["authority_sha256"], self.authority_pin)
            options = ["--authority-trust", self.authority_pin, "--selected-trust", self.left_pin]
            inputs = [str(profile), str(self.case / "divergence.json.gz"), str(self.case / "long/left.json.gz")]
            approvals = []
            for index, key in enumerate(self.keys[:2]):
                key_path, approval = folder / f"key-{index}.pem", folder / f"approval-{index}.json"
                save_private_key(key_path, key, b"fixture-passphrase")
                with TextIOWrapper(BytesIO(b"fixture-passphrase\n")) as stream, patch("sys.stdin", stream):
                    with redirect_stdout(StringIO()):
                        self.assertEqual(main(["policy-history", "resolution-sign", *inputs, *options,
                                               "--key", str(key_path), "--passphrase-stdin", "--out", str(approval)]), 0)
                approvals.append(str(approval))
            with redirect_stdout(StringIO()) as bundled:
                self.assertEqual(main(["policy-history", "resolution-bundle", *inputs, *approvals, *options,
                                       "--out", str(packet)]), 0)
            pin = json.loads(bundled.getvalue())["decision_sha256"]
            self.assertEqual(pin, self.pin)
            check = ["policy-history", "verify-resolution", str(packet), "--authority-trust", self.authority_pin,
                     "--decision-trust", pin]
            with redirect_stdout(StringIO()) as verified:
                self.assertEqual(main(check), 0)
            self.assertEqual(json.loads(verified.getvalue()), self.verify(self.packet))
            with redirect_stderr(StringIO()) as failed:
                self.assertEqual(main([*check, "--proof", "unused.json"]), 2)
            self.assertIn("Use --review", failed.getvalue())

    def test_loopback_verifies_json_and_gzip_with_independent_pins(self):
        with TemporaryDirectory() as workspace, ThreadingHTTPServer(
                ("127.0.0.1", 0), _handler(Lab.workbench(workspace, "consortium", seed=True))) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            address = f"http://127.0.0.1:{server.server_port}"
            headers = {"Origin": address, "X-EduCredit-Authority": self.authority_pin, "X-EduCredit-Decision": self.pin}
            try:
                url = address + "/api/verify-policy-resolution"
                for media, body in (("application/json", canonical(self.packet)), ("application/gzip", gzip_proof(self.packet))):
                    request = Request(url, body, {**headers, "Content-Type": media})
                    with urlopen(request, timeout=5) as response:
                        self.assertEqual(json.load(response), self.verify(self.packet))
                refused = Request(url, gzip_proof(self.alternate), {**headers, "Content-Type": "application/gzip"})
                with self.assertRaises(HTTPError) as failed:
                    urlopen(refused, timeout=5)
                with failed.exception as response:
                    self.assertEqual(response.status, 400)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
