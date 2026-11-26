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
from educreditlab.policy_resolution import bundle_policy_resolution, make_resolution_authority, sign_policy_resolution
from educreditlab.resolution_history import (append_resolution_publication, init_resolution_history,
                                             sign_resolution_publication, verify_published_resolution,
                                             verify_resolution_history)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.server import _handler
from educreditlab.transport import gzip_proof, read_proof, write_proof


class ResolutionHistoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        case = cls.results / "policy-divergence"
        pins = read_json(case / "long/pins.json")
        cls.evidence = read_proof(case / "divergence.json.gz")
        cls.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        cls.profile = make_resolution_authority(pins["initial_policy_sha256"],
                                                [reviewer_fingerprint(public_key(key)) for key in cls.keys], 2)
        cls.authority = digest(cls.profile)
        cls.empty, cls.genesis = init_resolution_history(cls.profile, cls.evidence, cls.authority)

        def resolution(branch):
            history = read_proof(case / f"long/{branch}.json.gz")
            pin = pins[f"{branch}_latest_revision_sha256"]
            signatures = [sign_policy_resolution(cls.profile, cls.evidence, history, key, cls.authority, pin)
                          for key in cls.keys[:2]]
            packet = bundle_policy_resolution(cls.profile, cls.evidence, history, signatures, cls.authority, pin)
            return packet, digest(packet["decision"])

        cls.first, cls.first_pin = resolution("left")
        cls.second, cls.second_pin = resolution("right")

        def advance(history, pin, packet, decision):
            approvals = [sign_resolution_publication(history, packet, key, cls.authority, pin, decision)
                         for key in cls.keys[:2]]
            return append_resolution_publication(history, packet, approvals, cls.authority, pin, decision)

        cls.once, cls.first_tip = advance(cls.empty, cls.genesis, cls.first, cls.first_pin)
        cls.twice, cls.second_tip = advance(cls.once, cls.first_tip, cls.second, cls.second_pin)
        cls.thrice, cls.third_tip = advance(cls.twice, cls.second_tip, cls.first, cls.first_pin)

    def test_empty_history_has_a_verified_genesis_and_no_decision(self):
        result = verify_resolution_history(self.empty, self.authority, self.genesis)
        self.assertEqual(result["publication_count"], 0)
        self.assertIsNone(result["current_decision_sha256"])
        with self.assertRaisesRegex(LabError, "no published decision"):
            verify_published_resolution(self.empty, self.first, self.authority, self.genesis)

    def test_reinstatement_has_a_new_publication_fingerprint(self):
        status = verify_resolution_history(self.thrice, self.authority, self.third_tip)
        self.assertTrue(status["resolution_history_verified"])
        self.assertEqual(status["publication_count"], 3)
        first = verify_published_resolution(self.thrice, self.first, self.authority, self.third_tip, number=1)
        latest = verify_published_resolution(self.thrice, self.first, self.authority, self.third_tip)
        self.assertEqual(first["decision_sha256"], latest["decision_sha256"])
        self.assertEqual(latest["current_decision_sha256"], self.first_pin)
        self.assertEqual((first["verified_publication"], latest["verified_publication"]), (1, 3))
        self.assertNotEqual(first["verified_publication_sha256"], latest["verified_publication_sha256"])

    def test_latest_fingerprint_rejects_stale_or_unexpected_histories(self):
        for history, tip in ((self.twice, self.third_tip), (self.thrice, self.second_tip)):
            with self.subTest(tip=tip), self.assertRaisesRegex(LabError, "independently expected latest publication"):
                verify_resolution_history(history, self.authority, tip)
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            verify_resolution_history(self.thrice, "0" * 64, self.third_tip)

    def test_old_approvals_and_resolution_signatures_do_not_approve_a_new_entry(self):
        with self.assertRaisesRegex(LabError, "Invalid review-policy-resolution-publication signature"):
            append_resolution_publication(self.twice, self.first, self.once["publications"][0]["approvals"],
                                          self.authority, self.second_tip, self.first_pin)
        with self.assertRaisesRegex(LabError, "Invalid review-policy-resolution-publication signature"):
            append_resolution_publication(self.empty, self.first, self.first["approvals"],
                                          self.authority, self.genesis, self.first_pin)

    def test_publications_require_distinct_authorized_signatures(self):
        approval = self.once["publications"][0]["approvals"][0]
        for approvals, reason in (([approval], "signature threshold"), ([approval, approval], "distinct keys")):
            with self.subTest(approvals=approvals), self.assertRaisesRegex(LabError, reason):
                append_resolution_publication(self.empty, self.first, approvals, self.authority,
                                              self.genesis, self.first_pin)
        with self.assertRaisesRegex(LabError, "outside the trusted resolution authority"):
            sign_resolution_publication(self.empty, self.first, Ed25519PrivateKey.generate(),
                                        self.authority, self.genesis, self.first_pin)

    def test_number_and_predecessor_are_verified_even_when_a_decision_repeats(self):
        for field, value, message in (("number", 4, "publication number"),
                                      ("previous_publication_sha256", self.first_tip, "preceding entry"),
                                      ("decision_sha256", self.second_pin, "Invalid review-policy-resolution-publication")):
            changed = deepcopy(self.thrice)
            changed["publications"][-1]["body"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(LabError, message):
                verify_resolution_history(changed, self.authority, self.third_tip)

    def test_candidate_must_fit_the_expected_decision_and_divergence(self):
        with self.assertRaisesRegex(LabError, "independently expected decision"):
            sign_resolution_publication(self.empty, self.first, self.keys[0], self.authority,
                                        self.genesis, self.second_pin)
        other_evidence = dict(self.evidence, left_change=self.evidence["right_change"],
                              right_change=self.evidence["left_change"])
        branch, pin = self.first["selected_history"], self.first["decision"]["selected_revision_sha256"]
        approvals = [sign_policy_resolution(self.profile, other_evidence, branch, key, self.authority, pin)
                     for key in self.keys[:2]]
        other = bundle_policy_resolution(self.profile, other_evidence, branch, approvals, self.authority, pin)
        with self.assertRaisesRegex(LabError, "different divergence"):
            sign_resolution_publication(self.empty, other, self.keys[0], self.authority,
                                        self.genesis, digest(other["decision"]))

    def test_current_and_historical_reviews_follow_the_authenticated_publication(self):
        left, right = (read_proof(self.results / f"policy-divergence/long/{side}-quorum.json.gz")
                       for side in ("left", "right"))
        checked = verify_published_resolution(self.twice, self.second, self.authority, self.second_tip, bundle=right)
        self.assertTrue(checked["revision_binding_verified"])
        self.assertEqual(checked["verified_publication"], 2)
        pins = read_json(self.results / "revision-bound-review/128/pins.json")
        reviewed = verify_published_resolution(self.twice, self.first, self.authority, self.second_tip, number=1,
                                              bundle=left, proof=read_proof(self.results / "review-plan/review-128.json.gz"),
                                              trusted_manifest=pins["manifest_sha256"],
                                              trusted_checkpoint=pins["checkpoint_sha256"])
        self.assertEqual((reviewed["verified_publication"], reviewed["publication_count"]), (1, 2))
        self.assertTrue(reviewed["proof_rechecked"])
        self.assertEqual(reviewed["result_sha256"], pins["result_sha256"])
        with self.assertRaisesRegex(LabError, "independently expected decision"):
            verify_published_resolution(self.twice, self.first, self.authority, self.second_tip)
        with self.assertRaisesRegex(LabError, "selected reviewer policy revision"):
            verify_published_resolution(self.twice, self.second, self.authority, self.second_tip, bundle=left)

    def test_cli_init_sign_append_and_verify_and_reject_null_review(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            profile, evidence = folder / "authority.json", folder / "exhibit.json.gz"
            history, packet, latest = (folder / name for name in
                                        ("initial.json.gz", "resolution.json.gz", "history.json.gz"))
            write_proof(profile, self.profile)
            write_proof(evidence, self.evidence)
            write_proof(packet, self.first)

            def cli(*args):
                with redirect_stdout(StringIO()) as output:
                    self.assertEqual(main(["resolution-history", *map(str, args)]), 0)
                return json.loads(output.getvalue())

            trust = ("--authority-trust", self.authority)
            result = cli("init", profile, evidence, *trust, "--out", history)
            self.assertEqual(result["latest_publication_sha256"], self.genesis)
            inputs = [history, packet]
            flags = [*trust, "--publication-trust", self.genesis, "--decision-trust", self.first_pin]
            approvals = []
            for i, key in enumerate(self.keys[:2]):
                secret, approval = folder / f"key-{i}.pem", folder / f"approval-{i}.json"
                save_private_key(secret, key, b"fixture-passphrase")
                with TextIOWrapper(BytesIO(b"fixture-passphrase\n")) as stream, patch("sys.stdin", stream):
                    cli("sign", *inputs, *flags, "--key", secret, "--passphrase-stdin", "--out", approval)
                approvals.append(approval)
            result = cli("append", *inputs, *approvals, *flags, "--out", latest)
            self.assertEqual(result["latest_publication_sha256"], self.first_tip)
            latest_flags = [*trust, "--publication-trust", self.first_tip]
            self.assertEqual(cli("verify", latest, *latest_flags)["current_decision_sha256"], self.first_pin)
            self.assertEqual(cli("review", latest, packet, *latest_flags)["verified_publication"], 1)
            null = folder / "null.json"
            null.write_text("null", encoding="utf-8")
            with redirect_stderr(StringIO()) as failed:
                self.assertEqual(main(["resolution-history", "review", str(latest), str(packet), *latest_flags,
                                       "--review", str(null)]), 2)
            self.assertIn("Expected a joint confirmation", failed.getvalue())

    def test_loopback_accepts_both_encodings_and_refuses_a_stale_history(self):
        with TemporaryDirectory() as directory, ThreadingHTTPServer(
                ("127.0.0.1", 0), _handler(Lab.workbench(directory, "consortium", seed=True))) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            address = f"http://127.0.0.1:{server.server_port}"
            url = address + "/api/verify-resolution-history"
            headers = {"Origin": address, "X-EduCredit-Authority": self.authority,
                       "X-EduCredit-Publication": self.third_tip}
            try:
                for media, data in (("application/json", canonical(self.thrice)),
                                    ("application/gzip", gzip_proof(self.thrice))):
                    with urlopen(Request(url, data, {**headers, "Content-Type": media}), timeout=5) as response:
                        self.assertEqual(json.load(response)["current_decision_sha256"], self.first_pin)
                with self.assertRaises(HTTPError) as failed:
                    urlopen(Request(url, gzip_proof(self.twice), {**headers, "Content-Type": "application/gzip"}),
                            timeout=5)
                with failed.exception as response:
                    self.assertEqual(response.status, 400)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
