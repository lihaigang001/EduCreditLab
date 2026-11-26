from contextlib import redirect_stdout
from copy import deepcopy
from http.server import ThreadingHTTPServer
from io import BytesIO, StringIO, TextIOWrapper
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from unittest.mock import patch
from urllib.request import Request, urlopen
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from educreditlab.cli import main
from educreditlab.keys import public_key, save_private_key
from educreditlab.lab import Lab
from educreditlab.model import LabError, canonical, digest, read_json
from educreditlab.policy_resolution import bundle_policy_resolution, make_resolution_authority, sign_policy_resolution
from educreditlab.resolution_history import (append_resolution_handover, append_resolution_publication,
                                             init_resolution_history, sign_resolution_handover,
                                             sign_resolution_publication, verify_published_resolution,
                                             verify_resolution_history)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.server import _handler
from educreditlab.transport import gzip_proof, read_proof, write_proof


class ResolutionHandoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        case = cls.results / "policy-divergence"
        pins = read_json(case / "long/pins.json")
        evidence = read_proof(case / "divergence.json.gz")
        cls.old_keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        cls.new_keys = [Ed25519PrivateKey.generate() for _ in range(3)]

        def authority(keys, threshold):
            return make_resolution_authority(pins["initial_policy_sha256"],
                                             [reviewer_fingerprint(public_key(key)) for key in keys], threshold)

        cls.initial = authority(cls.old_keys, 2)
        cls.successor = authority(cls.new_keys, 3)
        cls.initial_pin, cls.successor_pin = digest(cls.initial), digest(cls.successor)

        def resolution(side, profile, keys):
            history = read_proof(case / f"long/{side}.json.gz")
            revision, pin = pins[f"{side}_latest_revision_sha256"], digest(profile)
            approvals = [sign_policy_resolution(profile, evidence, history, key, pin, revision) for key in keys]
            packet = bundle_policy_resolution(profile, evidence, history, approvals, pin, revision)
            return packet, digest(packet["decision"])

        cls.old, cls.old_decision = resolution("left", cls.initial, cls.old_keys[:2])
        cls.new, cls.new_decision = resolution("right", cls.successor, cls.new_keys)
        empty, root = init_resolution_history(cls.initial, evidence, cls.initial_pin)
        approvals = [sign_resolution_publication(empty, cls.old, key, cls.initial_pin, root, cls.old_decision)
                     for key in cls.old_keys[:2]]
        cls.prior, cls.prior_pin = append_resolution_publication(empty, cls.old, approvals,
                                                                 cls.initial_pin, root, cls.old_decision)
        cls.approvals = {
            role: [sign_resolution_handover(cls.prior, cls.new, cls.successor, key, cls.initial_pin,
                                            cls.prior_pin, cls.new_decision, trusted_successor=cls.successor_pin, role=role)
                   for key in keys]
            for role, keys in (("outgoing", cls.old_keys[:2]), ("incoming", cls.new_keys))
        }
        cls.rotated, cls.rotated_tip = append_resolution_handover(
            cls.prior, cls.new, cls.successor, cls.approvals, cls.initial_pin, cls.prior_pin, cls.new_decision,
            trusted_successor=cls.successor_pin)
        approvals = [sign_resolution_publication(cls.rotated, cls.new, key, cls.initial_pin,
                                                  cls.rotated_tip, cls.new_decision) for key in cls.new_keys]
        cls.final, cls.final_tip = append_resolution_publication(cls.rotated, cls.new, approvals,
                                                                 cls.initial_pin, cls.rotated_tip, cls.new_decision)

    def append_handover(self, approvals):
        return append_resolution_handover(self.prior, self.new, self.successor, approvals, self.initial_pin,
                                          self.prior_pin, self.new_decision, trusted_successor=self.successor_pin)

    def test_handover_preserves_existing_entries_and_the_initial_anchor(self):
        prior = verify_resolution_history(self.prior, self.initial_pin, self.prior_pin)
        later = verify_resolution_history(self.final, self.initial_pin, self.final_tip)
        self.assertEqual((self.prior["schema"], self.final["schema"]), (1, 2))
        self.assertEqual(self.final["publications"][:1], self.prior["publications"])
        self.assertEqual(prior["history_sha256"], later["history_sha256"])
        self.assertNotIn("active_authority_sha256", prior)
        self.assertEqual(later["authority_sha256"], self.initial_pin)
        self.assertEqual(later["active_authority_sha256"], self.successor_pin)
        self.assertEqual((later["authority_handover_count"], later["publication_count"]), (1, 3))

    def test_each_authority_threshold_is_required_independently(self):
        for role in ("outgoing", "incoming"):
            insufficient = {**self.approvals, role: self.approvals[role][:-1]}
            with self.subTest(role=role), self.assertRaisesRegex(
                    LabError, f"{role.capitalize()} authority approval failed.*signature threshold"):
                self.append_handover(insufficient)

    def test_role_and_predecessor_are_signed(self):
        swapped = {"outgoing": self.approvals["incoming"][:2], "incoming": self.approvals["outgoing"]}
        with self.assertRaisesRegex(LabError, "Outgoing authority approval failed"):
            self.append_handover(swapped)
        damaged = deepcopy(self.rotated)
        damaged["publications"][-1]["body"]["previous_publication_sha256"] = "0" * 64
        with self.assertRaisesRegex(LabError, "preceding entry"):
            verify_resolution_history(damaged, self.initial_pin, self.rotated_tip)

    def test_successor_profile_and_its_scope_must_be_expected(self):
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            sign_resolution_handover(self.prior, self.new, self.successor, self.old_keys[0], self.initial_pin,
                                     self.prior_pin, self.new_decision, trusted_successor="0" * 64, role="outgoing")
        wrong_scope = {**self.successor, "initial_policy_sha256": "0" * 64}
        with self.assertRaisesRegex(LabError, "retain the initial reviewer policy"):
            sign_resolution_handover(self.prior, self.new, wrong_scope, self.old_keys[0], self.initial_pin,
                                     self.prior_pin, self.new_decision, trusted_successor=digest(wrong_scope),
                                     role="outgoing")

    def test_rotated_history_rejects_stale_head_and_initial_pin_replacement(self):
        with self.assertRaisesRegex(LabError, "independently expected latest publication"):
            verify_resolution_history(self.prior, self.initial_pin, self.final_tip)
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            verify_resolution_history(self.final, self.successor_pin, self.final_tip)
        with self.assertRaisesRegex(LabError, "resolution publication body"):
            verify_resolution_history({**self.rotated, "schema": 1}, self.initial_pin, self.rotated_tip)

    def test_retired_key_and_old_packet_cannot_sign_the_next_publication(self):
        with self.assertRaisesRegex(LabError, "outside the trusted resolution authority"):
            sign_resolution_publication(self.final, self.new, self.old_keys[0], self.initial_pin,
                                        self.final_tip, self.new_decision)
        with self.assertRaisesRegex(LabError, "independently trusted fingerprint"):
            sign_resolution_publication(self.final, self.old, self.new_keys[0], self.initial_pin,
                                        self.final_tip, self.old_decision)

    def test_historical_and_current_reviews_use_their_respective_authorities(self):
        pins = read_json(self.results / "revision-bound-review/128/pins.json")
        proof = read_proof(self.results / "review-plan/review-128.json.gz")
        left, right = (read_proof(self.results / f"policy-divergence/long/{side}-quorum.json.gz")
                       for side in ("left", "right"))
        historic = verify_published_resolution(self.final, self.old, self.initial_pin, self.final_tip, number=1,
                                               bundle=left, proof=proof, trusted_manifest=pins["manifest_sha256"],
                                               trusted_checkpoint=pins["checkpoint_sha256"])
        current = verify_published_resolution(self.final, self.new, self.initial_pin, self.final_tip, bundle=right)
        self.assertTrue(historic["proof_rechecked"] and current["revision_binding_verified"])
        self.assertEqual((historic["verified_authority_sha256"], current["verified_authority_sha256"]),
                         (self.initial_pin, self.successor_pin))
        self.assertEqual(historic["active_authority_sha256"], self.successor_pin)
        self.assertEqual((historic["verified_publication"], current["verified_publication"]), (1, 3))
        self.assertEqual(historic["result_sha256"], current["result_sha256"])
        with self.assertRaisesRegex(LabError, "selected reviewer policy revision"):
            verify_published_resolution(self.final, self.new, self.initial_pin, self.final_tip, bundle=left)

    def test_second_handover_uses_the_current_outgoing_roster(self):
        approvals = {
            role: [sign_resolution_handover(self.final, self.old, self.initial, key, self.initial_pin,
                                            self.final_tip, self.old_decision, trusted_successor=self.initial_pin, role=role)
                   for key in keys]
            for role, keys in (("outgoing", self.new_keys), ("incoming", self.old_keys[:2]))
        }
        next_history, tip = append_resolution_handover(self.final, self.old, self.initial, approvals,
                                                        self.initial_pin, self.final_tip, self.old_decision,
                                                        trusted_successor=self.initial_pin)
        state = verify_published_resolution(next_history, self.old, self.initial_pin, tip)
        self.assertEqual((state["authority_handover_count"], state["verified_publication"]), (2, 4))
        self.assertEqual(state["verified_authority_sha256"], self.initial_pin)

    def test_cli_signs_both_roles_and_appends_the_same_handover(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            history, packet, profile, output = (root / n for n in ("prior.json.gz", "next.json.gz", "authority.json",
                                                                  "advanced.json.gz"))
            for name, data in ((history, self.prior), (packet, self.new), (profile, self.successor)):
                write_proof(name, data)
            pins = ["--authority-trust", self.initial_pin, "--publication-trust", self.prior_pin,
                    "--decision-trust", self.new_decision, "--successor-trust", self.successor_pin]
            source = [str(history), str(packet), str(profile), *pins]
            approvals = []
            for role, keys in (("outgoing", self.old_keys[:2]), ("incoming", self.new_keys)):
                approvals.append(f"--{role}")
                for i, key in enumerate(keys):
                    secret, approval = (root / f"{role}-{i}.pem", root / f"{role}-{i}.json")
                    save_private_key(secret, key, b"fixture-passphrase")
                    with TextIOWrapper(BytesIO(b"fixture-passphrase\n")) as stream, patch("sys.stdin", stream):
                        with redirect_stdout(StringIO()):
                            self.assertEqual(main(["resolution-history", "handover-sign", *source, "--role", role,
                                                   "--key", str(secret), "--passphrase-stdin", "--out", str(approval)]), 0)
                    approvals.append(str(approval))
            with redirect_stdout(StringIO()) as response:
                self.assertEqual(main(["resolution-history", "handover-append", *source, *approvals,
                                       "--out", str(output)]), 0)
            self.assertEqual(json.loads(response.getvalue())["latest_publication_sha256"], self.rotated_tip)
            self.assertEqual(read_proof(output), self.rotated)

    def test_workbench_reports_the_verified_successor_for_both_encodings(self):
        with TemporaryDirectory() as directory, ThreadingHTTPServer(
                ("127.0.0.1", 0), _handler(Lab.workbench(directory, "consortium", seed=True))) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            address = f"http://127.0.0.1:{server.server_port}"
            headers = {"Origin": address, "X-EduCredit-Authority": self.initial_pin,
                       "X-EduCredit-Publication": self.final_tip}
            try:
                for media, body in (("application/json", canonical(self.final)),
                                    ("application/gzip", gzip_proof(self.final))):
                    request = Request(address + "/api/verify-resolution-history", body,
                                      {**headers, "Content-Type": media})
                    with urlopen(request, timeout=5) as response:
                        self.assertEqual(json.load(response)["active_authority_sha256"], self.successor_pin)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
