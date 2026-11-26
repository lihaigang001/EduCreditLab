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

from educreditlab.cli import main
from educreditlab.model import LabError, canonical, digest, read_json
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, verify_checkpoint_resolution,
                                               verify_resolution_witness)
from educreditlab.server import _handler
from educreditlab.transport import gzip_proof, read_proof


class ResolutionCheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = Path(__file__).resolve().parents[1] / "results"
        cls.source = cls.results / "resolution-handover"
        cls.short_history = read_proof(cls.source / "short/history.json.gz")
        cls.long_history = read_proof(cls.source / "long/history.json.gz")
        cls.short_pins = read_json(cls.source / "short/pins.json")
        cls.long_pins = read_json(cls.source / "long/pins.json")
        cls.old_packet = read_proof(cls.source / "outgoing-resolution.json.gz")
        cls.new_packet = read_proof(cls.source / "incoming-resolution.json.gz")
        cls.short = cls.audit(cls.short_history, cls.short_pins)
        cls.long = cls.audit(cls.long_history, cls.long_pins)

    @staticmethod
    def audit(history, pins):
        return audit_resolution_checkpoint(history, pins["initial_authority_sha256"], pins["latest_publication_sha256"])

    def test_legacy_singleton_checkpoint_has_an_empty_path(self):
        prior = self.audit(read_proof(self.source / "prior-history.json.gz"), read_json(self.source / "prior-pins.json"))
        witness = prior.witness()
        self.assertEqual(witness["siblings"], [])
        result = verify_checkpoint_resolution(witness, self.old_packet, prior.fingerprint)
        self.assertEqual(result["verified_publication"], 1)
        self.assertTrue(result["is_checkpoint_head"])
        self.assertTrue(result["policy_resolution_verified"])

    def test_audit_checks_anchor_head_and_both_handover_thresholds(self):
        for pin in ("initial_authority_sha256", "latest_publication_sha256"):
            with self.subTest(pin=pin), self.assertRaises(LabError):
                self.audit(self.long_history, {**self.long_pins, pin: "0" * 64})
        for role in ("outgoing", "incoming"):
            incomplete = deepcopy(self.short_history)
            incomplete["publications"][1]["approvals"][role].pop()
            with self.subTest(role=role), self.assertRaisesRegex(LabError, "authority approval failed"):
                self.audit(incomplete, self.short_pins)
        empty = {**self.short_history, "schema": 1, "publications": []}
        with self.assertRaisesRegex(LabError, "at least one published decision"):
            self.audit(empty, {**self.short_pins, "latest_publication_sha256": self.short.descriptor["history_sha256"]})

    def test_every_leaf_keeps_its_ordinal_and_effective_authority(self):
        self.assertEqual(self.long.fingerprint, digest(self.long.descriptor))
        for number, record in enumerate(self.long_history["publications"], 1):
            result = verify_resolution_witness(self.long.witness(number), self.long.fingerprint, number=number)
            self.assertEqual(result["verified_publication_sha256"], digest(record["body"]))
            self.assertEqual(result["verified_decision_sha256"], record["body"]["decision_sha256"])
            pin = "initial_authority_sha256" if number == 1 else "active_authority_sha256"
            self.assertEqual(result["verified_authority_sha256"], self.long_pins[pin])
            self.assertEqual(result["is_checkpoint_head"], number == 27)
        self.assertLess(len(self.short.witness()["siblings"]), len(self.short.witness(1)["siblings"]))

    def test_checkpoint_outputs_are_independent_copies(self):
        expected = self.long.fingerprint
        self.long.descriptor["publication_count"] = 4
        witness = self.long.witness()
        witness["checkpoint"]["merkle_root"] = "0" * 64
        witness["entry"]["number"] = 2
        self.assertEqual(self.long.fingerprint, expected)
        self.assertEqual(verify_resolution_witness(self.long.witness(), expected)["verified_publication"], 27)

    def test_selection_requires_an_explicit_ordinal_for_history(self):
        old = self.long.witness(1)
        with self.assertRaisesRegex(LabError, "selected publication number"):
            verify_resolution_witness(old, self.long.fingerprint)
        repeated = self.long.witness(3)
        self.assertEqual(repeated["entry"]["decision_sha256"], self.long.witness()["entry"]["decision_sha256"])
        with self.assertRaisesRegex(LabError, "selected publication number"):
            verify_resolution_witness(repeated, self.long.fingerprint)
        for number in (0, True, 28, "1"):
            with self.subTest(number=number), self.assertRaises(LabError):
                verify_resolution_witness(old, self.long.fingerprint, number=number)

    def test_checkpoint_trust_rejects_earlier_and_modified_descriptors(self):
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            verify_resolution_witness(self.short.witness(), self.long.fingerprint)
        modified = self.long.witness()
        modified["checkpoint"]["latest_publication_sha256"] = "0" * 64
        with self.assertRaisesRegex(LabError, "independently trusted publication checkpoint"):
            verify_resolution_witness(modified, self.long.fingerprint)
        with self.assertRaisesRegex(LabError, "does not match the checkpoint endpoint"):
            verify_resolution_witness(modified, digest(modified["checkpoint"]))

    def test_path_authenticates_entry_and_uses_exact_siblings(self):
        original = self.long.witness(1)
        for field in ("publication_sha256", "decision_sha256", "authority_sha256"):
            modified = deepcopy(original)
            modified["entry"][field] = "0" * 64
            with self.subTest(field=field), self.assertRaisesRegex(LabError, "Merkle path"):
                verify_resolution_witness(modified, self.long.fingerprint, number=1)
        path = original["siblings"]
        for siblings in (path[:-1], [*path, "0" * 64], list(reversed(path)), ["bad", *path[1:]]):
            with self.assertRaisesRegex(LabError, "Merkle"):
                verify_resolution_witness({**original, "siblings": siblings}, self.long.fingerprint, number=1)
        with self.assertRaises(LabError):
            verify_resolution_witness({**original, "entry": {**original["entry"], "number": True}},
                                      self.long.fingerprint, number=1)

    def test_resolution_and_confirmation_must_match_the_selected_publication(self):
        branch = self.results / "policy-divergence/long"
        historical = self.long.witness(1)
        bundle = read_proof(branch / "left-quorum.json.gz")
        result = verify_checkpoint_resolution(historical, self.old_packet, self.long.fingerprint, number=1, bundle=bundle)
        self.assertEqual(result["receipt_count"], 128)
        self.assertFalse(result["proof_rechecked"])
        with self.assertRaises(LabError):
            verify_checkpoint_resolution(historical, self.new_packet, self.long.fingerprint, number=1)
        with self.assertRaises(LabError):
            verify_checkpoint_resolution(historical, self.old_packet, self.long.fingerprint, number=1,
                                         bundle=read_proof(branch / "right-quorum.json.gz"))
        with self.assertRaisesRegex(LabError, "joint confirmation is required"):
            verify_checkpoint_resolution(historical, self.old_packet, self.long.fingerprint, number=1,
                                         expected_proof="0" * 64)

    def test_cli_audits_exports_and_rechecks_an_archived_review(self):
        def cli(*args, code=0):
            with redirect_stdout(StringIO()) as out, redirect_stderr(StringIO()) as error:
                self.assertEqual(main(["resolution-history", *map(str, args)]), code, error.getvalue())
            return json.loads(out.getvalue()) if code == 0 else error.getvalue()

        with TemporaryDirectory() as directory:
            history = self.source / "long/history.json.gz"
            descriptor = Path(directory) / "descriptor.json"
            witness = Path(directory) / "witness.json.gz"
            trust = ("--authority-trust", self.long_pins["initial_authority_sha256"],
                     "--publication-trust", self.long_pins["latest_publication_sha256"])
            cli("checkpoint", history, *trust, "--out", descriptor, "--witness-out", descriptor, code=2)
            cli("checkpoint", history, *trust, "--out", history, code=2)
            cli("checkpoint", history, *trust, "--out", descriptor, "--witness-out", witness, "--publication", 28, code=2)
            self.assertFalse(descriptor.exists())
            emitted = cli("checkpoint", history, *trust, "--out", descriptor, "--witness-out", witness, "--publication", 1)
            self.assertEqual(emitted["publication_checkpoint_sha256"], digest(read_proof(descriptor)))
            self.assertEqual(read_proof(witness), self.long.witness(1))
            prefix = ("checkpoint-verify", witness, "--publication-checkpoint-trust", self.long.fingerprint)
            cli(*prefix, code=2)
            cli(*prefix, "--publication", 1, "--proof-trust", "0" * 64, code=2)
            review = json.loads((self.source / "measurement.json").read_text(encoding="utf-8"))["review"]
            result = cli(*prefix, "--publication", 1, "--resolution", self.source / "outgoing-resolution.json.gz",
                         "--review", self.results / "policy-divergence/long/left-quorum.json.gz",
                         "--proof", self.results / "review-plan/review-128.json.gz", "--trust", review["manifest_sha256"],
                         "--checkpoint-trust", review["checkpoint_sha256"])
            self.assertTrue(result["proof_rechecked"])
            self.assertEqual((result["receipt_count"], result["replay_count"], result["anchor_count"]), (128, 16, 112))
            self.assertEqual(result["result_sha256"], review["result_sha256"])

    def test_workbench_verifies_both_encodings_and_enforces_pin_and_selection(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), _handler(None)) as server:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            address = f"http://127.0.0.1:{server.server_port}"
            headers = {"Origin": address, "X-EduCredit-Publication-Checkpoint": self.long.fingerprint}

            def send(body, media, **extra):
                return urlopen(Request(address + "/api/verify-resolution-checkpoint", body,
                                       {**headers, "Content-Type": media, **extra}), timeout=5)

            try:
                with send(canonical(self.long.witness()), "application/json") as response:
                    self.assertTrue(json.load(response)["is_checkpoint_head"])
                old = gzip_proof(self.long.witness(1))
                with send(old, "application/gzip", **{"X-EduCredit-Publication-Number": "1"}) as response:
                    result = json.load(response)
                    self.assertFalse(result["is_checkpoint_head"])
                    self.assertEqual(result["verified_authority_sha256"], self.long_pins["initial_authority_sha256"])
                for extra in ({}, {"X-EduCredit-Publication-Number": "01"},
                              {"X-EduCredit-Publication-Number": "1",
                               "X-EduCredit-Publication-Checkpoint": self.short.fingerprint}):
                    with self.assertRaises(HTTPError) as failed:
                        send(old, "application/gzip", **extra)
                    with failed.exception as response:
                        self.assertEqual(response.status, 400)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
