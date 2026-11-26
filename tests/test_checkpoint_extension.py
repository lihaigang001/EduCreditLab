from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from educreditlab import ledger
from educreditlab.checkpoint import audit_checkpoint, checkpoint_delta, extend_checkpoint, workspace_checkpoint
from educreditlab.cli import main
from educreditlab.custody_demo import run_demo
from educreditlab.lab import Lab, bundled_data, verify_review
from educreditlab.model import LabError, digest, read_json
from educreditlab.transport import read_proof


class CheckpointExtensionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = Lab(self.root / "lab", "central")
        self.lab.seed()
        transcript = bundled_data("cases.json")[0]["transcript"]
        target = ("uc-irvine", "cse-bs", "2023-06-15")
        self.before = self.lab.issue_workbench_receipt(transcript, *target)["receipt_sha256"]
        self.lab.seed_amendment()
        self.after = self.lab.issue_workbench_receipt(transcript, *target)["receipt_sha256"]
        self.index, self.full = workspace_checkpoint(self.lab.ledger)
        _, self.base = workspace_checkpoint(self.lab.ledger, height=4)
        self.manifest_pin = self.lab.ledger.fingerprint
        self.archive_pin = digest(self.base)
        self.delta = checkpoint_delta(self.full, 4)

    def extend(self, *, base=None, delta=None, **target):
        return extend_checkpoint(self.base if base is None else base, self.delta if delta is None else delta,
                                 self.manifest_pin, self.archive_pin, **target)

    def test_extension_checks_only_new_certificates_and_matches_full_audit(self):
        reference = audit_checkpoint(self.full, self.manifest_pin)
        with patch.object(ledger, "_verify_votes", wraps=ledger._verify_votes) as votes:
            index, archive = self.extend(expected_height=6, expected_head=reference.descriptor["head_sha256"])
        self.assertEqual([call.args[1]["core"]["height"] for call in votes.call_args_list], [5, 6])
        self.assertEqual(index.descriptor, reference.descriptor)
        self.assertEqual(index.fingerprint, reference.fingerprint)
        self.assertEqual(archive, self.full)
        for reference, units in ((self.before, 1600), (self.after, 400)):
            proof = index.proof(reference, self.lab.ledger.artifact(reference, "receipt"))
            replay = verify_review(proof, self.manifest_pin, trusted_checkpoint=index.fingerprint)
            self.assertEqual(replay["decision"]["recognized_units"], units)

    def test_validated_extension_can_be_used_as_the_next_base(self):
        _, first = workspace_checkpoint(self.lab.ledger, height=5)
        index, retained = self.extend(delta=checkpoint_delta(first, 4))
        latest, archive = extend_checkpoint(retained, checkpoint_delta(self.full, 5), self.manifest_pin,
                                            digest(retained))
        self.assertEqual(index.descriptor["height"], 5)
        self.assertEqual(latest.descriptor, self.index.descriptor)
        self.assertEqual(digest(archive), digest(self.full))

    def test_requires_matching_independent_pins(self):
        with self.assertRaisesRegex(LabError, "independently trusted archive fingerprint"):
            extend_checkpoint(self.base, self.delta, self.manifest_pin, None)
        with self.assertRaisesRegex(LabError, "independently trusted manifest fingerprint"):
            extend_checkpoint(self.base, self.delta, None, self.archive_pin)
        with self.assertRaisesRegex(LabError, "Manifest does not match"):
            extend_checkpoint(self.base, self.delta, "0" * 64, self.archive_pin)
        changed = deepcopy(self.base)
        changed["chain"][0]["finalization"]["votes"]["authority"] = "0" * 128
        with self.assertRaisesRegex(LabError, "Archive does not match"):
            self.extend(base=changed)

    def test_rejects_wrong_base_and_noncontiguous_updates(self):
        for field, value in (
            ("base_height", 3), ("base_head_sha256", "0" * 64), ("manifest_sha256", "0" * 64),
            ("blocks", []), ("blocks", self.delta["blocks"][1:]), ("blocks", self.delta["blocks"][::-1]),
        ):
            with self.subTest(field=field, value_type=type(value)), self.assertRaises(LabError):
                self.extend(delta={**self.delta, field: value})
        with self.assertRaises(LabError):
            checkpoint_delta(self.full, len(self.full["chain"]))

    def test_checks_new_signatures_and_the_requested_endpoint(self):
        with self.assertRaisesRegex(LabError, "target height"):
            self.extend(delta={**self.delta, "blocks": self.delta["blocks"][:1]}, expected_height=6)
        with self.assertRaisesRegex(LabError, "expected target head"):
            self.extend(expected_head="0" * 64)
        changed = deepcopy(self.delta)
        changed["blocks"][-1]["votes"]["authority"] = "0" * 128
        with self.assertRaisesRegex(LabError, "vote signature"):
            self.extend(delta=changed)

    def test_managed_actor_and_validator_rotations_survive_a_resume(self):
        directory = self.root / "managed"
        run_demo(directory)
        trust = (directory / "trusted-manifest-sha256.txt").read_text().strip()
        before = read_json(directory / "proof-before-rotation.json")
        after = read_json(directory / "proof-after-rotation.json")
        base = ledger.head_document(before["manifest"], before["chain"])
        target = ledger.head_document(after["manifest"], after["chain"])
        audit_checkpoint(base, trust)
        # The first update commits rotations. The resumed audit uses the new keys at the next block.
        rotated = ledger.head_document(after["manifest"], after["chain"][:6])
        _, retained = extend_checkpoint(base, checkpoint_delta(rotated, 4), trust, digest(base))
        latest, _ = extend_checkpoint(retained, checkpoint_delta(target, 6), trust, digest(retained))
        self.assertEqual(latest.descriptor, audit_checkpoint(after, trust).descriptor)
        for source in (before, after):
            original = verify_review(source, trust)
            evidence = {key: source[key] for key in ("policy", "transcript", "receipt")}
            short = latest.proof(original["receipt_sha256"], evidence)
            replay = verify_review(short, trust, trusted_checkpoint=latest.fingerprint)
            self.assertEqual({key: replay[key] for key in original}, original)

    def test_cli_exports_and_extends_a_public_archive(self):
        base, delta, retained, proposed, descriptor = (
            self.root / name for name in ("base.json.gz", "delta.json.gz", "retained.json", "new.json.gz", "checkpoint.json")
        )
        workspace = ["--workspace", str(self.root / "lab"), "checkpoint", "export"]
        standard = ["checkpoint", "extend", str(retained), str(delta), "--trust", self.manifest_pin,
                    "--archive-trust", self.archive_pin, "--out", str(descriptor), "--archive-out", str(proposed)]
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main([*workspace, "--height", "4", "--out", str(base)]), 0)
            self.assertEqual(main([*workspace, "--from-height", "4", "--height", "6", "--out", str(delta)]), 0)
            self.assertEqual(main(["checkpoint", "audit", str(base), "--trust", self.manifest_pin,
                                   "--archive-out", str(retained)]), 0)
            self.assertEqual(main([*standard, "--expect-height", "7"]), 2)
            self.assertFalse(descriptor.exists() or proposed.exists())
            stdout.seek(0)
            stdout.truncate()
            self.assertEqual(main([*standard, "--expect-height", "6"]), 0)
        verdict = json.loads(stdout.getvalue())
        self.assertEqual(verdict["verified_new_blocks"], 2)
        self.assertEqual(verdict["archive_sha256"], digest(read_proof(proposed)))
        self.assertEqual(read_json(descriptor), self.index.descriptor)
        public = read_proof(delta)
        self.assertEqual(public["base_height"], 4)
        self.assertEqual(len(public["blocks"]), 2)
        self.assertNotIn('"attempts"', json.dumps(public))


if __name__ == "__main__":
    unittest.main()
