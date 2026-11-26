from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from educreditlab.checkpoint import audit_checkpoint, workspace_checkpoint
from educreditlab.cli import main
from educreditlab.custody_demo import run_demo
from educreditlab.lab import Lab, bundled_data, verify_review
from educreditlab.model import LabError, digest, read_json
from educreditlab.review_plan import make_review_plan
from educreditlab.transport import read_proof


class ReviewPlanTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = Lab(self.root / "state", "central")
        self.lab.seed()
        transcript = bundled_data("cases.json")[0]["transcript"]
        def issue(receiver):
            return self.lab.issue_workbench_receipt(transcript, receiver, "cse-bs", "2023-06-15")["receipt_sha256"]
        self.before = issue("uc-irvine")
        self.lab.seed_amendment()
        self.after = issue("uc-irvine")
        self.merced = issue("uc-merced")
        self.references = [self.before, self.after, self.merced]
        index, archive = workspace_checkpoint(self.lab.ledger)
        self.trust = self.lab.ledger.fingerprint
        self.index = audit_checkpoint(archive, self.trust)
        self.assertEqual(self.index.descriptor, index.descriptor)
        self.plan = self.make(replay=[self.before, self.after], anchor=[self.merced])
        self.pin = digest(self.plan)

    def make(self, **requests):
        return make_review_plan(self.trust, self.index.fingerprint, **requests)

    def evidence(self, reference):
        return self.lab.ledger.artifact(reference, "receipt")

    def proof(self):
        return self.index.review_proof(self.plan, self.pin, self.evidence)

    def verify(self, proof, **kwargs):
        pins = {"trusted_checkpoint": self.index.fingerprint, "trusted_plan": self.pin, **kwargs}
        return verify_review(proof, self.trust, **pins)

    def test_mixed_review_loads_only_replay_evidence_and_preserves_results(self):
        requested = []
        def load(reference):
            requested.append(reference)
            return self.evidence(reference)
        bundle = self.index.review_proof(self.plan, self.pin, load)
        self.assertCountEqual(requested, [self.before, self.after])
        self.assertEqual(set(bundle["evidence"]), {self.before, self.after})
        self.assertEqual(len(bundle["policies"]), 2)
        scopes = [leaf["entry"]["scope"] for leaf in bundle["leaves"] if leaf["entry"]["kind"] == "policy-scope"]
        self.assertEqual([scope["receiver"] for scope in scopes], ["uc-irvine"])
        result = self.verify(bundle)
        self.assertEqual((result["replay_count"], result["anchor_count"]), (2, 1))
        self.assertEqual([r["receipt_sha256"] for r in result["receipts"]], self.references)
        self.assertEqual([r["decision"]["recognized_units"] for r in result["receipts"][:2]], [1600, 400])
        self.assertNotIn("decision", result["receipts"][2])
        for row in result["receipts"]:
            ref = row["receipt_sha256"]
            evidence = self.evidence(ref) if row["replayed"] else None
            separate = verify_review(self.index.proof(ref, evidence), self.trust,
                                     trusted_checkpoint=self.index.fingerprint)
            self.assertEqual(row, {key: separate[key] for key in row})

    def test_plan_is_deterministic_and_rejects_duplicate_or_empty_requests(self):
        self.assertEqual(self.plan, self.make(replay=[self.after, self.before], anchor=[self.merced]))
        with self.assertRaisesRegex(LabError, "unique and increasing"):
            self.make(replay=[self.before], anchor=[self.before])
        with self.assertRaisesRegex(LabError, "at least one receipt"):
            self.make()

    def test_rejects_missing_or_different_independently_agreed_plan(self):
        bundle = self.proof()
        with self.assertRaisesRegex(LabError, "independently trusted review plan"):
            self.verify(bundle, trusted_plan=None)
        alternate = self.make(anchor=self.references)
        internally_valid = self.index.review_proof(alternate, digest(alternate), self.evidence)
        with self.assertRaisesRegex(LabError, "does not match the independently trusted fingerprint"):
            self.verify(internally_valid)
        with self.assertRaisesRegex(LabError, "plan-bound proofs only"):
            self.verify(self.index.batch_proof(self.references))

    def test_export_rejects_bad_pin_wrong_checkpoint_and_absent_receipts_before_private_load(self):
        def forbidden(reference):
            self.fail(f"Unexpected access to {reference}")
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            self.index.review_proof(self.plan, "0" * 64, forbidden)
        other = {**self.plan, "checkpoint_sha256": "0" * 64}
        with self.assertRaisesRegex(LabError, "selected manifest and checkpoint"):
            self.index.review_proof(other, digest(other), forbidden)
        missing = self.make(replay=["0" * 64, self.before])
        with self.assertRaisesRegex(LabError, "not included"):
            self.index.review_proof(missing, digest(missing), forbidden)

    def test_rejects_missing_evidence_and_extra_disclosure_with_intact_plan(self):
        proof = self.proof()
        omitted, excess = deepcopy(proof), deepcopy(proof)
        omitted["evidence"].pop(self.before)
        excess["evidence"][self.merced] = {key: value for key, value in self.evidence(self.merced).items()
                                          if key in ("transcript", "receipt")}
        for candidate in (omitted, excess):
            with self.assertRaisesRegex(LabError, "requested replay set"):
                self.verify(candidate)

    def test_valid_multiproof_of_an_incomplete_group_fails_the_original_plan(self):
        partial = self.make(replay=[self.before, self.after])
        substitute = self.index.review_proof(partial, digest(partial), self.evidence)
        candidate = {**substitute, "review_plan": self.plan}
        with self.assertRaisesRegex(LabError, "exactly the planned receipts"):
            self.verify(candidate)

    def test_uniform_modes_are_supported(self):
        anchor = self.make(anchor=self.references)
        def forbidden(reference):
            self.fail(f"Anchor-only export attempted to read {reference}")
        for plan, loader, full in ((anchor, forbidden, False), (self.make(replay=self.references), self.evidence, True)):
            pin = digest(plan)
            proof = self.index.review_proof(plan, pin, loader)
            result = self.verify(proof, trusted_plan=pin)
            self.assertEqual(result["replayed"], full)
            self.assertEqual(result["replay_count"], len(self.references) if full else 0)
            self.assertEqual(len(proof["evidence"]), result["replay_count"])

    def test_mixed_plan_replays_receipt_issued_after_key_rotation(self):
        directory = self.root / "managed"
        run_demo(directory)
        trust = (directory / "trusted-manifest-sha256.txt").read_text().strip()
        original = [read_json(directory/f"proof-{side}-rotation.json") for side in ("before", "after")]
        index = audit_checkpoint(original[-1], trust)
        before, after = [verify_review(bundle, trust)["receipt_sha256"] for bundle in original]
        private = {after: {key: original[-1][key] for key in ("policy", "transcript", "receipt")}}
        plan = make_review_plan(trust, index.fingerprint, anchor=[before], replay=[after])
        pin = digest(plan)
        result = verify_review(index.review_proof(plan, pin, private.__getitem__), trust,
                               trusted_checkpoint=index.fingerprint, trusted_plan=pin)
        self.assertEqual([row["height"] for row in result["receipts"]], [4, 7])
        self.assertTrue(result["receipts"][0]["anchor_verified"])
        self.assertEqual(result["receipts"][1]["decision"]["recognized_units"], 1600)

    def test_cli_creates_pinned_gzip_package_and_requires_plan_pin(self):
        plan, output = (self.root / name for name in ("review-plan.json", "review.json.gz"))
        stdout, stderr = StringIO(), StringIO()
        pins = ["--trust", self.trust, "--checkpoint-trust", self.index.fingerprint]
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(["review-plan", *pins, "--replay", self.before, "--anchor", self.after,
                                   "--out", str(plan)]), 0)
            pin = json.loads(stdout.getvalue())["review_plan_sha256"]
            command = ["--workspace", str(self.root / "state"), "bundle-review", str(plan), "--out", str(output)]
            self.assertEqual(main([*command, "--plan-trust", "0" * 64]), 2)
            self.assertFalse(output.exists())
            self.assertEqual(main([*command, "--plan-trust", pin]), 0)
            self.assertEqual(main(["verify", str(output), *pins]), 2)
            stdout.seek(0)
            stdout.truncate()
            self.assertEqual(main(["verify", str(output), *pins, "--plan-trust", pin]), 0)
        self.assertEqual(read_proof(output)["schema"], 4)
        result = json.loads(stdout.getvalue())
        self.assertEqual((result["replay_count"], result["anchor_count"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
