import copy
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from educreditlab.checkpoint import audit_checkpoint, workspace_checkpoint
from educreditlab.cli import main
from educreditlab.custody_demo import run_demo
from educreditlab.lab import Lab, bundled_data, verify_review
from educreditlab.merkle import MerkleTree, verify_path
from educreditlab.model import LabError, canonical, digest, read_json
from educreditlab.transport import read_proof


def reference_root(values):
    if not values:
        return sha256(b"").digest()
    if len(values) == 1:
        return sha256(b"\x00" + canonical(values[0])).digest()
    split = 1 << ((len(values) - 1).bit_length() - 1)
    return sha256(b"\x01" + reference_root(values[:split]) + reference_root(values[split:])).digest()


def receipt_evidence(bundle):
    return {key: bundle[key] for key in ("receipt", "policy", "transcript")}


class MerkleTests(unittest.TestCase):
    def test_root_matches_recursive_reference_at_even_and_odd_sizes(self):
        for length in (0, 1, 2, 3, 5, 6, 9, 16, 17, 33, 64, 257):
            with self.subTest(length=length):
                entries = [{"sequence": index} for index in range(length)]
                tree = MerkleTree(entries)
                self.assertEqual(tree.root, reference_root(entries).hex())
                for index, entry in enumerate(entries):
                    verify_path(entry, index, tree.path(index), length, tree.root)

    def test_incomplete_extra_or_wrong_position_paths_fail(self):
        tree = MerkleTree([1, 2, 3, 4, 5])
        for value, index, path in ((5, 4, []), (5, 4, tree.path(4) + ["0" * 64]), (5, 0, tree.path(4)),
                                   (2, 1, ["0" * 64] * 3), (1, True, tree.path(0))):
            with self.subTest(index=index, value=value, siblings=len(path)), self.assertRaises(LabError):
                verify_path(value, index, path, 5, tree.root)


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = Lab(self.root / "state", "central")
        self.lab.seed()
        self.transcript = bundled_data("cases.json")[0]["transcript"]
        self.target = ("uc-irvine", "cse-bs", "2023-06-15")
        self.before = self.lab.issue_workbench_receipt(self.transcript, *self.target)["receipt_sha256"]
        self.lab.seed_amendment()
        self.after = self.lab.issue_workbench_receipt(self.transcript, *self.target)["receipt_sha256"]
        self.index, self.archive = workspace_checkpoint(self.lab.ledger)
        self.trust = self.lab.ledger.fingerprint

    def proof(self, reference):
        return self.index.proof(reference, self.lab.ledger.artifact(reference, "receipt"))

    def test_independent_audit_matches_workspace_descriptor(self):
        independently_checked = audit_checkpoint(self.archive, self.trust)
        self.assertEqual(independently_checked.fingerprint, self.index.fingerprint)
        self.assertEqual(independently_checked.descriptor, self.index.descriptor)
        original = self.lab.bundle(self.after)
        self.assertEqual(audit_checkpoint(original, self.trust).fingerprint, independently_checked.fingerprint)

    def test_policy_revisions_replay_using_the_original_knowledge_cutoff(self):
        for reference, units in ((self.before, 1600), (self.after, 400)):
            original = verify_review(self.lab.bundle(reference), self.trust)
            compact = verify_review(self.proof(reference), self.trust, trusted_checkpoint=self.index.fingerprint)
            self.assertEqual(compact["decision"]["recognized_units"], units)
            self.assertEqual({k: compact[k] for k in original}, original)

    def test_anchor_excludes_grades_and_uses_signed_receipt_height(self):
        proof = self.index.proof(self.before)
        self.assertNotIn("scope_witness", proof)
        self.assertNotIn("chain", proof)
        self.assertNotIn(b'"attempts"', canonical(proof))
        verified = verify_review(proof, self.trust, trusted_checkpoint=self.index.fingerprint)
        self.assertTrue(verified["anchor_verified"])
        self.assertFalse(verified["replayed"])
        self.assertEqual((verified["height"], verified["checkpoint_height"]), (4, 6))
        self.assertEqual(verified["receipt_sha256"], self.before)

    def test_full_proof_requires_independent_pins(self):
        compact = self.proof(self.after)
        with self.assertRaisesRegex(LabError, "independent manifest and checkpoint"):
            verify_review(compact, self.trust)
        with self.assertRaisesRegex(LabError, "independent manifest and checkpoint"):
            verify_review(compact, None, trusted_checkpoint=self.index.fingerprint)
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            verify_review(compact, "0" * 64, trusted_checkpoint=self.index.fingerprint)
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            verify_review(compact, self.trust, trusted_checkpoint="0" * 64)

    def test_explicit_checkpoint_does_not_fall_back_to_full_prefix_mode(self):
        with self.assertRaisesRegex(LabError, "compact proofs only"):
            verify_review(self.lab.bundle(self.after), self.trust, trusted_checkpoint=self.index.fingerprint)

    def test_proof_does_not_transfer_to_another_height_of_the_same_network(self):
        earlier, _ = workspace_checkpoint(self.lab.ledger, height=4)
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            verify_review(self.proof(self.after), self.trust, trusted_checkpoint=earlier.fingerprint)
        with self.assertRaisesRegex(LabError, "not included"):
            earlier.proof(self.after)
        with self.assertRaisesRegex(LabError, "not been committed"):
            workspace_checkpoint(self.lab.ledger, height=300)

    def test_committed_receipt_entry_and_its_path_are_checked(self):
        for field in ("entry", "path"):
            changed = self.proof(self.after)
            if field == "entry":
                # Copy nested data to keep the index intact for the next case.
                changed = copy.deepcopy(changed)
                changed["receipt_witness"]["entry"]["actor_keys"]["uc-irvine"] = "0" * 64
            else:
                changed["receipt_witness"]["path"][0] = "0" * 64
            with self.assertRaisesRegex(LabError, "Merkle path"):
                verify_review(changed, self.trust, trusted_checkpoint=self.index.fingerprint)

    def test_policy_scope_witness_must_include_the_committed_timeline(self):
        omitted = copy.deepcopy(self.proof(self.before))
        omitted["scope_witness"]["entry"]["registrations"].pop()
        with self.assertRaisesRegex(LabError, "Merkle path"):
            verify_review(omitted, self.trust, trusted_checkpoint=self.index.fingerprint)
        evidence = self.lab.ledger.artifact(self.after, "receipt")
        document = self.index.proof(self.after, evidence)
        other_scope = {**document["receipt_witness"]["entry"]["scope"], "receiver": "uc-merced"}
        document["scope_witness"] = self.index._witness(self.index._scope_indices[digest(other_scope)])
        with self.assertRaisesRegex(LabError, "timeline does not match"):
            verify_review(document, self.trust, trusted_checkpoint=self.index.fingerprint)

    def test_compact_replay_checks_original_private_signatures(self):
        for part in ("transcript", "receipt"):
            proof = self.proof(self.after)
            proof[part]["signature"] = "0" * 128
            with self.assertRaisesRegex(LabError, f"{part} signature"):
                verify_review(proof, self.trust, trusted_checkpoint=self.index.fingerprint)

    def test_checkpoint_audit_checks_all_public_votes(self):
        corrupt = copy.deepcopy(self.archive)
        corrupt["chain"][1]["votes"]["authority"] = "0" * 128
        with self.assertRaisesRegex(LabError, "vote signature"):
            audit_checkpoint(corrupt, self.trust)
        with self.assertRaisesRegex(LabError, "signed ledger archive"):
            audit_checkpoint(self.proof(self.after), self.trust)

    def test_cli_audits_archive_and_replays_the_gzip_proof(self):
        archive = self.root / "archive.json.gz"
        descriptor = self.root / "checkpoint.json"
        proof = self.root / "proof.json.gz"
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            workspace = ["--workspace", str(self.root / "state")]
            self.assertEqual(main([*workspace, "checkpoint", "export", "--height", "6", "--out", str(archive)]), 0)
            self.assertEqual(main(["checkpoint", "audit", str(archive), "--trust", self.trust,
                                   "--out", str(descriptor)]), 0)
            self.assertEqual(main([*workspace, "bundle", self.before, "--compact", "--checkpoint-height", "6",
                                   "--out", str(proof)]), 0)
            self.assertEqual(main(["verify", str(proof), "--trust", self.trust]), 2)
            self.assertEqual(main(["verify", str(proof), "--trust", self.trust, "--checkpoint-trust",
                                   self.index.fingerprint]), 0)
        self.assertEqual(read_json(descriptor), read_proof(proof)["checkpoint"])

    def test_legacy_v100_proof_has_a_compatible_compact_form(self):
        directory = Path(__file__).parent / "fixtures"
        older = read_json(directory / "v100-review-bundle.json")
        trust = (directory / "v100-trust-fingerprint.txt").read_text().strip()
        legacy = verify_review(older, trust)
        index = audit_checkpoint(older, trust)
        compact = index.proof(legacy["receipt_sha256"], receipt_evidence(older))
        new = verify_review(compact, trust, trusted_checkpoint=index.fingerprint)
        self.assertEqual({k: new[k] for k in legacy}, legacy)

    def test_before_and_after_actor_and_validator_rotation(self):
        directory = self.root / "managed"
        run_demo(directory)
        trust = (directory / "trusted-manifest-sha256.txt").read_text().strip()
        older = read_json(directory / "proof-before-rotation.json")
        newer = read_json(directory / "proof-after-rotation.json")
        index = audit_checkpoint(newer, trust)
        actor_keys = []
        for proof in (older, newer):
            prior = verify_review(proof, trust)
            short = index.proof(prior["receipt_sha256"], receipt_evidence(proof))
            compact = verify_review(short, trust, trusted_checkpoint=index.fingerprint)
            self.assertEqual({k: compact[k] for k in prior}, prior)
            self.assertEqual(compact["decision"]["recognized_units"], 1600)
            actor_keys.append(short["receipt_witness"]["entry"]["actor_keys"]["uc-irvine"])
        self.assertNotEqual(*actor_keys)


if __name__ == "__main__":
    unittest.main()
