import copy
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from educreditlab import custody
from educreditlab.keys import KeyRegistry, enroll, load_private_key, public_key, save_private_key
from educreditlab.lab import DEMO_ACTORS, DEMO_AMENDMENT, Lab, bundled_data, verify_review
from educreditlab.ledger import MODES, head_document, verify_chain
from educreditlab.model import LabError, canonical, digest, normalize_policy

POLICY = bundled_data("policies.json")[0]
TRANSCRIPT = bundled_data("cases.json")[0]["transcript"]
TARGET = ("uc-irvine", "cse-bs", "2023-06-15")


class ManagedCustodyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.actors = {name: Ed25519PrivateKey.generate() for name in DEMO_ACTORS}
        self.members = {name: Ed25519PrivateKey.generate() for name in MODES["consortium"][0]}
        self.enrollments = [enroll(role, name, key)
                            for role, group in (("actor", self.actors), ("validator", self.members))
                            for name, key in group.items()]
        self.lab = custody.initialize(self.root / "coordinator", self.enrollments)
        self.ledger = self.lab.ledger
        self.trust = self.ledger.fingerprint
        self.genesis = self.head()
        self.nodes = {name: custody.ValidatorStore(self.root / f"{name}.db", name, self.trust)
                      for name in self.members}
        for node in self.nodes.values():
            node.initialize(self.genesis)

    def head(self):
        return head_document(self.ledger.manifest, self.ledger.prefix())

    def policy_op(self):
        return custody.sign_policy(self.head(), self.trust, POLICY, self.actors[TARGET[0]])

    def signed_transcript(self):
        return custody.sign_transcript(self.head(), self.trust, TRANSCRIPT, self.actors[TRANSCRIPT["issuer"]])

    def approve(self, *, signed=None, known_height=None):
        request = custody.prepare_receipt(self.lab, signed or self.signed_transcript(), *TARGET,
                                          known_height=known_height)
        return custody.approve_receipt(request, self.trust, self.actors[TARGET[0]])

    def votes(self, request, names=("peer-a", "peer-b", "peer-c")):
        return [self.nodes[name].vote(request, self.members[name]) for name in names]

    def commit(self, operation, names=("peer-a", "peer-b", "peer-c")):
        result = custody.submit(self.lab, operation)
        return self.ledger.commit_external(self.votes(result["request"], names))

    def rotate(self, role, name):
        owners = self.actors if role == "actor" else self.members
        replacement = Ed25519PrivateKey.generate()
        block = self.commit(custody.authorize_rotation(self.head(), self.trust, role, name, owners[name],
                                                       replacement, "Scheduled test renewal"))
        old, owners[name] = owners[name], replacement
        return block, old

    def receipt(self, operation):
        commitment = operation["event"]["body"]["payload"]["receipt_sha256"]
        return verify_review(self.lab.bundle(commitment), self.trust)

    def test_bootstrap_never_stores_owner_secrets_and_is_repeatable(self):
        with closing(sqlite3.connect(self.ledger.path)) as conn, conn:
            self.assertEqual(conn.execute("SELECT keys FROM settings").fetchone()[0],
                             canonical({"actors": {}, "validators": {}}))
        reopened = custody.initialize(self.ledger.directory, self.enrollments)
        self.assertEqual(reopened.ledger.fingerprint, self.trust)
        self.assertTrue(reopened.ledger.managed)
        with self.assertRaisesRegex(LabError, "custody commands"):
            reopened.publish(POLICY)
        with self.assertRaisesRegex(LabError, "custody commands"):
            reopened.ledger.sync()
        with self.assertRaisesRegex(LabError, "custody commands"):
            reopened.issue_workbench_receipt(TRANSCRIPT, *TARGET)

    def test_enrollment_checks_ownership_and_duplicate_roles(self):
        corrupt = copy.deepcopy(self.enrollments)
        corrupt[0]["body"]["name"] = "unverified-institution"
        with self.assertRaisesRegex(LabError, "enrollment signature"):
            custody.initialize(self.root / "invalid", corrupt)
        with self.assertRaisesRegex(LabError, "only once"):
            custody.initialize(self.root / "invalid", [*self.enrollments, self.enrollments[0]])
        self.assertFalse((self.root / "invalid").exists())

    def test_existing_local_network_cannot_be_relabeled_managed(self):
        local = Lab(self.root / "legacy")
        with self.assertRaisesRegex(LabError, "different custody model"):
            custody.initialize(local.ledger.directory, self.enrollments)
        self.assertEqual(Lab.open(local.ledger.directory).ledger.fingerprint, local.ledger.fingerprint)

    def test_two_votes_hold_proposal_and_restart_recovers_same_hash(self):
        op = self.policy_op()
        pending = custody.submit(self.lab, op)
        votes = self.votes(pending["request"])
        with self.assertRaisesRegex(LabError, "quorum"):
            self.ledger.commit_external(votes[:2])
        self.assertEqual(self.ledger.prefix(), [])
        reopened = Lab.open(self.ledger.directory)
        self.assertEqual(reopened.ledger.external_pending(), pending["request"])
        committed = reopened.ledger.commit_external(votes)
        self.assertEqual(committed["hash"], pending["block_sha256"])
        self.assertEqual(reopened.ledger.commit_external(votes), committed)
        self.assertEqual(custody.submit(reopened, op)["status"], "committed")
        self.assertEqual(len(reopened.ledger.prefix()), 1)

    def test_duplicate_sender_votes_cannot_satisfy_quorum(self):
        result = custody.submit(self.lab, self.policy_op())
        votes = self.votes(result["request"])
        with self.assertRaisesRegex(LabError, "vote once"):
            self.ledger.commit_external([votes[0], votes[0], votes[1]])
        self.assertEqual(self.ledger.pending_height(), 1)

    def test_validator_reservation_survives_restart_and_concurrent_calls(self):
        result = custody.submit(self.lab, self.policy_op())
        request = result["request"]
        node = self.nodes["peer-a"]
        key = self.members[node.name]
        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.map(lambda _: node.vote(request, key), range(2))
        self.assertEqual(first, second)
        reopened = custody.ValidatorStore(node.path, node.name, self.trust)
        self.assertEqual(reopened.vote(request, key), first)
        other = copy.deepcopy(request)
        other["proposal"]["recorded_at"] = "2030-01-01T00:00:00+00:00"
        with self.assertRaisesRegex(LabError, "reserved a different vote"):
            reopened.vote(other, key)

    def test_validator_needs_local_bound_state_and_expected_identity(self):
        request = custody.submit(self.lab, self.policy_op())["request"]
        node = self.nodes["peer-a"]
        with self.assertRaisesRegex(LabError, "not active"):
            node.vote(request, self.members["peer-b"])
        with self.assertRaisesRegex(LabError, "bound to a different identity"):
            custody.ValidatorStore(node.path, "peer-b", self.trust).vote(request, self.members["peer-b"])
        missing = self.root / "missing.db"
        with self.assertRaisesRegex(LabError, "durable state"):
            custody.ValidatorStore(missing, "peer-a", self.trust).vote(request, self.members["peer-a"])
        self.assertFalse(missing.exists())

    def test_validator_rejects_old_heads_after_certified_sync(self):
        pending = custody.submit(self.lab, self.policy_op())
        votes = self.votes(pending["request"])
        self.ledger.commit_external(votes)
        node = self.nodes["peer-d"]
        node.accept_head(self.head())
        with self.assertRaisesRegex(LabError, "prefix is older"):
            node.vote(pending["request"], self.members["peer-d"])

    def test_owner_and_validator_reject_mismatched_trust_roots(self):
        stranger = "1" * 64
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            custody.sign_policy(self.genesis, stranger, POLICY, self.actors[TARGET[0]])
        request = custody.submit(self.lab, self.policy_op())["request"]
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            custody.ValidatorStore(self.root / "peer-a.db", "peer-a", stranger).vote(request, self.members["peer-a"])

    def test_policy_artifact_must_match_authorized_descriptor(self):
        op = self.policy_op()
        op["artifact"]["rules"][0]["label"] = "A different rule wording"
        with self.assertRaisesRegex(LabError, "signed descriptor"):
            custody.submit(self.lab, op)
        self.assertIsNone(self.ledger.pending_height())

    def test_grade_evidence_stays_outside_validator_exchange(self):
        self.commit(self.policy_op())
        operation = self.approve()
        pending = custody.submit(self.lab, operation)
        payload = pending["request"]["proposal"]["event"]["body"]["payload"]
        self.assertEqual(set(payload), {"policy_sha256", "receipt_sha256", "knowledge", "approval"})
        for key in (b'"attempts"', b'"decision"', b'"transcript"'):
            self.assertNotIn(key, canonical(pending["request"]))
        votes = self.votes(pending["request"])
        self.ledger.commit_external(votes)
        root = operation["event"]["body"]["payload"]["receipt_sha256"]
        anchor = self.lab.bundle(root, anchor_only=True)
        self.assertTrue(verify_review(anchor, self.trust)["anchor_verified"])
        self.assertNotIn(b'"attempts"', canonical(anchor))

    def test_receiver_rotation_retires_key_preserves_receipt_and_fingerprint(self):
        self.commit(self.policy_op())
        old_approval = self.approve()
        self.commit(old_approval)
        previous = self.receipt(old_approval)
        rotation, old_key = self.rotate("actor", TARGET[0])
        request = custody.prepare_receipt(self.lab, self.signed_transcript(), *TARGET, known_height=1)
        with self.assertRaisesRegex(LabError, "not active"):
            custody.approve_receipt(request, self.trust, old_key)
        new_approval = custody.approve_receipt(request, self.trust, self.actors[TARGET[0]])
        self.commit(new_approval, ("peer-b", "peer-c", "peer-d"))
        self.assertEqual(previous, self.receipt(old_approval))
        self.assertEqual(self.receipt(new_approval)["decision"], previous["decision"])
        self.assertEqual(custody.submit(self.lab, old_approval)["height"], previous["height"])
        self.assertEqual(verify_chain(self.ledger.manifest, self.ledger.prefix(), self.trust)["height"], 4)
        self.assertEqual(rotation["core"]["height"], 3)

    def test_validator_rotation_retains_state_uses_old_then_new_key(self):
        self.commit(self.policy_op())
        rotation, old_key = self.rotate("validator", "peer-b")
        self.assertIn("peer-b", rotation["votes"])
        pending = custody.submit(self.lab, self.approve())
        node = self.nodes["peer-b"]
        with self.assertRaisesRegex(LabError, "not active"):
            node.vote(pending["request"], old_key)
        votes = self.votes(pending["request"], ("peer-b", "peer-c", "peer-d"))
        committed = self.ledger.commit_external(votes)
        self.assertEqual(set(committed["votes"]), {"peer-b", "peer-c", "peer-d"})
        chain = self.ledger.prefix()
        self.assertEqual(KeyRegistry(self.ledger.manifest, chain).active_key("validator", "peer-b"),
                         public_key(self.members["peer-b"]))
        self.assertEqual(verify_chain(self.ledger.manifest, chain, self.trust)["height"], 3)

    def test_rotation_requires_replacement_proof_and_unseen_public_key(self):
        replacement = Ed25519PrivateKey.generate()
        previous = self.actors[TARGET[0]]
        rotation = custody.authorize_rotation(self.genesis, self.trust, "actor", TARGET[0], previous,
                                              replacement, "Renewal")
        corrupt = copy.deepcopy(rotation)
        corrupt["event"]["body"]["payload"]["possession"] = "0" * 128
        with self.assertRaisesRegex(LabError, "key-possession"):
            custody.submit(self.lab, corrupt)
        self.commit(rotation)
        with self.assertRaisesRegex(LabError, "unused"):
            custody.authorize_rotation(self.head(), self.trust, "actor", TARGET[0], replacement,
                                       previous, "Reuse old key")

    def test_issuer_rotation_requires_resigning_uncommitted_transcripts(self):
        self.commit(self.policy_op())
        signed = self.signed_transcript()
        old_receipt = self.approve(signed=signed)
        self.commit(old_receipt)
        stale = self.approve(signed=signed)
        self.rotate("actor", TRANSCRIPT["issuer"])
        with self.assertRaisesRegex(LabError, "preceding committed view"):
            custody.submit(self.lab, stale)
        with self.assertRaisesRegex(LabError, "transcript signature"):
            custody.prepare_receipt(self.lab, signed, *TARGET)
        active = self.approve()
        self.commit(active)
        self.assertTrue(self.receipt(old_receipt)["replayed"])
        self.assertTrue(self.receipt(active)["replayed"])

    def test_managed_policy_revision_can_use_old_knowledge_with_current_approval(self):
        self.commit(self.policy_op())
        self.rotate("actor", TARGET[0])
        revision = custody.sign_policy(self.head(), self.trust, bundled_data(DEMO_AMENDMENT), self.actors[TARGET[0]],
                                       supersedes=digest(normalize_policy(POLICY)), reason="Synthetic correction")
        self.commit(revision)
        old_view = self.approve(known_height=1)
        self.commit(old_view)
        new_view = self.approve()
        self.commit(new_view)
        self.assertEqual(self.receipt(old_view)["decision"]["recognized_units"], 1600)
        self.assertEqual(self.receipt(new_view)["decision"]["recognized_units"], 400)
        with self.assertRaisesRegex(LabError, "no certified finalization times"):
            self.lab.assess(TRANSCRIPT, *TARGET, known_at="2026-11-22T08:00:00+00:00")

    def test_pem_is_encrypted_owner_only_and_not_overwritten(self):
        path = self.root / "private.pem"
        key = self.actors[TARGET[0]]
        password = b"synthetic test passphrase"
        save_private_key(path, key, password)
        self.assertIn(b"BEGIN ENCRYPTED PRIVATE KEY", path.read_bytes())
        self.assertEqual(public_key(load_private_key(path, password)), public_key(key))
        snapshot = path.read_bytes()
        with self.assertRaises(FileExistsError):
            save_private_key(path, self.actors[TRANSCRIPT["issuer"]], password)
        self.assertEqual(path.read_bytes(), snapshot)
        with self.assertRaisesRegex(LabError, "Cannot unlock"):
            load_private_key(path, b"wrong password")
        if os.name == "posix":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.chmod(0o644)
            with self.assertRaisesRegex(LabError, "only to its owner"):
                load_private_key(path, password)


if __name__ == "__main__":
    unittest.main()
