"""Business-date and registration-history tests for same-year policy amendments."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from educreditlab.lab import DEMO_AMENDMENT, Lab, bundled_data, verify_bundle, verify_review
from educreditlab.ledger import policy_descriptor
from educreditlab.model import LabError, digest, normalize_policy
from educreditlab.temporal import knowledge_view

TARGET = ("uc-irvine", "cse-bs", "2023-06-15")
TRANSCRIPT = bundled_data("cases.json")[0]["transcript"]
AMENDMENT = bundled_data(DEMO_AMENDMENT)
PARENT = normalize_policy(bundled_data("policies.json")[0])


def variant(version, start, end):
    policy = deepcopy(AMENDMENT)
    policy.update(version=version, valid_from=start, valid_until=end)
    return policy


class TemporalRegistryTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name)
        self.lab = Lab(self.path)
        self.lab.seed()
        self.initial_height = len(self.lab.ledger.prefix())
        self.parent = digest(PARENT)

    def test_same_assessment_date_uses_knowledge_before_and_after_revision(self):
        amended = self.lab.seed_amendment()
        result = self.lab.compare(TRANSCRIPT, *TARGET, self.initial_height)
        self.assertEqual(result["before"]["decision"]["recognized_units"], 1600)
        self.assertEqual(result["after"]["decision"]["recognized_units"], 400)
        self.assertEqual(result["delta"], {"units": -1200, "added_rules": [], "removed_rules": ["ics-31-33"]})
        self.assertEqual(result["after"]["policy_view"]["registration"]["supersedes"], self.parent)
        self.assertEqual(result["after"]["policy_view"]["registration"]["block_sha256"], amended["hash"])

    def test_revision_starts_inclusively_and_ends_exclusively(self):
        self.lab.seed_amendment()
        for when, expected in (("2023-05-31", "ay-2022-23"), ("2023-06-01", AMENDMENT["version"]),
                               ("2023-06-30", AMENDMENT["version"]), ("2023-07-01", "sim-2023-07")):
            with self.subTest(when=when):
                selected = self.lab.preview(TRANSCRIPT, *TARGET[:2], when)
                self.assertEqual(selected["policy_version"], expected)

    def test_ordinary_overlapping_registration_requires_revision(self):
        with self.assertRaisesRegex(LabError, "explicit policy revision"):
            self.lab.publish(AMENDMENT)

    def test_cross_institution_parent_is_rejected(self):
        merced = digest(normalize_policy(bundled_data("policies.json")[1]))
        with self.assertRaisesRegex(LabError, "same institution"):
            self.lab.revise(AMENDMENT, merced, "Testing the policy scope")
        self.assertEqual(len(self.lab.ledger.prefix()), self.initial_height)
        self.assertIsNone(self.lab.ledger.pending_height())

    def test_child_interval_cannot_extend_beyond_parent(self):
        child = variant("long-interval", "2023-06-01", "2023-07-02")
        with self.assertRaisesRegex(LabError, "parent policy's effective interval"):
            self.lab.revise(child, self.parent, "Interval example")

    def test_previous_parent_is_inactive_at_overlapping_slice(self):
        self.lab.seed_amendment()
        child = variant("second-june-revision", "2023-06-10", "2023-06-24")
        with self.assertRaisesRegex(LabError, "no longer active"):
            self.lab.revise(child, self.parent, "This slice already has an amendment")
        child_parent = digest(normalize_policy(AMENDMENT))
        self.lab.revise(child, child_parent, "Follow-up to the immediately current policy")
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET)["policy_version"], child["version"])
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET[:2], "2023-06-25")["policy_version"],
                         AMENDMENT["version"])

    def test_disjoint_amendment_can_still_reference_original(self):
        self.lab.seed_amendment()
        second = variant("may-revision", "2023-05-22", "2023-06-01")
        self.lab.revise(second, self.parent, "A distinct interval")
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET[:2], "2023-05-31")["policy_version"],
                         second["version"])
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET)["policy_version"], AMENDMENT["version"])

    def test_wrong_receiving_signer_cannot_register_amendment(self):
        descriptor = policy_descriptor(normalize_policy(AMENDMENT))
        event = self.lab.ledger.event("policy-revision", "uc-merced",
            {"policy": descriptor, "supersedes": self.parent, "reason": "Check the receiver's role"})
        with self.assertRaisesRegex(LabError, "Only a receiving institution"):
            self.lab.ledger.append(event, artifact=AMENDMENT)

    def test_pending_amendment_does_not_change_committed_view(self):
        peers = ("peer-a", "peer-b")
        with self.assertRaisesRegex(LabError, "quorum unavailable"):
            self.lab.revise(AMENDMENT, self.parent, "Controlled quorum test", available=peers)
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET)["recognized_units"], 1600)
        fresh = Lab.open(self.path)
        pending = fresh.ledger.pending_height()
        fresh.ledger.sync()
        self.assertEqual(fresh.preview(TRANSCRIPT, *TARGET)["recognized_units"], 400)
        self.assertEqual(len(fresh.ledger.prefix()), pending)
        self.assertEqual(fresh.revise(AMENDMENT, self.parent, "Controlled quorum test")["core"]["height"],
                         pending)

    def test_concurrent_different_amendments_do_not_split_one_parent_slice(self):
        options = [variant(value, "2023-06-01", "2023-07-01") for value in ("june-a", "june-b")]
        def publish(policy):
            try:
                return self.lab.revise(policy, self.parent, "Concurrent registration test")
            except LabError as error:
                return str(error)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(publish, options))
        accepted = [result for result in results if isinstance(result, dict)]
        self.assertEqual(len(accepted), 1)
        self.assertTrue(any("no longer active" in entry for entry in results if isinstance(entry, str)))
        self.assertEqual(len(self.lab.ledger.prefix()), self.initial_height + 1)

    def test_new_receipt_can_pin_old_view_after_new_policy_is_registered(self):
        self.lab.seed_amendment()
        signed = self.lab.sign_transcript(TRANSCRIPT)
        old = self.lab.record(signed, *TARGET, known_height=self.initial_height)
        new = self.lab.record(signed, *TARGET)
        for result, amount in ((old, 1600), (new, 400)):
            bundle = self.lab.bundle(result["receipt_sha256"])
            checked = verify_bundle(bundle, self.lab.ledger.fingerprint)
            self.assertEqual(checked["decision"]["recognized_units"], amount)
            self.assertEqual(checked["policy_view"], result["policy_view"])
            anchor = self.lab.bundle(result["receipt_sha256"], anchor_only=True)
            self.assertTrue(verify_review(anchor, self.lab.ledger.fingerprint)["anchor_verified"])
        self.assertGreater(old["height"], self.initial_height + 1)

    def test_unpinned_cli_nonce_remembers_original_policy_after_revision(self):
        signed = self.lab.sign_transcript(TRANSCRIPT)
        first = self.lab.record(signed, *TARGET, nonce="e1" * 32)
        self.lab.seed_amendment()
        retry = self.lab.record(signed, *TARGET, nonce="e1" * 32)
        self.assertEqual(first, retry)
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET)["recognized_units"], 400)

    def test_workbench_approval_distinguishes_changed_policy_and_reuses_old_receipt(self):
        old = self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET)
        self.lab.seed_amendment()
        now = self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET)
        again = self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET, known_height=self.initial_height)
        self.assertEqual(old, again)
        self.assertNotEqual(old["receipt_sha256"], now["receipt_sha256"])

    def test_temporal_lookup_does_not_move_transcript_cutoff(self):
        transcript = deepcopy(TRANSCRIPT)
        transcript["attempts"] = [dict(attempt, grade="B", completed_on="2023-06-16")
                                  if attempt["course"] == "CS/IS 137" else attempt
                                  for attempt in transcript["attempts"]]
        self.lab.seed_amendment()
        self.assertEqual(self.lab.preview(transcript, *TARGET)["recognized_units"], 400)
        self.assertEqual(self.lab.preview(transcript, *TARGET[:2], "2023-06-16")["recognized_units"], 1600)

    def test_signed_registration_instant_selects_revision(self):
        amendment = self.lab.seed_amendment()
        utc = amendment["finalization"]["recorded_at"]
        state = self.lab.assess(TRANSCRIPT, *TARGET, known_at=utc)
        self.assertEqual(state["policy_view"]["knowledge"]["height"], amendment["core"]["height"])
        self.assertEqual(state["decision"]["recognized_units"], 400)
        with self.assertRaisesRegex(LabError, "either"):
            self.lab.assess(TRANSCRIPT, *TARGET, known_at=utc, known_height=self.initial_height)

    def test_a_time_during_quorum_wait_sees_only_committed_policy(self):
        prepare = datetime(2040, 1, 1, 9, 0, tzinfo=timezone.utc)
        commit = datetime(2040, 1, 1, 10, 0, tzinfo=timezone.utc)
        with patch("educreditlab.ledger.datetime", wraps=datetime) as clock:
            clock.now.return_value = prepare
            with self.assertRaisesRegex(LabError, "quorum unavailable"):
                self.lab.revise(AMENDMENT, self.parent, "Wait for quorum", available=("peer-a", "peer-b"))
            clock.now.return_value = commit
            self.lab.ledger.sync()
        amendment = self.lab.ledger.prefix()[-1]
        self.assertEqual(amendment["core"]["recorded_at"], prepare.isoformat())
        self.assertEqual(amendment["finalization"]["recorded_at"], commit.isoformat())
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET, known_at="2040-01-01T09:30:00Z")
                         ["recognized_units"], 1600)
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET, known_at=commit.isoformat())
                         ["recognized_units"], 400)

    def test_a_changed_finalize_time_is_rejected_in_replay(self):
        self.lab.seed_amendment()
        receipt = self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET)
        proof = self.lab.bundle(receipt["receipt_sha256"])
        proof["chain"][-2]["finalization"]["recorded_at"] = "2040-01-01T10:00:00Z"
        with self.assertRaisesRegex(LabError, "finalization signature"):
            verify_bundle(proof, self.lab.ledger.fingerprint)

    def test_invalid_comparison_order_and_snapshot_range(self):
        self.lab.seed_amendment()
        with self.assertRaisesRegex(LabError, "earlier knowledge height"):
            self.lab.compare(TRANSCRIPT, *TARGET, self.initial_height + 1, self.initial_height)
        with self.assertRaisesRegex(LabError, "knowledge height"):
            self.lab.preview(TRANSCRIPT, *TARGET, known_height=999)


class KnowledgeCutoffTests(unittest.TestCase):
    def test_utc_offset_and_tie_inclusive(self):
        values = ["2026-11-22T07:00:00+00:00", "2026-11-22T07:05:00+00:00",
                  "2026-11-22T07:05:00+00:00"]
        chain = [{"core": {"recorded_at": when}, "finalization": {"recorded_at": when}, "hash": digest(n)}
                 for n, when in enumerate(values)]
        self.assertEqual(knowledge_view(chain, known_at="2026-11-22T15:04:59+08:00")["height"], 1)
        self.assertEqual(knowledge_view(chain, known_at="2026-11-22T07:05:00Z")["height"], 3)
        self.assertEqual(knowledge_view(chain, known_at="2026-11-22T06:59:00Z")["height"], 0)
        with self.assertRaisesRegex(LabError, "UTC offset"):
            knowledge_view(chain, known_at="2026-11-22T07:01:00")

    def test_backward_clock_uses_height_to_disambiguate(self):
        higher = datetime(2026, 11, 22, 7, 1, tzinfo=timezone.utc).isoformat()
        lower = datetime(2026, 11, 22, 7, 0, tzinfo=timezone.utc).isoformat()
        chain = [{"core": {"recorded_at": when}, "finalization": {"recorded_at": when}, "hash": digest(n)}
                 for n, when in enumerate((higher, lower))]
        with self.assertRaisesRegex(LabError, "moved backwards"):
            knowledge_view(chain, known_at=higher)
        self.assertEqual(knowledge_view(chain, known_height=1)["recorded_at"], higher)

    def test_legacy_proposal_time_does_not_claim_a_commit_cutoff(self):
        old = {"core": {"recorded_at": "2026-11-22T07:00:00Z"}, "hash": digest("old")}
        revised = {"core": {"recorded_at": "2026-11-22T08:00:00Z"},
                   "finalization": {"recorded_at": "2026-11-22T08:05:00Z"}, "hash": digest("new")}
        with self.assertRaisesRegex(LabError, "predates the certified"):
            knowledge_view([old, revised], known_at="2026-11-22T07:30:00Z")
        self.assertEqual(knowledge_view([old, revised], known_height=1)["time_basis"], "proposal")
        self.assertEqual(knowledge_view([old, revised], known_at="2026-11-22T08:05:00Z")["height"], 2)

