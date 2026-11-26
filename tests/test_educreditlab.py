from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from educreditlab.lab import Lab, bundled_data, verify_bundle
from educreditlab.ledger import verify_chain
from educreditlab.model import LabError, digest, loads, normalize_policy
from educreditlab.solver import evaluate

DAY = "2023-06-15"
POLICIES = bundled_data("policies.json")
CASES = bundled_data("cases.json")
CASE = CASES[0]["transcript"]


def rules(decision):
    return {row["id"] for row in decision["rules"] if row["status"] == "recognized"}


class SolverTests(unittest.TestCase):
    def test_case_matches_archived_extracts(self):
        uci = evaluate(POLICIES[0], CASE, DAY)
        ucm = evaluate(POLICIES[1], CASE, DAY)
        self.assertEqual((uci["recognized_units"], uci["unit"]), (1600, "quarter units"))
        self.assertEqual((ucm["recognized_units"], ucm["unit"]), (2000, "semester units"))
        self.assertEqual(rules(uci), {"ics-31-33", "math-2a"})
        self.assertEqual(rules(ucm), {"cse-020-021", "cse-022", "cse-030", "math-021",
                                      "math-022", "phys-008-008l"})

    def test_retake_eligible_only_on_or_after_completion(self):
        before = evaluate(POLICIES[0], CASES[1]["transcript"], DAY)
        on_date = evaluate(POLICIES[0], CASES[1]["transcript"], "2023-06-24")
        self.assertNotIn("ics-31-33", rules(before))
        self.assertIn("ics-31-33", rules(on_date))

    def test_mixed_regular_and_honors_path(self):
        output = evaluate(POLICIES[1], CASES[2]["transcript"], DAY)
        self.assertEqual(rules(output), {"cse-020-021", "cse-022", "math-023", "math-024",
                                         "phys-008-008l", "phys-009-009l"})

    def test_cap_with_conflict_explanations(self):
        decision = evaluate(POLICIES[2], CASES[3]["transcript"], "2023-07-15")
        self.assertEqual(1600, decision["recognized_units"])
        blocked = next(row for row in decision["rules"] if row["status"] == "allocation_conflict")
        self.assertTrue(any(row["total_cap"] for row in blocked["allocation_blockers"]))

    def test_reuse_must_be_explicit(self):
        policy = deepcopy(POLICIES[1])
        policy["reuse"] = []
        self.assertNotIn("cse-020-021", rules(evaluate(policy, CASE, DAY)))
        self.assertIn("cse-020-021", rules(evaluate(POLICIES[1], CASE, DAY)))

    def test_zero_cap_preserves_a_zero_unit_preparation_check(self):
        policy = deepcopy(POLICIES[1])
        policy["cap"] = 0
        output = evaluate(policy, CASE, DAY)
        self.assertEqual(rules(output), {"cse-020-021"})
        self.assertEqual(output["recognized_units"], 0)

    def test_future_date_at_exclusive_policy_boundary(self):
        with self.assertRaises(LabError):
            evaluate(POLICIES[0], CASE, "2023-07-01")

    def test_deterministic_under_ordering_changes(self):
        policy, transcript = deepcopy(POLICIES[1]), deepcopy(CASE)
        policy["rules"].reverse()
        for rule in policy["rules"]:
            rule["options"].reverse()
        transcript["attempts"].reverse()
        self.assertEqual(evaluate(policy, transcript, DAY), evaluate(POLICIES[1], CASE, DAY))

    def test_unknown_course_is_ignored_and_pass_is_unranked(self):
        transcript = deepcopy(CASE)
        transcript["attempts"] = [{"id": "unranked", "course": "MATH 103EH",
                                   "grade": "P", "completed_on": DAY},
                                  {"id": "unmapped", "course": "UNKNOWN 1",
                                   "grade": "A", "completed_on": DAY}]
        result = evaluate(POLICIES[1], transcript, DAY)
        checks = next(row for row in result["rules"] if row["id"] == "math-021")
        self.assertEqual(checks["options"][1]["clauses"][0]["state"], "unranked_grade")
        self.assertEqual(result["recognized_units"], 0)

    def test_invalid_field_and_duplicate_json_key(self):
        with self.assertRaisesRegex(LabError, "Duplicate JSON key"):
            loads('{"policy": 1, "policy": 2}')
        with self.assertRaises(LabError):
            loads('{"cap": 0.5}')
        wrong = deepcopy(POLICIES[0])
        wrong["cap"] = True
        with self.assertRaises(LabError):
            normalize_policy(wrong)

    def test_reuse_for_unrelated_rule_rejected(self):
        broken = deepcopy(POLICIES[1])
        broken["reuse"][0]["rules"] = ["cse-020-021", "math-021"]
        with self.assertRaisesRegex(LabError, "reuse exception"):
            normalize_policy(broken)


class LedgerTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "network"
        self.lab = Lab(self.path)
        self.lab.publish(POLICIES[0])
        self.signed = self.lab.sign_transcript(CASE)
        self.peers = tuple(self.lab.ledger.manifest["validators"])

    def record(self, **kwargs):
        return self.lab.record(self.signed, "uc-irvine", "cse-bs", DAY, **kwargs)

    def test_after_policy_revision_original_receipt_replays(self):
        event = self.record()
        self.lab.publish(POLICIES[2])
        restored = Lab.open(self.path)
        bundle = restored.bundle(event["receipt_sha256"], self.peers[1])
        outcome = verify_bundle(bundle, self.lab.ledger.fingerprint)
        self.assertEqual(outcome["decision"]["recognized_units"], 1600)
        self.assertEqual(restored.preview(CASE, "uc-irvine", "cse-bs", "2023-07-01")["recognized_units"], 400)
        self.assertEqual(outcome["height"], 2)

    def test_republishing_same_snapshot_is_idempotent(self):
        original = self.lab.ledger.prefix()[0]
        self.assertEqual(self.lab.publish(POLICIES[0]), original)
        self.assertEqual(len(self.lab.ledger.prefix()), 1)

    def test_overlapping_policy_edition_rejected(self):
        overlap = deepcopy(POLICIES[0])
        overlap["version"] = "overlap"
        with self.assertRaisesRegex(LabError, "Overlapping"):
            self.lab.publish(overlap)

    def test_known_signed_transcript_only(self):
        edited = deepcopy(self.signed)
        edited["signature"] = "1" * 128
        with self.assertRaisesRegex(LabError, "Invalid transcript signature"):
            self.lab.record(edited, "uc-irvine", "cse-bs", DAY)

    def test_quorum_fails_closed_then_retries_without_duplicate(self):
        nonce = "ab" * 32
        with self.assertRaisesRegex(LabError, "quorum unavailable"):
            self.record(nonce=nonce, available=self.peers[:2])
        self.assertEqual(len(self.lab.ledger.prefix()), 1)
        restored = Lab.open(self.path)
        restored.ledger.sync()
        first = self.record(nonce=nonce, available=self.peers[:3])
        self.assertEqual(first["height"], 2)
        self.assertTrue(all(len(self.lab.ledger.prefix(name)) == 2 for name in self.peers))

    def test_one_replica_can_catch_up(self):
        event = self.record(available=self.peers[:3])
        self.assertEqual(len(event["votes"]), 3)
        self.assertEqual(len(self.lab.ledger.prefix(self.peers[3])), 1)
        self.lab.ledger.sync()
        bundle = self.lab.bundle(event["receipt_sha256"], self.peers[3])
        self.assertTrue(verify_bundle(bundle, self.lab.ledger.fingerprint)["replayed"])

    def test_changed_block_copy_fails_verification(self):
        receipt = self.record()
        original = self.lab.bundle(receipt["receipt_sha256"])
        for corrupt in ("hash", "votes", "policy", "transcript"):
            with self.subTest(corrupt=corrupt):
                bundle = deepcopy(original)
                if corrupt == "hash":
                    bundle["chain"][-1]["core"]["previous"] = "0" * 64
                elif corrupt == "votes":
                    bundle["chain"][-1]["votes"] = dict(list(bundle["chain"][-1]["votes"].items())[:2])
                elif corrupt == "policy":
                    bundle["policy"]["rules"][0]["units"] += 100
                else:
                    bundle["transcript"]["body"]["transcript"]["holder"] = "another"
                with self.assertRaises(LabError):
                    verify_bundle(bundle, self.lab.ledger.fingerprint)

    def test_wrong_trust_domain_rejected(self):
        receipt = self.record()
        bundle = self.lab.bundle(receipt["receipt_sha256"])
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            verify_bundle(bundle, "0" * 64)

    def test_chain_only_holds_commitments(self):
        self.record()
        event = self.lab.ledger.prefix()[-1]["core"]["event"]["body"]
        self.assertEqual(set(event["payload"]), {"policy_sha256", "receipt_sha256", "knowledge"})
        self.assertEqual(set(event["payload"]["knowledge"]), {"height", "head_sha256"})
        self.assertNotIn(CASE["holder"], str(event))

    def test_concurrent_retry_of_same_signed_event(self):
        policy = normalize_policy(POLICIES[2])
        from educreditlab.ledger import policy_descriptor
        event = self.lab.ledger.event("policy", policy["receiver"], policy_descriptor(policy))
        self.lab.ledger.cache(digest(policy), "policy", policy)
        with ThreadPoolExecutor(max_workers=3) as pool:
            blocks = list(pool.map(self.lab.ledger.append, [event] * 3))
        self.assertEqual(len({block["hash"] for block in blocks}), 1)
        self.assertEqual(verify_chain(self.lab.ledger.manifest, self.lab.ledger.prefix(),
                                      self.lab.ledger.fingerprint)["height"], 2)

    def test_retry_after_replica_sync_interruption(self):
        # A committed block remains canonical when one replica lags after certification.
        from unittest.mock import patch
        sync = self.lab.ledger._sync

        def transient(name, prefix, proposal=None):
            if proposal is None and name == self.peers[0]:
                raise LabError("transient storage failure")
            return sync(name, prefix, proposal)

        with patch.object(self.lab.ledger, "_sync", side_effect=transient):
            event = self.record()
        self.assertEqual(len(self.lab.ledger.prefix()), 2)
        self.assertEqual(len(self.lab.ledger.prefix(self.peers[0])), 1)
        self.lab.ledger.sync()
        self.assertTrue(verify_bundle(self.lab.bundle(event["receipt_sha256"], self.peers[0]),
                                      self.lab.ledger.fingerprint)["replayed"])

