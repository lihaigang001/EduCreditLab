"""Integrity, retry and upgrade regressions reproduced against the v1.0.0 release."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, closing
from copy import deepcopy
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from educreditlab.cli import status
from educreditlab.lab import Lab, bundled_data, verify_bundle, verify_review
from educreditlab.ledger import policy_descriptor
from educreditlab.model import LabError, canonical, code, digest, loads, read_json, write_json
from educreditlab.server import _handler

TRANSCRIPT = bundled_data("cases.json")[0]["transcript"]
HISTORICAL = bundled_data("policies.json")[0]
TARGET = ("uc-irvine", "cse-bs", "2023-06-15")
PROOF_FIXTURE = Path(__file__).parent / "fixtures" / "v100-review-bundle.json"
PROOF_TRUST = (Path(__file__).parent / "fixtures" / "v100-trust-fingerprint.txt").read_text().strip()


@contextmanager
def workbench(lab):
    with ThreadingHTTPServer(("127.0.0.1", 0), _handler(lab)) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def send(path, document=None, **headers):
            data = None if document is None else (document if isinstance(document, bytes)
                                                     else json.dumps(document).encode("utf-8"))
            url = f"http://127.0.0.1:{server.server_port}{path}"
            request = Request(url, data=data, headers={"Content-Type": "application/json", **headers})
            try:
                with urlopen(request, timeout=8) as response:
                    return response.status, json.load(response)
            except HTTPError as error:
                with error:
                    return error.code, json.load(error)

        try:
            yield send
        finally:
            server.shutdown()
            thread.join()


class AuditRegressions(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.lab = Lab(self.root / "ledger")
        self.lab.publish(HISTORICAL)

    def test_repeated_http_submission_has_one_receipt(self):
        body = {"transcript": TRANSCRIPT,
                "target": dict(zip(("receiver", "programme", "as_of"), TARGET))}
        with workbench(self.lab) as send:
            first = send("/api/record", body)
            second = send("/api/record", body)
        self.assertEqual(first, second)
        self.assertEqual(len(self.lab.ledger.prefix()), 2)

    def test_web_retry_after_restart_and_quorum_recovery(self):
        with self.assertRaisesRegex(LabError, "quorum unavailable"):
            self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET, available=("peer-b", "peer-c"))
        self.assertEqual(self.lab.ledger.pending_height(), 2)
        restarted = Lab.open(self.lab.ledger.directory)
        restarted.ledger.sync()
        receipt = restarted.issue_workbench_receipt(TRANSCRIPT, *TARGET)
        self.assertEqual(receipt["height"], 2)
        self.assertIsNone(restarted.ledger.pending_height())
        self.assertEqual(len(restarted.ledger.prefix()), 2)

    def test_concurrent_equivalent_web_requests_share_one_receipt(self):
        copy = deepcopy(TRANSCRIPT)
        copy["attempts"].reverse()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(self.lab.issue_workbench_receipt, candidate, *TARGET)
                       for candidate in (copy, TRANSCRIPT)]
            results = [job.result(timeout=15) for job in futures]
        self.assertEqual(results[0], results[1])
        self.assertEqual(len(self.lab.ledger.prefix()), 2)

    def test_different_transcript_can_issue_another_receipt(self):
        first = self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET)
        revised = deepcopy(TRANSCRIPT)
        revised["attempts"][0]["grade"] = "A"
        second = self.lab.issue_workbench_receipt(revised, *TARGET)
        self.assertNotEqual(first["receipt_sha256"], second["receipt_sha256"])

    def test_http_replay_selects_available_valid_replica(self):
        saved = self.lab.record(self.lab.sign_transcript(TRANSCRIPT), *TARGET,
                                available=("peer-b", "peer-c", "peer-d"))
        self.assertEqual(status(self.lab)["replica_status"]["peer-a"]["state"], "behind")
        with workbench(self.lab) as send:
            code_out, replay = send("/api/replay", {"receipt": saved["receipt_sha256"]})
        self.assertEqual(code_out, 200)
        self.assertEqual(replay["replica"], "peer-b")
        self.assertEqual(replay["decision"]["recognized_units"], 1600)

    def test_status_and_replay_bypass_a_damaged_replica(self):
        saved = self.lab.record(self.lab.sign_transcript(TRANSCRIPT), *TARGET)
        with closing(sqlite3.connect(self.lab.ledger.directory / "peer-a.sqlite3")) as conn, conn:
            conn.execute("UPDATE blocks SET hash=? WHERE height=2", ("0" * 64,))
        self.assertEqual(status(self.lab)["replica_status"]["peer-a"]["state"], "invalid")
        reply = self.lab.replay_from_replica(saved["receipt_sha256"])
        self.assertEqual(reply["replica"], "peer-b")

    def test_checked_policy_lookup_refuses_incomplete_certificate(self):
        self.assertEqual(self.lab.preview(TRANSCRIPT, *TARGET)["recognized_units"], 1600)
        with closing(sqlite3.connect(self.lab.ledger.path)) as conn, conn:
            source = conn.execute("SELECT document FROM blocks WHERE height=1").fetchone()[0]
            block = loads(source)
            block["votes"].clear()
            conn.execute("UPDATE blocks SET document=? WHERE height=1", (canonical(block),))
        with self.assertRaisesRegex(LabError, "Validator quorum"):
            self.lab.preview(TRANSCRIPT, *TARGET)
        with self.assertRaisesRegex(LabError, "Validator quorum"):
            self.lab.ledger.sync()

    def test_catalog_validates_local_policy_against_registry(self):
        altered = deepcopy(HISTORICAL)
        altered["rules"][0]["units"] += 100
        with closing(sqlite3.connect(self.lab.ledger.path)) as conn, conn:
            conn.execute("UPDATE artifacts SET document=? WHERE kind='policy'", (canonical(altered),))
        with workbench(self.lab) as send:
            outcome, body = send("/api/catalog")
        self.assertEqual(outcome, 400)
        self.assertIn("registered commitment", body["error"])

    def test_rejected_policy_leaves_no_artifact_or_proposal(self):
        overlap = deepcopy(HISTORICAL)
        overlap["version"] = "failed-publication"
        with self.assertRaisesRegex(LabError, "Overlapping"):
            self.lab.publish(overlap)
        with closing(sqlite3.connect(self.lab.ledger.path)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0], 1)
        self.assertIsNone(self.lab.ledger.pending_height())

    def test_artifact_must_match_its_pending_publication(self):
        policy = bundled_data("policies.json")[1]
        event = self.lab.ledger.event("policy", policy["receiver"], policy_descriptor(policy))
        with self.assertRaisesRegex(LabError, "match the signed event commitment"):
            self.lab.ledger.append(event, artifact=HISTORICAL)
        self.assertIsNone(self.lab.ledger.pending_height())
        self.assertEqual(len(self.lab.ledger.prefix()), 1)

    def test_damaged_vote_can_be_repaired_for_the_same_block(self):
        signed = self.lab.sign_transcript(TRANSCRIPT)
        with self.assertRaisesRegex(LabError, "quorum unavailable"):
            self.lab.record(signed, *TARGET, nonce="13" * 32, available=("peer-a", "peer-b"))
        with closing(sqlite3.connect(self.lab.ledger.path)) as conn:
            proposal = loads(conn.execute("SELECT core FROM pending").fetchone()[0])
        self.lab.ledger._sync("peer-a", self.lab.ledger.prefix(), proposal)
        with closing(sqlite3.connect(self.lab.ledger.directory / "peer-a.sqlite3")) as conn, conn:
            conn.execute("UPDATE votes SET signature=? WHERE height=2", ("unreadable vote",))
        self.lab.ledger.sync()
        header = self.lab.ledger.prefix()[-1]
        self.assertEqual(header["hash"], digest(proposal))
        self.assertEqual(len(header["votes"]), 4)

    def test_browser_accepts_valid_original_bytes_and_rejects_bad_imports(self):
        with workbench(self.lab) as send:
            self.assertEqual(send("/api/transcript", canonical(TRANSCRIPT))[0], 200)
            malformed = deepcopy(TRANSCRIPT)
            malformed["attempts"] = [None]
            self.assertEqual(send("/api/transcript", malformed)[0], 400)
            duplicate_schema = b'{"schema":1,"schema":1,"issuer":"glendale-cc","holder":"x","attempts":[]}'
            self.assertEqual(send("/api/transcript", duplicate_schema)[0], 400)

    def test_anchor_proof_verifies_without_the_off_chain_artifact(self):
        saved = self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET)
        receipt = saved["receipt_sha256"]
        with closing(sqlite3.connect(self.lab.ledger.path)) as conn, conn:
            conn.execute("DELETE FROM artifacts WHERE commitment=?", (receipt,))
        with self.assertRaisesRegex(LabError, "off-chain artifact"):
            self.lab.bundle(receipt)
        with workbench(self.lab) as send:
            outcome, anchor = send(f"/api/bundle?receipt={receipt}&mode=anchor")
            verified_status, verified = send("/api/verify-file", canonical(anchor),
                                            **{"X-EduCredit-Trust": self.lab.ledger.fingerprint})
        self.assertEqual(outcome, 200)
        self.assertEqual(verified_status, 200)
        self.assertTrue(verified["anchor_verified"])
        self.assertFalse(verified["replayed"])
        for confidential in ("transcript", "decision", "recognized_units", "attempts"):
            self.assertNotIn(confidential, canonical(anchor).decode("utf-8"))

    def test_resume_seed_preserves_existing_network_identity(self):
        before = self.lab.ledger.fingerprint
        restored = Lab.workbench(self.lab.ledger.directory, seed=True)
        self.assertEqual(restored.ledger.fingerprint, before)
        self.assertEqual(len(restored.descriptors()), 3)
        self.assertEqual(len(Lab.workbench(restored.ledger.directory, seed=True).descriptors()), 3)

    def test_empty_file_from_interrupted_initialization_is_recoverable(self):
        workspace = self.root / "interrupted"
        workspace.mkdir()
        (workspace / "ledger.sqlite3").touch()
        self.assertEqual(len(Lab.workbench(workspace).descriptors()), 3)

    def test_lost_coordinator_requires_restore_of_existing_network(self):
        self.lab.ledger.path.unlink()
        with self.assertRaisesRegex(LabError, "Restore a consistent workspace backup"):
            Lab.workbench(self.lab.ledger.directory)
        self.assertFalse(self.lab.ledger.path.exists())

    def test_atomic_export_preserves_a_previous_document_when_replace_fails(self):
        path = self.root / "export.json"
        write_json(path, {"edition": 1})
        with patch("educreditlab.model.os.replace", side_effect=OSError("write unavailable")):
            with self.assertRaises(OSError):
                write_json(path, {"edition": 2})
        self.assertEqual(read_json(path), {"edition": 1})
        self.assertFalse(any(self.root.glob(".export.json.*")))

    def test_long_unicode_course_code_is_rejected_before_storage(self):
        with self.assertRaisesRegex(LabError, "normalized course code"):
            code("ß" * 50)

    def test_v100_portable_receipt_replays_with_the_original_fingerprint(self):
        result = verify_bundle(read_json(PROOF_FIXTURE), PROOF_TRUST)
        self.assertTrue(result["replayed"])
        self.assertEqual(result["decision"]["recognized_units"], 1600)
        self.assertEqual(result["decision"]["method_version"], "1.0.0")

    def test_anchor_fingerprint_still_requires_independent_trust(self):
        result = self.lab.issue_workbench_receipt(TRANSCRIPT, *TARGET)
        anchor = self.lab.bundle(result["receipt_sha256"], anchor_only=True)
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            verify_review(anchor, "0" * 64)

