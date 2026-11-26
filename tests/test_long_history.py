import copy
from contextlib import redirect_stdout
from gzip import compress
from io import StringIO
from pathlib import Path
import sqlite3
import tempfile
import unittest

from educreditlab.cli import main, status
from educreditlab.lab import Lab, bundled_data, verify_review
from educreditlab.model import LabError, canonical, loads
from educreditlab.server import HistoryPages
from educreditlab.transport import decode_proof, gzip_proof, read_proof

CASE = bundled_data("cases.json")[0]["transcript"]
TARGET = ("uc-irvine", "cse-bs", "2023-06-15")


class LongHistoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.lab = Lab(self.root / "state", "central")
        self.lab.seed()
        self.earlier = self.record(1)
        self.later = self.record(2)
        self.trust = self.lab.ledger.fingerprint

    def record(self, number):
        signed = self.lab.sign_transcript(CASE, salt=f"{number:064x}")
        return self.lab.record(signed, *TARGET)["receipt_sha256"]

    def test_follows_old_page_without_gaps_after_an_append_and_refresh(self):
        pager = HistoryPages(self.lab)
        first = pager.page({"limit": ["2"]})
        self.assertEqual([b["height"] for b in first["blocks"]], [5, 4])
        page = first["page"]
        cursor = {"snapshot_height": [str(page["snapshot_height"])],
                  "snapshot_sha256": [page["snapshot_sha256"]],
                  "before_height": [str(page["next_before"])], "limit": ["2"]}
        self.record(3)
        older = pager.page(cursor)
        self.assertEqual([b["height"] for b in older["blocks"]], [3, 2])
        self.assertEqual(older["network"]["height"], 5)
        latest = pager.page({"limit": ["2"]})
        self.assertEqual([b["height"] for b in latest["blocks"]], [6, 5])
        # Reopen the fixed view from disk after the newer snapshot displaced it.
        self.assertEqual(pager.page(cursor)["blocks"], older["blocks"])
        cursor["before_height"] = ["2"]
        last = pager.page(cursor)
        self.assertEqual([b["height"] for b in last["blocks"]], [1])
        self.assertIsNone(last["page"]["next_before"])

    def test_incomplete_cursor_wrong_digest_and_unbounded_pages_are_rejected(self):
        pager = HistoryPages(self.lab)
        with self.assertRaisesRegex(LabError, "needs the snapshot"):
            pager.page({"before_height": ["4"]})
        with self.assertRaisesRegex(LabError, "snapshot is unavailable"):
            pager.page({"snapshot_height": ["5"], "snapshot_sha256": ["0" * 64], "before_height": ["4"]})
        with self.assertRaisesRegex(LabError, "page size"):
            pager.page({"limit": ["101"]})

    def test_upgrade_populates_index_without_rewriting_ledger_or_fingerprint(self):
        before = self.lab.ledger.prefix()
        with sqlite3.connect(self.lab.ledger.path) as conn:
            conn.execute("DROP TABLE receipt_index")
        reopened = Lab.open(self.lab.ledger.directory)
        self.assertEqual(reopened.ledger.prefix(), before)
        self.assertEqual(reopened.ledger.fingerprint, self.trust)
        with sqlite3.connect(reopened.ledger.path) as conn:
            self.assertEqual(conn.execute("SELECT height FROM receipt_index WHERE commitment=?", (self.earlier,)).fetchone(), (4,))

    def test_pending_receipt_adds_index_only_when_committed(self):
        lab = Lab(self.root / "quorum")
        lab.seed()
        signed = lab.sign_transcript(CASE)
        with self.assertRaisesRegex(LabError, "quorum"):
            lab.record(signed, *TARGET, available=("peer-a", "peer-b"))
        with sqlite3.connect(lab.ledger.path) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM receipt_index").fetchone(), (0,))
        lab.ledger.sync()
        with sqlite3.connect(lab.ledger.path) as conn:
            self.assertEqual(conn.execute("SELECT height FROM receipt_index").fetchall(), [(4,)])

    def test_incorrect_index_hint_uses_only_a_valid_receipt_event(self):
        with sqlite3.connect(self.lab.ledger.path) as conn:
            conn.execute("UPDATE receipt_index SET height=1 WHERE commitment=?", (self.earlier,))
        proof = self.lab.bundle(self.earlier)
        self.assertEqual(len(proof["chain"]), 4)
        self.assertEqual(verify_review(proof, self.trust)["receipt_sha256"], self.earlier)

    def test_old_replica_without_an_index_can_still_replay(self):
        peer = self.lab.ledger.directory / "authority.sqlite3"
        with sqlite3.connect(peer) as conn:
            conn.execute("DROP TABLE receipt_index")
        replay = self.lab.replay_from_replica(self.earlier)
        self.assertEqual(replay["height"], 4)
        self.assertEqual(replay["decision"]["recognized_units"], 1600)

    def damage_votes(self, path, height):
        with sqlite3.connect(path) as conn:
            document = loads(conn.execute("SELECT document FROM blocks WHERE height=?", (height,)).fetchone()[0])
            document["votes"]["authority"] = "0" * 128
            conn.execute("UPDATE blocks SET document=? WHERE height=?", (canonical(document), height))

    def test_earlier_receipt_stays_exportable_if_a_later_block_is_unreadable(self):
        self.damage_votes(self.lab.ledger.path, 5)
        proof = self.lab.bundle(self.earlier)
        self.assertEqual(verify_review(proof, self.trust)["height"], 4)
        with self.assertRaisesRegex(LabError, "vote signature"):
            self.lab.bundle(self.later)
        with self.assertRaisesRegex(LabError, "vote signature"):
            status(self.lab)

    def test_damaged_indexed_prefix_is_detected_on_export(self):
        self.damage_votes(self.lab.ledger.path, 2)
        with self.assertRaisesRegex(LabError, "vote signature"):
            self.lab.bundle(self.earlier)

    def test_replica_status_checks_divergent_bytes_even_after_a_valid_read(self):
        self.assertEqual(status(self.lab)["replica_status"]["authority"]["state"], "current")
        self.damage_votes(self.lab.ledger.directory / "authority.sqlite3", 3)
        self.assertEqual(status(self.lab)["replica_status"]["authority"]["state"], "invalid")

    def test_gzip_full_and_anchor_cli_round_trip(self):
        for scope in ([], ["--anchor-only"]):
            with self.subTest(scope=scope):
                filename = self.root / "proof.json.gz"
                output = StringIO()
                with redirect_stdout(output):
                    self.assertEqual(main(["--workspace", str(self.lab.ledger.directory), "bundle", self.earlier,
                                           *scope, "--out", str(filename)]), 0)
                    self.assertEqual(main(["verify", str(filename), "--trust", self.trust]), 0)
                self.assertEqual(read_proof(filename), self.lab.bundle(self.earlier, anchor_only=bool(scope)))

    def test_damaged_gzip_and_decoded_body_limit_are_checked(self):
        packet = gzip_proof(self.lab.bundle(self.earlier))
        with self.assertRaisesRegex(LabError, "damaged or incomplete"):
            decode_proof(packet[:-4])
        with self.assertRaisesRegex(LabError, "decompressed proof exceeds"):
            decode_proof(compress(b" " * 256 + b"{}"), max_content=64)

    def test_gzip_verifier_still_checks_the_full_prefix_and_trust(self):
        original = self.lab.bundle(self.later)
        encoded = gzip_proof(original)
        self.assertEqual(verify_review(decode_proof(encoded), self.trust), verify_review(original, self.trust))
        with self.assertRaisesRegex(LabError, "trusted fingerprint"):
            verify_review(decode_proof(encoded), "0" * 64)
        changed = copy.deepcopy(original)
        changed["chain"][1]["votes"]["authority"] = "0" * 128
        with self.assertRaisesRegex(LabError, "vote signature"):
            verify_review(decode_proof(gzip_proof(changed)), self.trust)


if __name__ == "__main__":
    unittest.main()
