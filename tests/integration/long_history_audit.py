"""Generate certified synthetic history and measure normal EduCreditLab read entry points."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from statistics import median
from threading import Thread
from time import perf_counter
from urllib.parse import urlencode
import json
import platform
import sqlite3

from educreditlab import __version__
from educreditlab.keys import sign_local
from educreditlab.lab import Lab, bundled_data, verify_review
from educreditlab.ledger import _db, _finalization_message, _insert
from educreditlab.model import canonical, digest, normalize_policy, read_json, write_json
from educreditlab.server import MAX_PROOF_BODY, _handler
from educreditlab.solver import evaluate


def build(directory, height):
    root = Path(directory)
    root.mkdir(mode=0o700)
    lab = Lab(root / "state")
    lab.seed()
    ledger = lab.ledger
    prefix = ledger.prefix()
    policy = normalize_policy(bundled_data("policies.json")[0])
    transcript = bundled_data("cases.json")[0]["transcript"]
    signed = lab.sign_transcript(transcript, salt="2" * 64)
    decision = evaluate(policy, transcript, "2023-06-15")
    decision_ref = decision["policy_sha256"]
    first_head = prefix[-1]["hash"]
    network = ledger.manifest["network"]
    reply = {"network": network, "schema": 1, "transcript_commitment": digest(signed), "decision": decision}
    signers = list(ledger.manifest["validators"])[:3]
    validator_keys = {name: ledger.keys["validators"][name] for name in signers}
    latest = datetime.fromisoformat(prefix[-1]["finalization"]["recorded_at"])

    def records():
        previous = first_head
        for index in range(4, height + 1):
            stamp = (latest + timedelta(milliseconds=index)).astimezone(timezone.utc).isoformat()
            body = {**reply, "salt": f"{index:064x}"}
            receipt = {"body": body, "signature": ledger.sign_as(policy["receiver"], "receipt", body)}
            commitment = digest(receipt)
            payload = {"policy_sha256": decision_ref, "receipt_sha256": commitment,
                       "knowledge": {"height": 3, "head_sha256": first_head}}
            event = ledger.event("receipt", policy["receiver"], payload)
            core = {"network": network, "height": index, "previous": previous,
                    "recorded_at": stamp, "event": event, "format": 2}
            previous = digest(core)
            block = {"core": core, "hash": previous,
                     "votes": {name: sign_local(key, "vote", core) for name, key in validator_keys.items()}}
            message = _finalization_message(block, stamp)
            block["finalization"] = {"recorded_at": stamp, "votes": {
                name: sign_local(key, "finalization", message) for name, key in validator_keys.items()}}
            artifact = {"policy": policy, "transcript": signed, "receipt": receipt}
            yield block, commitment, artifact

    with _db(ledger.path, write=True) as conn:
        for block, commitment, evidence in records():
            if __version__ == "1.3.0":
                _insert(conn, block)
            else:
                _insert(conn, block, receipt_index=True)
            ledger._cache(conn, commitment, "receipt", evidence)
            if block["core"]["height"] == 4:
                early = commitment
    with _db(ledger.path) as source:
        rows = source.execute("SELECT height, hash, document FROM blocks WHERE height>3 ORDER BY height").fetchall()
    for name in ledger.manifest["validators"]:
        with _db(ledger.directory / f"{name}.sqlite3", write=True) as replica:
            replica.executemany("INSERT INTO blocks VALUES (?, ?, ?)", rows)
    write_json(root / "fixture.json", {"height": height, "early_receipt_sha256": early,
                                      "latest_receipt_sha256": commitment, "manifest_sha256": ledger.fingerprint,
                                      "head_sha256": block["hash"], "synthetic": True})
    print(f"Prepared {height} signed blocks and four replica copies in {root.name}.", flush=True)


def measure(workspace, repeats, output, skip_large_proof=False):
    directory = Path(workspace)
    fixture = read_json(directory / "fixture.json")
    lab = Lab.open(directory / "state")
    trust = lab.ledger.fingerprint
    assert trust == fixture["manifest_sha256"]
    early = fixture["early_receipt_sha256"]
    latest = fixture["latest_receipt_sha256"]
    measurements = {"version": __version__, "fixture": fixture, "samples": {},
                    "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                    "host": platform.machine(), "scope": "local four-validator consortium"}

    def timed(metric, fn, count=1):
        samples = []
        for _ in range(count):
            before = perf_counter()
            value = fn()
            samples.append(round((perf_counter() - before) * 1000, 4))
        measurements["samples"][metric] = {"ms": samples, "median_ms": median(samples)}
        print(f"{__version__} #{fixture['height']} {metric}: {samples}", flush=True)
        return value

    with ThreadingHTTPServer(("127.0.0.1", 0), _handler(lab)) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        try:
            def request(path, data=None, headers=None):
                with_client = HTTPConnection("127.0.0.1", server.server_port, timeout=150)
                try:
                    with_client.request("GET" if data is None else "POST", path, body=data, headers=headers or {})
                    reply = with_client.getresponse()
                    return reply.status, reply.read()
                finally:
                    with_client.close()

            code, raw = timed("initial_history", lambda: request("/api/history"))
            assert code == 200
            page = json.loads(raw)
            assert page["network"]["head_sha256"] == fixture["head_sha256"]
            measurements["history_bytes"] = len(raw)
            measurements["history_returned_blocks"] = len(page["blocks"])
            if "page" in page:
                token = page["page"]
                url = "/api/history?" + urlencode({"snapshot_height": token["snapshot_height"],
                                                     "snapshot_sha256": token["snapshot_sha256"],
                                                     "before_height": token["next_before"]})
                code, raw = timed("older_page", lambda: request(url), repeats)
                assert code == 200 and json.loads(raw)["blocks"][0]["height"] == token["next_before"] - 1
            else:
                code, _ = timed("repeat_full_history", lambda: request("/api/history"), repeats)
                assert code == 200
            result = timed("early_full_export", lambda: lab.bundle(early), repeats)
            assert len(result["chain"]) == 4 and result["receipt"]["body"]["decision"]["recognized_units"] == 1600
            if not skip_large_proof:
                raw_path = "/api/bundle?receipt=" + latest
                code, proof = timed("latest_raw_download", lambda: request(raw_path))
                assert code == 200
                measurements["json_proof_bytes"] = len(proof)
                headers = {"Content-Type": "application/json", "X-EduCredit-Trust": trust}
                upload = proof
                if len(proof) > MAX_PROOF_BODY:
                    # The server rejects the advertised length before it reads the body.
                    headers["Content-Length"] = str(len(proof))
                    upload = b""
                status, web_report = timed("raw_browser_endpoint", lambda: request("/api/verify-file", upload, headers))
                measurements["raw_verify_http_status"] = status
                offline = timed("offline_json_full_verify", lambda: verify_review(json.loads(proof), trust))
                assert offline["replayed"] and offline["decision"]["recognized_units"] == 1600
                if "page" in page:
                    code, compressed = timed("latest_gzip_download", lambda: request(raw_path + "&encoding=gzip"))
                    assert code == 200
                    measurements["gzip_proof_bytes"] = len(compressed)
                    code, web_report = timed("gzip_browser_endpoint", lambda: request("/api/verify-file", compressed,
                        {"Content-Type": "application/gzip", "X-EduCredit-Trust": trust}))
                    assert code == 200 and json.loads(web_report)["replayed"]
                    measurements["gzip_verify_http_status"] = code
                    from educreditlab.transport import decode_proof
                    packed_check = timed("offline_gzip_full_verify", lambda: verify_review(decode_proof(compressed), trust))
                    assert packed_check == offline
                    (directory / "browser-full-proof.json.gz").write_bytes(compressed)
                measurements["replayed_units_centi"] = offline["decision"]["recognized_units"]
        finally:
            server.shutdown()
            thread.join()
    write_json(output, measurements)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fixture = sub.add_parser("build")
    fixture.add_argument("directory")
    fixture.add_argument("--height", type=int, required=True)
    check = sub.add_parser("measure")
    check.add_argument("directory")
    check.add_argument("--repeats", type=int, default=3)
    check.add_argument("--out", required=True)
    check.add_argument("--skip-large-proof", action="store_true")
    args = parser.parse_args()
    if args.command == "build":
        if not 4 <= args.height <= 100_000:
            parser.error("height must be between 4 and 100000")
        build(args.directory, args.height)
    else:
        if args.repeats < 1:
            parser.error("repeats must be positive")
        measure(args.directory, args.repeats, args.out, args.skip_large_proof)


if __name__ == "__main__":
    main()
