"""Loopback-only research workbench serving the same application API as the CLI."""

from __future__ import annotations

from email.parser import BytesParser
from email.policy import default as multipart_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from threading import Lock
from urllib.parse import parse_qs, urlsplit
import re
import sqlite3

from .cli import _status_from_verified_prefix
from .lab import DEMO_ACTORS, DEMO_AMENDMENT, bundled_data, verify_review
from .model import (LabError, canonical, digest, fields, hex_digest, integer, loads, normalize_policy,
                    normalize_transcript, sequence)
from .policy_divergence import verify_policy_divergence
from .policy_history import verify_policy_history, verify_review_at_revision
from .policy_resolution import verify_policy_resolution
from .resolution_checkpoint import verify_resolution_batch, verify_resolution_witness
from .resolution_history import verify_resolution_history
from .review_attestation import verify_attestation
from .review_quorum import verify_quorum
from .temporal import ZERO, block_timestamp
from .transport import GZIP_MIME, decode_proof, gzip_proof

ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8")}
JSON = "application/json; charset=utf-8"
MAX_BODY = 2 * 1024 * 1024
MAX_PROOF_BODY = 16 * 1024 * 1024
MAX_PROOF_EXPANDED = 64 * 1024 * 1024
HISTORY_PAGE_SIZE = 40


def _revision_review_files(headers, body):
    content_type = headers.get("Content-Type", "")
    if (headers.get_content_type() != "multipart/form-data" or not content_type.isascii()
            or "\r" in content_type or "\n" in content_type):
        raise LabError("Upload a rule history and a revision-bound joint attestation")
    prefix = ("Content-Type: " + content_type + "\r\nMIME-Version: 1.0\r\n\r\n").encode("ascii")
    try:
        message = BytesParser(policy=multipart_policy).parsebytes(prefix + body)
    except (ValueError, RecursionError) as exc:
        raise LabError("Invalid revision review upload") from exc
    parts = list(message.iter_parts())
    if message.defects or len(parts) != 2:
        raise LabError("Upload exactly one rule history and one joint attestation")
    documents = {}
    for part in parts:
        name = part.get_param("name", header="content-disposition")
        if (part.get_content_disposition() != "form-data" or part.defects or part.is_multipart()
                or part.get("Content-Transfer-Encoding") is not None
                or name not in ("history", "bundle") or name in documents):
            raise LabError("Upload exactly one rule history and one joint attestation")
        documents[name] = decode_proof(part.get_payload(decode=True), max_content=MAX_PROOF_EXPANDED)
    return documents["history"], documents["bundle"]


def _catalog(lab):
    chain = lab.ledger.prefix()
    policies = []
    for entry in lab.policy_history(chain):
        descriptor = entry["policy"]
        policy = lab.registered_policy(descriptor)
        policies.append({
            **descriptor, "kind": policy["kind"], "provenance": policy["provenance"],
            "rules": policy["rules"], "unit": policy["unit"], "cap": policy["cap"],
            "group_caps": policy["group_caps"], "reuse": policy["reuse"],
            "registered_height": entry["height"], "registered_at": entry["recorded_at"],
            "time_basis": entry["time_basis"],
            "registered_block_sha256": entry["block_sha256"], "supersedes": entry["supersedes"],
            "revision_reason": entry["reason"],
        })
    demo = None
    if not lab.ledger.managed and tuple(lab.ledger.manifest["actors"]) == DEMO_ACTORS:
        parent = digest(normalize_policy(bundled_data("policies.json")[0]))
        revision = digest(normalize_policy(bundled_data(DEMO_AMENDMENT)))
        if any(policy["policy_sha256"] == parent for policy in policies):
            demo = {"parent": parent, "revision": revision, "date": "2023-06-15"}
    return {"policies": policies, "cases": bundled_data("cases.json"),
            "network": _status_from_verified_prefix(lab, chain),
            "demo_amendment": demo}


def _query(query, *, knowledge=True):
    extra = ("known_height", "known_at") if knowledge and isinstance(query, dict) else ()
    suffix = "".join(" " + key for key in extra if key in query)
    return fields(query, "receiver programme as_of" + suffix, "target selection")


def _page_integer(value, name, low, high):
    if not value or not value.isascii() or not value.isdecimal() or len(value) > 7:
        raise LabError(f"{name} must be an integer")
    return integer(int(value), name, low, high)


class HistoryPages:
    """Keep one verified, explicitly identified snapshot for stable browsing."""

    def __init__(self, lab):
        self.lab = lab
        self._snapshot = None
        self._lock = Lock()

    def _verified_snapshot(self, anchor):
        if anchor is not None:
            with self._lock:
                cached = self._snapshot
            if cached is not None and cached[0] == anchor:
                return cached
        chain = self.lab.ledger.prefix(through=anchor[0] if anchor is not None else None)
        actual = (len(chain), chain[-1]["hash"] if chain else ZERO)
        if anchor is not None and actual != anchor:
            raise LabError("The history snapshot is unavailable. Refresh to the latest committed view.")
        snapshot = (actual, chain, _status_from_verified_prefix(self.lab, chain))
        with self._lock:
            self._snapshot = snapshot
        return snapshot

    def page(self, query):
        allowed = {"snapshot_height", "snapshot_sha256", "before_height", "limit"}
        if set(query) - allowed or any(len(values) != 1 for values in query.values()):
            raise LabError("Invalid history paging parameters")
        fields_in_query = {name for name in allowed if name in query} - {"limit"}
        anchor = None
        if fields_in_query:
            if fields_in_query != allowed - {"limit"}:
                raise LabError("History paging needs the snapshot height, digest and before height")
            anchor = (_page_integer(query["snapshot_height"][0], "snapshot height", 0, 1_000_000),
                      hex_digest(query["snapshot_sha256"][0], "snapshot digest"))
        limit = _page_integer(query.get("limit", [str(HISTORY_PAGE_SIZE)])[0], "page size", 1, 100)
        (height, digest_value), chain, network = self._verified_snapshot(anchor)
        end = (_page_integer(query["before_height"][0], "before height", 1, height + 1) - 1
               if anchor is not None else height)
        start = max(end - limit, 0)
        blocks = [{"height": block["core"]["height"], "hash": block["hash"],
                   "recorded_at": block_timestamp(block)[0], "time_basis": block_timestamp(block)[1],
                   "votes": sorted(block["votes"]), **block["core"]["event"]["body"]}
                  for block in reversed(chain[start:end])]
        return {"network": network, "blocks": blocks, "page": {
            "snapshot_height": height, "snapshot_sha256": digest_value,
            "next_before": start + 1 if start else None}}


def _handler(lab):
    pages = HistoryPages(lab)

    class Handler(BaseHTTPRequestHandler):
        server_version = "EduCreditLab"

        def _response(self, code, content, mime=JSON, download=None):
            data = content if isinstance(content, bytes) else canonical(content)
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; "
                             "form-action 'self'; frame-ancestors 'none'; object-src 'none'")
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            self.end_headers()
            self.wfile.write(data)

        def _allowed(self, post=False):
            port = self.server.server_address[1]
            hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
            if self.headers.get("Host") not in hosts:
                return False
            origin = self.headers.get("Origin")
            return (not post or origin is None
                    or origin in {f"http://{host}" for host in hosts})

        def do_GET(self):
            if not self._allowed():
                self._response(403, {"error": "Use the workbench's local address"})
                return
            url = urlsplit(self.path)
            try:
                if url.path in ASSETS:
                    name, mime = ASSETS[url.path]
                    self._response(200, files("educreditlab").joinpath("web", name).read_bytes(), mime)
                elif url.path == "/api/catalog":
                    self._response(200, _catalog(lab))
                elif url.path == "/api/history":
                    self._response(200, pages.page(parse_qs(url.query, keep_blank_values=True)))
                elif url.path == "/api/bundle":
                    query = parse_qs(url.query)
                    mode = query.get("mode", ["full"])[0]
                    if mode not in {"full", "anchor"}:
                        raise LabError("Expected full or anchor export mode")
                    encoding = query.get("encoding", ["json"])[0]
                    if encoding not in {"json", "gzip"}:
                        raise LabError("Expected json or gzip export encoding")
                    bundle = lab.bundle(query.get("receipt", [None])[0], query.get("replica", [None])[0],
                                        anchor_only=mode == "anchor")
                    name = "educreditlab-anchor.json" if mode == "anchor" else "educreditlab-review-bundle.json"
                    if encoding == "gzip":
                        self._response(200, gzip_proof(bundle), GZIP_MIME, download=name + ".gz")
                    else:
                        self._response(200, bundle, download=name)
                else:
                    self._response(404, {"error": "Unknown path"})
            except (LabError, OSError, sqlite3.Error) as exc:
                self._response(400, {"error": str(exc)})

        def _body_bytes(self, maximum):
            length = self.headers.get("Content-Length", "")
            if not length.isascii() or not length.isdecimal() or len(length) > 8:
                raise LabError("A valid Content-Length is required")
            integer(int(length), "request bytes", 1, maximum)
            data = self.rfile.read(int(length))
            if len(data) != int(length):
                raise LabError("The request body is incomplete")
            return data

        def _body(self):
            if self.headers.get_content_type() != JSON.split(";")[0]:
                raise LabError("Use application/json")
            return loads(self._body_bytes(MAX_BODY))

        def do_POST(self):
            if not self._allowed(post=True):
                self._response(403, {"error": "Cross-origin requests are unavailable"})
                return
            try:
                if self.path == "/api/verify-revision-review":
                    number = self.headers.get("X-EduCredit-Review-Revision")
                    if number is not None and not re.fullmatch(r"[1-9][0-9]{0,6}", number):
                        raise LabError("Select a positive reviewer policy revision number")
                    history, bundle = _revision_review_files(self.headers, self._body_bytes(MAX_PROOF_BODY))
                    result = verify_review_at_revision(
                        history, bundle, self.headers.get("X-EduCredit-Initial-Policy"),
                        self.headers.get("X-EduCredit-Revision"),
                        revision=None if number is None else int(number), require_revision_binding=True)
                    self._response(200, result)
                    return
                if self.path in ("/api/verify-file", "/api/verify-attestation", "/api/verify-quorum",
                                 "/api/verify-policy-history", "/api/verify-policy-divergence",
                                 "/api/verify-policy-resolution", "/api/verify-resolution-history",
                                 "/api/verify-resolution-checkpoint", "/api/verify-resolution-checkpoint-batch"):
                    mime = self.headers.get_content_type()
                    if mime not in {JSON.split(";")[0], GZIP_MIME}:
                        raise LabError("Use a JSON or gzip file")
                    proof = decode_proof(self._body_bytes(MAX_PROOF_BODY), compressed=mime == GZIP_MIME,
                                         max_content=MAX_PROOF_EXPANDED)
                    if self.path == "/api/verify-policy-history":
                        result = verify_policy_history(proof, self.headers.get("X-EduCredit-Initial-Policy"),
                                                       self.headers.get("X-EduCredit-Revision"))
                    elif self.path == "/api/verify-policy-divergence":
                        result = verify_policy_divergence(proof, self.headers.get("X-EduCredit-Initial-Policy"))
                    elif self.path == "/api/verify-policy-resolution":
                        result = verify_policy_resolution(proof, self.headers.get("X-EduCredit-Authority"),
                                                          self.headers.get("X-EduCredit-Decision"))
                    elif self.path == "/api/verify-resolution-history":
                        result = verify_resolution_history(proof, self.headers.get("X-EduCredit-Authority"),
                                                           self.headers.get("X-EduCredit-Publication"))
                    elif self.path == "/api/verify-resolution-checkpoint":
                        number = self.headers.get("X-EduCredit-Publication-Number")
                        if number is not None and not re.fullmatch(r"[1-9][0-9]{0,6}", number):
                            raise LabError("Select a positive publication number")
                        result = verify_resolution_witness(
                            proof, self.headers.get("X-EduCredit-Publication-Checkpoint"),
                            number=None if number is None else int(number))
                    elif self.path == "/api/verify-resolution-checkpoint-batch":
                        numbers = self.headers.get("X-EduCredit-Publication-Numbers", "").split(",")
                        if any(not re.fullmatch(r"[1-9][0-9]{0,6}", item) for item in numbers):
                            raise LabError("Specify the expected publication numbers")
                        result = verify_resolution_batch(
                            proof, self.headers.get("X-EduCredit-Publication-Checkpoint"), numbers=[int(item) for item in numbers])
                    elif self.path == "/api/verify-quorum":
                        result = verify_quorum(proof, self.headers.get("X-EduCredit-Policy"))
                    elif self.path == "/api/verify-attestation":
                        result = verify_attestation(proof, self.headers.get("X-EduCredit-Reviewer"),
                                                    self.headers.get("X-EduCredit-Plan"))
                    else:
                        result = verify_review(proof, self.headers.get("X-EduCredit-Trust"),
                                               trusted_checkpoint=self.headers.get("X-EduCredit-Checkpoint"),
                                               trusted_plan=self.headers.get("X-EduCredit-Plan"))
                    self._response(200, result)
                    return
                body = self._body()
                if self.path == "/api/preview":
                    fields(body, "transcript targets", "preview request")
                    transcript = normalize_transcript(body["transcript"])
                    targets = [_query(target) for target in sequence(body["targets"], "targets", 1, 3)]
                    chain = lab.ledger.prefix()
                    results = [lab._assess_from_verified_prefix(chain, transcript, **target) for target in targets]
                    self._response(200, {"results": [item["decision"] for item in results],
                                         "views": [item["policy_view"] for item in results]})
                elif self.path == "/api/compare-policy":
                    fields(body, "transcript target before_height after_height", "revision comparison request")
                    result = lab.compare(body["transcript"], **_query(body["target"], knowledge=False),
                                         before_height=body["before_height"], after_height=body["after_height"])
                    self._response(200, result)
                elif self.path == "/api/demo-amendment":
                    fields(body, "", "demonstration amendment request")
                    block = lab.seed_amendment()
                    self._response(201, {"height": block["core"]["height"], "sha256": block["hash"]})
                elif self.path == "/api/record":
                    fields(body, "transcript target", "receipt request")
                    result = lab.issue_workbench_receipt(body["transcript"], **_query(body["target"]))
                    self._response(201, result)
                elif self.path == "/api/transcript":
                    self._response(200, {"transcript": normalize_transcript(body)})
                elif self.path == "/api/replay":
                    fields(body, "receipt", "local replay request")
                    review = lab.replay_from_replica(body["receipt"])
                    self._response(200, review)
                elif self.path == "/api/verify":
                    has_checkpoint = isinstance(body, dict) and "checkpoint_fingerprint" in body
                    fields(body, "bundle fingerprint" + (" checkpoint_fingerprint" if has_checkpoint else ""),
                           "offline verification request")
                    self._response(200, verify_review(body["bundle"], body["fingerprint"],
                                                      trusted_checkpoint=body.get("checkpoint_fingerprint")))
                else:
                    self._response(404, {"error": "Unknown path"})
            except (LabError, OSError, sqlite3.Error) as exc:
                self._response(400, {"error": str(exc)})

        def log_message(self, format, *args):
            pass

    return Handler


def serve(lab, port):
    integer(port, "port", 1, 65535)
    with ThreadingHTTPServer(("127.0.0.1", port), _handler(lab)) as server:
        print(f"EduCreditLab workbench: http://127.0.0.1:{port}", flush=True)
        server.serve_forever()

