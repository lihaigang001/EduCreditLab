"""A local permissioned ledger with durable votes and independently checked proofs.

The reference network uses one coordinator, fixed membership and separate SQLite
replicas on one host. The same event format also runs over a single signer.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
import sqlite3

from .keys import KeyRegistry, local_keypair, sign_local as sign, verify
from .model import LabError, canonical, digest, fields, hex_digest, ident, integer, loads
from .temporal import POLICY_EVENTS, ZERO, PolicyHistory

MODES = {"central": (("authority",), 1),
         "consortium": (("peer-a", "peer-b", "peer-c", "peer-d"), 3)}


def _key_map(keys, field):
    if not isinstance(keys, dict) or not keys:
        raise LabError(f"{field} must be a nonempty key map")
    for name, value in keys.items():
        ident(name, field)
        hex_digest(value, f"{field} public key")
    if len(set(keys.values())) != len(keys):
        raise LabError(f"{field} public keys must be distinct")


def validate_manifest(manifest, expected_fingerprint=None):
    fields(manifest, "schema network mode actors validators quorum", "trust manifest")
    integer(manifest["schema"], "manifest schema", 1, 2)
    ident(manifest["network"], "network")
    mode = manifest["mode"]
    if not isinstance(mode, str) or mode not in MODES:
        raise LabError("Unknown ledger mode")
    if manifest["schema"] == 2 and mode != "consortium":
        raise LabError("Managed custody requires a three-of-four consortium")
    members, threshold = MODES[mode]
    _key_map(manifest["validators"], "validator")
    _key_map(manifest["actors"], "actor")
    if tuple(sorted(manifest["validators"])) != members or type(manifest["quorum"]) is not int or (
            manifest["quorum"] != threshold):
        raise LabError("The manifest does not match the network's fixed quorum")
    if set(manifest["actors"].values()).intersection(manifest["validators"].values()):
        raise LabError("Actor and validator keys must be distinct")
    fingerprint = digest(manifest)
    if expected_fingerprint is not None and fingerprint != hex_digest(expected_fingerprint,
                                                                      "trusted fingerprint"):
        raise LabError("Manifest does not match the trusted fingerprint")
    return fingerprint


def policy_descriptor(policy):
    return {**{field: policy[field] for field in
               ("issuer", "receiver", "programme", "version", "valid_from", "valid_until")},
            "policy_sha256": digest(policy)}


def event_body(manifest, kind, actor, payload):
    return {"network": manifest["network"], "kind": kind, "actor": actor, "payload": payload}


def _signed_event_body(manifest, event, keys, *, cached=False):
    fields(event, "body signature", "ledger event")
    body = fields(event["body"], "network kind actor payload", "event body")
    actor = ident(body["actor"], "event actor")
    kind = ident(body["kind"], "event kind")
    if body["network"] != manifest["network"]:
        raise LabError("Ledger event is outside the configured trust domain")
    role = "actor"
    if kind == "key-rotation":
        if manifest["schema"] != 2:
            raise LabError("Key rotation requires a managed ledger")
        keys.check_rotation(body, cached=cached)
        role = body["payload"]["role"]
    verify(keys.active_key(role, actor), "event", body, event["signature"], cached=cached)
    return body


def _same_request(stored, submitted):
    if stored == submitted:
        return True
    left, right = stored["body"], submitted["body"]
    if left["kind"] != "receipt" or right["kind"] != "receipt" or left["actor"] != right["actor"]:
        return False
    payload = right["payload"]
    return isinstance(payload, dict) and all(
        left["payload"][key] == payload.get(key) for key in ("policy_sha256", "receipt_sha256")
    )


def _header(core):
    if isinstance(core, dict) and "format" in core:
        fields(core, "network height previous recorded_at event format", "block header")
        integer(core["format"], "block format", 2, 3)
        return core
    return fields(core, "network height previous recorded_at event", "block header")


def _block_fields(block):
    core = _header(block.get("core") if isinstance(block, dict) else None)
    kind = "core hash votes finalization" if core.get("format") == 2 else "core hash votes"
    return fields(block, kind, "block")


def _utc(value, label):
    try:
        stamp = datetime.fromisoformat(value)
        if stamp.utcoffset() == timezone.utc.utcoffset(None):
            return stamp
    except (ValueError, TypeError):
        pass
    raise LabError(f"{label} must be an ISO 8601 UTC timestamp")


def _validate_core(manifest, core, history, keys, *, cached=False):
    _header(core)
    managed = manifest["schema"] == 2
    if (core.get("format") == 3) != managed:
        raise LabError("Block format does not match the custody model in the trust manifest")
    if (core["network"] != manifest["network"] or type(core["height"]) is not int
            or core["height"] != len(history.hashes) or core["previous"] != history.hashes[-1]):
        raise LabError("Block network, height or previous hash does not match")
    _utc(core["recorded_at"], "Block proposal time")
    event = _signed_event_body(manifest, core["event"], keys, cached=cached)
    kind, payload, actor = event["kind"], event["payload"], event["actor"]
    if kind in POLICY_EVENTS:
        history.validate_policy_event(kind, payload, actor, manifest["actors"])
    elif kind == "receipt":
        history.validate_receipt_event(payload, actor, managed=managed)
    elif kind != "key-rotation":
        raise LabError("Unknown ledger event type")


def _verify_votes(manifest, block, keys, *, cached=False):
    _block_fields(block)
    if block["hash"] != digest(block["core"]):
        raise LabError("Block hash does not match its canonical header")
    votes = block["votes"]
    if (not isinstance(votes, dict) or len(votes) < manifest["quorum"]
            or set(votes) - set(manifest["validators"])):
        raise LabError("Validator quorum is missing or includes untrusted validators")
    for name, signature in votes.items():
        verify(keys.active_key("validator", name), "vote", block["core"], signature, cached=cached)
    if "finalization" in block:
        certificate = fields(block["finalization"], "recorded_at votes", "finalization certificate")
        stamp = certificate["recorded_at"]
        _utc(stamp, "Block finalization time")
        signatures = certificate["votes"]
        if (not isinstance(signatures, dict) or len(signatures) < manifest["quorum"]
                or set(signatures) - set(votes)):
            raise LabError("Finalization certificates require a quorum of the block's validators")
        message = _finalization_message(block, stamp)
        for name, signature in signatures.items():
            verify(keys.active_key("validator", name), "finalization", message, signature, cached=cached)


def _finalization_message(block, recorded_at):
    return {"network": block["core"]["network"], "block_sha256": block["hash"],
            "recorded_at": recorded_at}


def verify_chain(manifest, chain, trusted_fingerprint, *, cached=False):
    """Verify the complete supplied prefix against an independently trusted manifest hash."""
    fingerprint = validate_manifest(manifest, trusted_fingerprint)
    if trusted_fingerprint is None:
        raise LabError("An independently trusted manifest fingerprint is required")
    if not isinstance(chain, list):
        raise LabError("A ledger prefix must be an array of blocks")
    verify_appended_blocks(manifest, (), chain, cached=cached)
    return summarized_history(manifest, chain, fingerprint)


def verify_appended_blocks(manifest, verified_prefix, blocks, *, cached=False):
    """Verify new blocks after a prefix and manifest already authenticated by the caller."""
    history = PolicyHistory(verified_prefix)
    keys = KeyRegistry(manifest, verified_prefix)
    for block in blocks:
        _verify_votes(manifest, block, keys, cached=cached)
        _validate_core(manifest, block["core"], history, keys, cached=cached)
        history.add(block)
        keys.apply(block["core"])


def summarized_history(manifest, verified_prefix, fingerprint):
    """Describe an already checked prefix without repeating signature verification."""
    return {"manifest_sha256": fingerprint, "height": len(verified_prefix),
            "head_sha256": verified_prefix[-1]["hash"] if verified_prefix else ZERO,
            "quorum": manifest["quorum"], "mode": manifest["mode"]}


def _rows(conn, through=None):
    if through is None:
        return conn.execute("SELECT height, hash, document FROM blocks ORDER BY height")
    return conn.execute("SELECT height, hash, document FROM blocks WHERE height<=? ORDER BY height", (through,))


def _decode_blocks(rows):
    blocks = []
    for height, block_hash, document in rows:
        block = _block_fields(loads(document))
        core = block["core"]
        if height != core["height"] or block_hash != block["hash"]:
            raise LabError("A stored block does not match its ledger index")
        blocks.append(block)
    return blocks


def _payloads(conn, through=None):
    return _decode_blocks(_rows(conn, through))


@contextmanager
def _db(path, *, write=False):
    with closing(sqlite3.connect(path, timeout=30)) as conn:
        conn.execute("PRAGMA synchronous=FULL")
        with conn:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn


def _table(conn, *, receipt_index=False):
    conn.execute("CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, "
                 "hash TEXT UNIQUE NOT NULL, document BLOB NOT NULL)")
    if receipt_index and not _has_receipt_index(conn):
        conn.execute("CREATE TABLE receipt_index (commitment TEXT PRIMARY KEY, height INTEGER UNIQUE NOT NULL)")
        for block in _payloads(conn):
            _index_receipt(conn, block)


def _has_receipt_index(conn):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='receipt_index'").fetchone() is not None


def _receipt_commitment(block):
    event = fields(block["core"]["event"], "body signature", "stored event")
    body = fields(event["body"], "network kind actor payload", "stored event body")
    if body["kind"] != "receipt":
        return None
    payload = body["payload"]
    return hex_digest(payload.get("receipt_sha256") if isinstance(payload, dict) else None,
                      "stored receipt commitment")


def _index_receipt(conn, block):
    commitment = _receipt_commitment(block)
    if commitment is not None:
        conn.execute("INSERT OR REPLACE INTO receipt_index VALUES (?, ?)", (commitment, block["core"]["height"]))


def _insert(conn, block, *, receipt_index=False):
    conn.execute("INSERT INTO blocks VALUES (?, ?, ?)",
                 (block["core"]["height"], block["hash"], canonical(block)))
    if receipt_index:
        _index_receipt(conn, block)


def head_document(manifest, prefix):
    return {"schema": 1, "manifest": manifest, "chain": prefix}


def _vote_document(document):
    fields(document, "validator height block_sha256 signature", "detached validator vote")
    ident(document["validator"], "validator name")
    integer(document["height"], "vote height", 1)
    hex_digest(document["block_sha256"], "voted block hash")
    return document


class Ledger:
    """Durable coordinator and separately stored validator replicas."""

    def __init__(self, directory, mode, actors, *, managed_manifest=None):
        if mode not in MODES:
            raise LabError(f"Unsupported mode: {mode}")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.directory / "ledger.sqlite3"
        if not self.path.exists() and self._has_replica_storage():
            raise LabError("The coordinator identity is missing. Restore a consistent workspace backup.")
        if not self.path.exists():
            self.path.touch(mode=0o600, exist_ok=True)
        names, threshold = MODES[mode]
        actors = sorted({ident(name, "actor") for name in actors})
        if not actors:
            raise LabError("At least one institutional actor is required")
        if managed_manifest is not None:
            validate_manifest(managed_manifest)
            if (managed_manifest["schema"] != 2 or managed_manifest["mode"] != mode
                    or sorted(managed_manifest["actors"]) != actors):
                raise LabError("Supplied enrollment does not match a managed workspace")
        with _db(self.path, write=True) as conn:
            _table(conn, receipt_index=True)
            conn.execute("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), "
                         "manifest BLOB NOT NULL, keys BLOB NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS pending (id INTEGER PRIMARY KEY CHECK(id=1), "
                         "core BLOB NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS artifacts (commitment TEXT PRIMARY KEY, "
                         "kind TEXT NOT NULL, document BLOB NOT NULL)")
            conn.execute("CREATE TABLE IF NOT EXISTS workbench_requests (request_hash TEXT PRIMARY KEY, "
                         "document BLOB NOT NULL)")
            existing = conn.execute("SELECT manifest, keys FROM settings WHERE id=1").fetchone()
            if existing:
                self.manifest, self.keys = map(loads, existing)
                validate_manifest(self.manifest)
                fields(self.keys, "actors validators", "local signing keys")
                if any(not isinstance(group, dict) for group in self.keys.values()):
                    raise LabError("Local signing keys must have valid actor and validator groups")
                if self.manifest["mode"] != mode or list(self.manifest["actors"]) != actors:
                    raise LabError("Workspace mode or actor list differs from the initialized network")
                if managed_manifest is not None and any(self.manifest[name] != managed_manifest[name]
                                                        for name in ("schema", "actors", "validators")):
                    raise LabError("Workspace is already initialized with a different custody model or enrollment")
            else:
                if conn.execute("SELECT 1 FROM blocks LIMIT 1").fetchone() or self._has_replica_storage():
                    raise LabError("The coordinator identity is missing. Restore a consistent workspace backup.")
                if managed_manifest is not None:
                    self.manifest, self.keys = managed_manifest, {"actors": {}, "validators": {}}
                else:
                    actor_keys = {name: local_keypair() for name in actors}
                    validator_keys = {name: local_keypair() for name in names}
                    self.manifest = {"schema": 1, "network": uuid4().hex, "mode": mode,
                                     "actors": {n: k[1] for n, k in actor_keys.items()},
                                     "validators": {n: k[1] for n, k in validator_keys.items()},
                                     "quorum": threshold}
                    self.keys = {"actors": {n: k[0] for n, k in actor_keys.items()},
                                 "validators": {n: k[0] for n, k in validator_keys.items()}}
                conn.execute("INSERT INTO settings VALUES (1, ?, ?)",
                             (canonical(self.manifest), canonical(self.keys)))
            if self.managed and any(self.keys.values()):
                raise LabError("A managed coordinator may not store signing keys")
        self.fingerprint = validate_manifest(self.manifest)

    @property
    def managed(self):
        return self.manifest["schema"] == 2

    def require_managed(self):
        if not self.managed:
            raise LabError("This command requires a separately initialized managed workspace")

    def require_local_signing(self):
        if self.managed:
            raise LabError("Use custody commands and the owners' keys to sign or commit in a managed workspace")

    def _has_replica_storage(self):
        return any((self.directory / (name + ".sqlite3")).is_file()
                   for names, _ in MODES.values() for name in names)

    @staticmethod
    def read_manifest(directory):
        path = Path(directory) / "ledger.sqlite3"
        if not path.is_file():
            return None
        with _db(path) as conn:
            present = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='settings'").fetchone()
            row = conn.execute("SELECT manifest FROM settings WHERE id=1").fetchone() if present else None
        if row is None:
            return None
        manifest = loads(row[0])
        validate_manifest(manifest)
        return manifest

    def sign_as(self, actor, domain, body):
        self.require_local_signing()
        if actor not in self.keys["actors"]:
            raise LabError(f"Unknown lab signing actor: {actor}")
        return sign(self.keys["actors"][actor], domain, body)

    def event(self, kind, actor, payload):
        body = event_body(self.manifest, kind, actor, payload)
        return {"body": body, "signature": self.sign_as(actor, "event", body)}

    def cache(self, commitment, kind, document):
        with _db(self.path, write=True) as conn:
            self._cache(conn, commitment, kind, document)

    @staticmethod
    def _cache(conn, commitment, kind, document):
        data = canonical(document)
        conn.execute("INSERT OR IGNORE INTO artifacts VALUES (?, ?, ?)", (commitment, kind, data))
        row = conn.execute("SELECT kind, document FROM artifacts WHERE commitment=?",
                           (commitment,)).fetchone()
        if row != (kind, data):
            raise LabError("Conflicting content for the same artifact commitment")

    def _cache_for_event(self, conn, event, artifact):
        kind, payload = event["body"]["kind"], event["body"]["payload"]
        if kind == "policy-revision":
            kind, payload = "policy", payload["policy"]
        if kind == "receipt":
            fields(artifact, "policy transcript receipt", "receipt artifacts")
            committed_document = artifact["receipt"]
        else:
            committed_document = artifact
        commitment = payload[f"{kind}_sha256"]
        if digest(committed_document) != commitment:
            raise LabError("The supplied artifact does not match the signed event commitment")
        self._cache(conn, commitment, kind, artifact)

    def reserve_request(self, key, document):
        """Persist a request context before publication so retries use its original view."""
        key = hex_digest(key, "receipt request hash")
        with _db(self.path, write=True) as conn:
            conn.execute("INSERT OR IGNORE INTO workbench_requests VALUES (?, ?)",
                         (key, canonical(document)))
            return loads(conn.execute("SELECT document FROM workbench_requests WHERE request_hash=?",
                                      (key,)).fetchone()[0])

    def artifact(self, commitment, kind):
        with _db(self.path) as conn:
            row = conn.execute("SELECT document FROM artifacts WHERE commitment=? AND kind=?",
                               (hex_digest(commitment, "commitment"), kind)).fetchone()
        if row is None:
            raise LabError("The off-chain artifact is unavailable in this workspace")
        return loads(row[0])

    def _store_path(self, replica):
        if replica is None:
            return self.path
        if replica not in self.manifest["validators"]:
            raise LabError("Unknown validator")
        if self.managed:
            raise LabError("Managed validator stores are held by their owners")
        return self.directory / (replica + ".sqlite3")

    def prefix(self, replica=None, *, through=None):
        path = self._store_path(replica)
        if through is not None:
            through = integer(through, "history cutoff", 0)
        if not path.is_file():
            return []
        with _db(path) as conn:
            return self._checked_history(conn, through)

    def _checked_history(self, conn, through=None):
        blocks = _payloads(conn, through)
        verify_chain(self.manifest, blocks, self.fingerprint, cached=True)
        return blocks

    def receipt_prefix(self, commitment, replica=None):
        """Certify the origin-to-receipt prefix using the index only as a lookup hint."""
        commitment = hex_digest(commitment, "receipt commitment")
        path = self._store_path(replica)
        if path.is_file():
            with _db(path) as conn:
                conn.execute("BEGIN")
                if _has_receipt_index(conn):
                    match = conn.execute("SELECT height FROM receipt_index WHERE commitment=?", (commitment,)).fetchone()
                    if match and type(match[0]) is int and match[0] > 0:
                        candidate = self._checked_history(conn, match[0])
                        if (len(candidate) == match[0] and _receipt_commitment(candidate[-1]) == commitment):
                            return candidate
                chain = self._checked_history(conn)
                for index, block in enumerate(chain):
                    if _receipt_commitment(block) == commitment:
                        return chain[:index + 1]
        raise LabError("Receipt is unavailable in the selected committed history")

    def replica_status(self, replica, verified_rows):
        """Reuse exact canonical records from the verified coordinator prefix."""
        path = self._store_path(replica)
        if not path.is_file():
            return {"height": 0, "state": "behind" if verified_rows else "empty"}
        with _db(path) as conn:
            rows = _rows(conn).fetchall()
        shared = min(len(rows), len(verified_rows))
        if rows != verified_rows[:len(rows)]:
            blocks = _decode_blocks(rows)
            verify_chain(self.manifest, blocks, self.fingerprint, cached=True)
            if any(canonical(block) != row[2] for block, row in zip(blocks[:shared], verified_rows)):
                return {"height": len(rows), "state": "inconsistent"}
        if len(rows) < len(verified_rows):
            state = "behind"
        elif len(rows) > len(verified_rows):
            state = "advancing"
        else:
            state = "current" if rows else "empty"
        return {"height": len(rows), "state": state}

    def pending_height(self):
        with _db(self.path) as conn:
            row = conn.execute("SELECT core FROM pending WHERE id=1").fetchone()
        if row is None:
            return None
        core = _header(loads(row[0]))
        return integer(core["height"], "pending height", 1)

    def _members(self, available):
        if available is None:
            return tuple(self.manifest["validators"])
        if len(set(available)) != len(available) or set(available) - set(self.manifest["validators"]):
            raise LabError("Available validator names must be unique and known")
        return tuple(sorted(available))

    def _sync(self, name, prefix, proposal=None):
        self.require_local_signing()
        path = self.directory / (name + ".sqlite3")
        with _db(path, write=True) as conn:
            _table(conn, receipt_index=True)
            conn.execute("CREATE TABLE IF NOT EXISTS votes (height INTEGER PRIMARY KEY, "
                         "hash TEXT NOT NULL, signature TEXT NOT NULL)")
            local = _payloads(conn)
            if len(local) > len(prefix) or any(first != second for first, second in zip(local, prefix)):
                raise LabError(f"Replica {name} does not match the proposed history")
            history = PolicyHistory(local)
            keys = KeyRegistry(self.manifest)
            for height, block in enumerate(prefix[len(local):], start=len(local) + 1):
                _verify_votes(self.manifest, block, keys, cached=True)
                _validate_core(self.manifest, block["core"], history, keys, cached=True)
                vote = conn.execute("SELECT hash FROM votes WHERE height=?", (height,)).fetchone()
                if vote and vote[0] != block["hash"]:
                    raise LabError(f"Replica {name} previously voted for a different block")
                _insert(conn, block, receipt_index=True)
                history.add(block)
            if proposal is None:
                return None
            height = len(prefix) + 1
            _validate_core(self.manifest, proposal, history, keys, cached=True)
            block_hash = digest(proposal)
            existing = conn.execute("SELECT hash, signature FROM votes WHERE height=?",
                                    (height,)).fetchone()
            if existing:
                if existing[0] != block_hash:
                    raise LabError(f"Replica {name} refuses a second vote at height {height}")
                try:
                    verify(self.manifest["validators"][name], "vote", proposal, existing[1], cached=True)
                    return existing[1]
                except LabError:
                    # A damaged signature can be restored for the same reserved block.
                    signature = sign(self.keys["validators"].get(name), "vote", proposal)
                    verify(self.manifest["validators"][name], "vote", proposal, signature, cached=True)
                    conn.execute("UPDATE votes SET signature=? WHERE height=?", (signature, height))
                    return signature
            signature = sign(self.keys["validators"].get(name), "vote", proposal)
            conn.execute("INSERT INTO votes VALUES (?, ?, ?)", (height, block_hash, signature))
            return signature

    def reserve_external(self, event, artifact, checked_head):
        """Reserve one managed proposal bound to the application-checked head."""
        self.require_managed()
        with _db(self.path, write=True) as conn:
            prefix = self._checked_history(conn)
            for block in prefix:
                if block["core"]["event"] == event:
                    if artifact is not None:
                        self._cache_for_event(conn, event, artifact)
                    return {"status": "committed", "height": block["core"]["height"], "block_sha256": block["hash"]}
            history = PolicyHistory(prefix)
            if history.hashes[-1] != checked_head:
                raise LabError("The committed head changed. Check and resubmit the operation.")
            row = conn.execute("SELECT core FROM pending WHERE id=1").fetchone()
            if row:
                proposal = loads(row[0])
                if proposal["event"] != event:
                    raise LabError("Complete the existing managed proposal before submitting another operation")
            else:
                proposal = {"network": self.manifest["network"], "height": len(prefix) + 1,
                            "previous": history.hashes[-1], "recorded_at": datetime.now(timezone.utc).isoformat(),
                            "event": event, "format": 3}
            _validate_core(self.manifest, proposal, history, KeyRegistry(self.manifest, prefix), cached=True)
            if artifact is not None:
                self._cache_for_event(conn, event, artifact)
            if not row:
                conn.execute("INSERT INTO pending VALUES (1, ?)", (canonical(proposal),))
            return {"status": "reserved", "height": proposal["height"], "block_sha256": digest(proposal),
                    "request": {**head_document(self.manifest, prefix), "proposal": proposal}}

    def external_pending(self):
        self.require_managed()
        with _db(self.path, write=True) as conn:
            row = conn.execute("SELECT core FROM pending WHERE id=1").fetchone()
            if row is None:
                raise LabError("There is no pending managed proposal")
            prefix = self._checked_history(conn)
            return {**head_document(self.manifest, prefix), "proposal": loads(row[0])}

    def commit_external(self, responses):
        self.require_managed()
        if not responses:
            raise LabError("A managed commit needs detached validator votes")
        votes = [_vote_document(response) for response in responses]
        height, block_hash = votes[0]["height"], votes[0]["block_sha256"]
        signatures = {vote["validator"]: vote["signature"] for vote in votes}
        if len(signatures) != len(votes) or any(vote["height"] != height or vote["block_sha256"] != block_hash
                                                for vote in votes):
            raise LabError("Each validator must vote once for the same managed proposal")
        with _db(self.path, write=True) as conn:
            prefix = self._checked_history(conn)
            if height <= len(prefix):
                existing = prefix[height - 1]
                retried = {"core": existing["core"], "hash": block_hash, "votes": signatures}
                _verify_votes(self.manifest, retried, KeyRegistry(self.manifest, prefix[:height - 1]))
                return existing
            row = conn.execute("SELECT core FROM pending WHERE id=1").fetchone()
            if row is None or height != len(prefix) + 1:
                raise LabError("The votes do not belong to the pending managed proposal")
            proposal = loads(row[0])
            keys = KeyRegistry(self.manifest, prefix)
            _validate_core(self.manifest, proposal, PolicyHistory(prefix), keys, cached=True)
            block = {"core": proposal, "hash": block_hash, "votes": signatures}
            _verify_votes(self.manifest, block, keys)
            _insert(conn, block, receipt_index=True)
            conn.execute("DELETE FROM pending WHERE id=1")
            return block

    def sync(self, available=None):
        """Finish a reserved proposal and bring the named replicas to the committed head."""
        self.require_local_signing()
        members = self._members(available)
        with _db(self.path, write=True) as conn:
            row = conn.execute("SELECT core FROM pending WHERE id=1").fetchone()
            prefix = self._checked_history(conn)
            if row:
                if len(members) < self.manifest["quorum"]:
                    raise LabError("Validator quorum unavailable; proposal remains pending")
                proposal = loads(row[0])
                votes, diagnostics = {}, []
                for name in members:
                    try:
                        signature = self._sync(name, prefix, proposal)
                        verify(self.manifest["validators"][name], "vote", proposal, signature, cached=True)
                        votes[name] = signature
                    except (LabError, sqlite3.Error) as exc:
                        diagnostics.append(f"{name}: {exc}")
                block = {"core": proposal, "hash": digest(proposal), "votes": votes}
                if len(votes) < self.manifest["quorum"]:
                    raise LabError("Validator quorum unavailable; proposal remains pending. "
                                   + " | ".join(diagnostics))
                if proposal.get("format") == 2:
                    stamp = datetime.now(timezone.utc).isoformat()
                    message = _finalization_message(block, stamp)
                    block["finalization"] = {"recorded_at": stamp, "votes": {
                        name: sign(self.keys["validators"].get(name), "finalization", message) for name in votes
                    }}
                _verify_votes(self.manifest, block, KeyRegistry(self.manifest), cached=True)
                _insert(conn, block, receipt_index=True)
                conn.execute("DELETE FROM pending WHERE id=1")
        # First commit the coordinator. Catch-up can then be safely retried after
        # a process interruption, with no replica ahead of the published head.
        with _db(self.path, write=True) as conn:
            prefix = self._checked_history(conn)
            replica_errors = {}
            for name in members:
                try:
                    self._sync(name, prefix)
                except (LabError, sqlite3.Error) as exc:
                    replica_errors[name] = str(exc)
            return {"height": len(prefix), "head_sha256": prefix[-1]["hash"] if prefix else ZERO,
                    "replica_errors": replica_errors}

    def append(self, event, available=None, *, artifact=None):
        self.require_local_signing()
        self._members(available)
        keys = KeyRegistry(self.manifest)
        _signed_event_body(self.manifest, event, keys, cached=True)
        for _ in range(8):
            with _db(self.path, write=True) as conn:
                prefix = self._checked_history(conn)
                found = next((block for block in prefix
                              if _same_request(block["core"]["event"], event)), None)
                if found is not None:
                    if artifact is not None:
                        self._cache_for_event(conn, found["core"]["event"], artifact)
                    return found
                pending = conn.execute("SELECT core FROM pending WHERE id=1").fetchone()
                if pending is None:
                    history = PolicyHistory(prefix)
                    proposal = {"network": self.manifest["network"], "height": len(prefix) + 1,
                                "previous": prefix[-1]["hash"] if prefix else ZERO,
                                "recorded_at": datetime.now(timezone.utc).isoformat(),
                                "event": event, "format": 2}
                    _validate_core(self.manifest, proposal, history, keys, cached=True)
                    if artifact is not None:
                        self._cache_for_event(conn, event, artifact)
                    conn.execute("INSERT INTO pending VALUES (1, ?)", (canonical(proposal),))
                elif artifact is not None:
                    reserved = loads(pending[0])["event"]
                    if _same_request(reserved, event):
                        self._cache_for_event(conn, reserved, artifact)
            self.sync(available)
        raise LabError("Concurrent proposals prevented the append; retry the same signed event")

