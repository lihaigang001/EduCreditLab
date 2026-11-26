"""Detached institution approvals and independent validator votes for managed ledgers."""

from __future__ import annotations

from pathlib import Path
from secrets import token_hex
from uuid import uuid4

from .keys import KeyRegistry, public_key, read_enrollment, role_group, rotation_message, sign, verify
from .lab import Lab, verify_receipt_evidence, verify_transcript
from .ledger import (MODES, _db, _insert, _payloads, _table, _validate_core, event_body,
                     head_document, policy_descriptor, verify_chain)
from .model import (LabError, canonical, day, digest, fields, hex_digest, ident, integer,
                    normalize_policy, normalize_transcript, text)
from .solver import evaluate
from .temporal import POLICY_EVENTS, ZERO, PolicyHistory, knowledge_view


def initialize(directory, enrollments):
    actors, validators = {}, {}
    groups = {"actors": actors, "validators": validators}
    for signed in enrollments:
        member = read_enrollment(signed)
        members = groups[role_group(member["role"])]
        name = member["name"]
        if name in members:
            raise LabError("Each role and identity can enroll only once")
        members[name] = member["public_key"]
    manifest = {"schema": 2, "network": uuid4().hex, "mode": "consortium",
                **groups, "quorum": MODES["consortium"][1]}
    return Lab(directory, "consortium", actors, managed_manifest=manifest)


def _checked_head(document, trust, extra=""):
    fields(document, "schema manifest chain" + extra, "managed exchange document")
    integer(document["schema"], "exchange schema", 1, 1)
    manifest, chain = document["manifest"], document["chain"]
    verified = verify_chain(manifest, chain, trust)
    if manifest["schema"] != 2:
        raise LabError("An independently managed trust manifest is required")
    return manifest, chain, verified


def _operation(body, key, artifact):
    return {"schema": 1, "event": {"body": body, "signature": sign(key, "event", body)}, "artifact": artifact}


def sign_policy(head, trust, policy, key, *, supersedes=None, reason=None):
    manifest, chain, _ = _checked_head(head, trust)
    policy = normalize_policy(policy)
    actor = policy["receiver"]
    KeyRegistry(manifest, chain).require_owner("actor", actor, key)
    kind, payload = "policy", policy_descriptor(policy)
    if supersedes is not None:
        kind, payload = "policy-revision", {
            "policy": payload, "supersedes": hex_digest(supersedes, "superseded policy hash"),
            "reason": text(reason, "revision reason", 400),
        }
    elif reason is not None:
        raise LabError("A revision reason needs a parent policy")
    PolicyHistory(chain).validate_policy_event(kind, payload, actor, manifest["actors"])
    return _operation(event_body(manifest, kind, actor, payload), key, policy)


def sign_transcript(head, trust, transcript, key):
    manifest, chain, _ = _checked_head(head, trust)
    transcript = normalize_transcript(transcript)
    KeyRegistry(manifest, chain).require_owner("actor", transcript["issuer"], key)
    body = {"network": manifest["network"], "transcript": transcript, "salt": token_hex(32)}
    return {"body": body, "signature": sign(key, "transcript", body)}


def prepare_receipt(lab, signed, receiver, programme, as_of, *, known_height=None):
    ledger = lab.ledger
    ledger.require_managed()
    chain = ledger.prefix()
    manifest = ledger.manifest
    transcript = verify_transcript(signed, manifest, KeyRegistry(manifest, chain))
    policy, view = lab._choose_policy(chain, transcript["issuer"], receiver, programme,
                                      as_of, known_height=known_height)
    return {**head_document(manifest, chain), "policy": policy, "transcript": signed,
            "as_of": day(as_of, "as_of"), "knowledge": _view_ref(view["knowledge"])}


def _view_ref(view):
    return {key: view[key] for key in ("height", "head_sha256")}


def approve_receipt(request, trust, key):
    manifest, chain, confirmed = _checked_head(request, trust, " policy transcript as_of knowledge")
    keys = KeyRegistry(manifest, chain)
    signed = request["transcript"]
    transcript = verify_transcript(signed, manifest, keys)
    policy = normalize_policy(request["policy"])
    actor = policy["receiver"]
    keys.require_owner("actor", actor, key)
    as_of = day(request["as_of"], "as_of")
    knowledge = fields(request["knowledge"], "height head_sha256", "requested knowledge view")
    if knowledge != _view_ref(knowledge_view(chain, known_height=knowledge["height"])):
        raise LabError("The requested knowledge view is not part of the certified history")
    selected = PolicyHistory(chain).select(transcript["issuer"], actor, policy["programme"], as_of,
                                           knowledge["height"])
    if selected["policy"] != policy_descriptor(policy):
        raise LabError("The supplied policy is not applicable in the requested view")
    decision = evaluate(policy, transcript, as_of)
    receipt_body = {"schema": 1, "network": manifest["network"], "salt": token_hex(32),
                    "decision": decision, "transcript_commitment": digest(signed)}
    receipt = {"body": receipt_body, "signature": sign(key, "receipt", receipt_body)}
    body = event_body(manifest, "receipt", actor, {"receipt_sha256": digest(receipt),
                                                   "policy_sha256": decision["policy_sha256"],
                                                   "knowledge": knowledge, "approval": _view_ref(confirmed)})
    return _operation(body, key, {"policy": policy, "transcript": signed, "receipt": receipt})


def authorize_rotation(head, trust, role, name, previous, replacement, reason):
    manifest, chain, _ = _checked_head(head, trust)
    name = ident(name, "signer name")
    keys = KeyRegistry(manifest, chain)
    keys.require_owner(role, name, previous)
    body = event_body(manifest, "key-rotation", name, {
        "role": role, "previous_key": public_key(previous), "replacement_key": public_key(replacement),
        "reason": text(reason, "rotation reason", 400),
    })
    body["payload"]["possession"] = sign(replacement, "key-possession", rotation_message(body))
    keys.check_rotation(body)
    return _operation(body, previous, None)


def submit(lab, operation):
    ledger = lab.ledger
    ledger.require_managed()
    fields(operation, "schema event artifact", "signed managed operation")
    integer(operation["schema"], "managed operation schema", 1, 1)
    event = fields(operation["event"], "body signature", "signed event")
    body = fields(event["body"], "network kind actor payload", "event body")
    kind, artifact = ident(body["kind"], "event kind"), operation["artifact"]
    prefix = ledger.prefix()
    if kind in POLICY_EVENTS:
        policy = normalize_policy(artifact)
        descriptor = (fields(body["payload"], "policy supersedes reason", "policy revision")["policy"]
                      if kind == "policy-revision" else body["payload"])
        if policy_descriptor(policy) != descriptor or canonical(policy) != canonical(artifact):
            raise LabError("The policy artifact does not match its signed descriptor")
    elif kind == "receipt":
        previously = next((index for index, block in enumerate(prefix) if block["core"]["event"] == event),
                          len(prefix))
        prior = prefix[:previously]
        PolicyHistory(prior).validate_receipt_event(body["payload"], body["actor"], managed=True)
        verify_receipt_evidence(artifact, ledger.manifest, prior, body)
    elif kind != "key-rotation" or artifact is not None:
        raise LabError("Unsupported managed operation or unexpected rotation artifact")
    head = prefix[-1]["hash"] if prefix else ZERO
    return ledger.reserve_external(event, artifact, head)


class ValidatorStore:
    """Persist one vote per height across processes and validator key rotations."""

    def __init__(self, path, name, trust):
        self.path = Path(path)
        self.name = ident(name, "validator name")
        self.trust = hex_digest(trust, "trusted fingerprint")

    def initialize(self, genesis):
        manifest, chain, _ = _checked_head(genesis, self.trust)
        KeyRegistry(manifest).active_key("validator", self.name)
        if chain:
            raise LabError("Initialize each validator from the agreed empty network head")
        if self.path.exists():
            with _db(self.path) as conn:
                self._binding(conn)
            return
        self.path.touch(mode=0o600, exist_ok=False)
        with _db(self.path, write=True) as conn:
            _table(conn)
            conn.execute("CREATE TABLE binding (name TEXT NOT NULL, trust TEXT NOT NULL)")
            conn.execute("INSERT INTO binding VALUES (?, ?)", (self.name, self.trust))
            conn.execute("CREATE TABLE votes (height INTEGER PRIMARY KEY, hash TEXT NOT NULL, signature TEXT NOT NULL)")

    def _binding(self, conn):
        if conn.execute("SELECT name, trust FROM binding").fetchall() != [(self.name, self.trust)]:
            raise LabError("Validator state is bound to a different identity or trust manifest")

    def _accept(self, conn, chain):
        self._binding(conn)
        local = _payloads(conn)
        if len(local) > len(chain) or any(old["hash"] != new["hash"] for old, new in zip(local, chain)):
            raise LabError("This certified prefix is older than or conflicts with the validator state")
        for block in chain[len(local):]:
            height = block["core"]["height"]
            reserved = conn.execute("SELECT hash FROM votes WHERE height=?", (height,)).fetchone()
            if reserved and self.name in block["votes"] and reserved[0] != block["hash"]:
                raise LabError("A certificate conflicts with this validator's durable vote")
            _insert(conn, block)

    def accept_head(self, head):
        _, chain, confirmed = _checked_head(head, self.trust)
        with _db(self._existing_path(), write=True) as conn:
            self._accept(conn, chain)
        return confirmed

    def _existing_path(self):
        if not self.path.is_file():
            raise LabError("Open the validator's existing durable state or initialize it before the first vote")
        return self.path

    def vote(self, request, key):
        manifest, chain, _ = _checked_head(request, self.trust, " proposal")
        keys = KeyRegistry(manifest, chain)
        keys.require_owner("validator", self.name, key)
        core = request["proposal"]
        _validate_core(manifest, core, PolicyHistory(chain), keys)
        height, block_hash = core["height"], digest(core)
        with _db(self._existing_path(), write=True) as conn:
            self._accept(conn, chain)
            prior = conn.execute("SELECT hash, signature FROM votes WHERE height=?", (height,)).fetchone()
            if prior is not None:
                if prior[0] != block_hash:
                    raise LabError("The validator has already reserved a different vote at this height")
                signature = prior[1]
                verify(keys.active_key("validator", self.name), "vote", core, signature)
            else:
                signature = sign(key, "vote", core)
                conn.execute("INSERT INTO votes VALUES (?, ?, ?)", (height, block_hash, signature))
        return {"validator": self.name, "height": height, "block_sha256": block_hash, "signature": signature}
