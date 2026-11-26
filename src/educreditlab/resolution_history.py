"""Record and verify the ordered publication of institutional resolution decisions."""

from dataclasses import dataclass

from .model import LabError, digest, fields, hex_digest, integer, sequence
from .policy_divergence import verify_policy_divergence
from .policy_history import MAX_REVISIONS
from .policy_resolution import (_approval_signer, _sign_approval, _validate_authority, _verify_approvals,
                                verify_policy_resolution, verify_resolved_review)

HISTORY_KIND = "educreditlab-policy-resolution-history"
PUBLICATION_KIND = "educreditlab-policy-resolution-publication"
PUBLICATION_DOMAIN = "review-policy-resolution-publication"
HANDOVER_KIND = "educreditlab-policy-resolution-authority-handover"
HANDOVER_DOMAINS = {"outgoing": "review-policy-resolution-handover-outgoing",
                    "incoming": "review-policy-resolution-handover-incoming"}
PUBLICATION_FIELDS = "schema kind history_sha256 number previous_publication_sha256 decision_sha256"


@dataclass(frozen=True)
class _VerifiedHistory:
    root: str
    tip: str
    entries: list[tuple[dict, str]]
    profile: dict
    authority: str
    handovers: int


def _history_fingerprint(history):
    # The original anchor also authenticates existing entries in a schema 2 history.
    return digest({"schema": 1, "kind": history["kind"], "authority": history["authority"],
                   "divergence_sha256": history["divergence_sha256"]})


def init_resolution_history(authority, evidence, trusted_authority):
    _validate_authority(authority, trusted_authority)
    verified = verify_policy_divergence(evidence, authority["initial_policy_sha256"])
    history = {"schema": 1, "kind": HISTORY_KIND, "authority": authority,
               "divergence_sha256": verified["evidence_sha256"], "publications": []}
    return history, _history_fingerprint(history)


def _publication_body(root, tip, number, decision_sha256):
    return {"schema": 1, "kind": PUBLICATION_KIND, "history_sha256": root, "number": number,
            "previous_publication_sha256": tip, "decision_sha256": decision_sha256}


def _handover_body(publication, successor):
    return {**publication, "kind": HANDOVER_KIND, "successor_authority": successor}


def _validate_successor(profile, authority, successor, successor_pin):
    _validate_authority(successor, successor_pin)
    if successor["initial_policy_sha256"] != profile["initial_policy_sha256"]:
        raise LabError("A successor authority must retain the initial reviewer policy fingerprint")
    if successor_pin == authority:
        raise LabError("An authority handover requires a different successor profile")


def _verify_handover_approvals(profile, successor, body, approvals):
    fields(approvals, "outgoing incoming", "authority handover approvals")
    for role, roster in (("outgoing", profile), ("incoming", successor)):
        try:
            _verify_approvals(roster, body, approvals[role], domain=HANDOVER_DOMAINS[role])
        except LabError as exc:
            raise LabError(f"{role.capitalize()} authority approval failed: {exc}") from exc


def _verify_publications(records, root, tip, profile, authority, *, schema, base_count=0):
    verified = []
    handovers = 0
    for index, record in enumerate(records, base_count + 1):
        fields(record, "body approvals", "signed resolution publication")
        body = record["body"]
        handover = schema == 2 and isinstance(body, dict) and body.get("kind") == HANDOVER_KIND
        fields(body, PUBLICATION_FIELDS + " successor_authority" if handover else PUBLICATION_FIELDS,
               "resolution publication body")
        integer(body["schema"], "publication schema", 1, 1)
        integer(body["number"], "publication number", index, index)
        decision = hex_digest(body["decision_sha256"], "published decision fingerprint")
        publication = _publication_body(root, tip, index, decision)
        if body != (_handover_body(publication, body["successor_authority"]) if handover else publication):
            raise LabError("Publication does not match its history and preceding entry")
        if handover:
            successor = body["successor_authority"]
            successor_pin = digest(successor)
            _validate_successor(profile, authority, successor, successor_pin)
            _verify_handover_approvals(profile, successor, body, record["approvals"])
            profile, authority = successor, successor_pin
            handovers += 1
        else:
            _verify_approvals(profile, body, record["approvals"], domain=PUBLICATION_DOMAIN)
        tip = digest(body)
        verified.append((body, authority))
    return _VerifiedHistory(root, tip, verified, profile, authority, handovers)


def _verified_history(history, trusted_authority, trusted_publication):
    fields(history, "schema kind authority divergence_sha256 publications", "resolution publication history")
    schema = integer(history["schema"], "publication history schema", 1, 2)
    if history["kind"] != HISTORY_KIND:
        raise LabError("Expected an EduCreditLab resolution publication history")
    expected = hex_digest(trusted_publication, "independently expected publication fingerprint")
    profile = history["authority"]
    _validate_authority(profile, trusted_authority)
    hex_digest(history["divergence_sha256"], "history divergence fingerprint")
    root = _history_fingerprint(history)
    records = sequence(history["publications"], "resolution publications", 0, MAX_REVISIONS)
    state = _verify_publications(records, root, root, profile, trusted_authority, schema=schema)
    if state.tip != expected:
        raise LabError("History does not match the independently expected latest publication")
    return state


def _status(history, trusted_authority, state):
    result = {"resolution_history_verified": True, "authority_sha256": trusted_authority,
              "divergence_sha256": history["divergence_sha256"], "history_sha256": state.root,
              "publication_count": len(state.entries), "latest_publication_sha256": state.tip,
              "current_decision_sha256": state.entries[-1][0]["decision_sha256"] if state.entries else None}
    if history["schema"] == 2:
        result.update(active_authority_sha256=state.authority, authority_handover_count=state.handovers)
    return result


def verify_resolution_history(history, trusted_authority, trusted_publication):
    state = _verified_history(history, trusted_authority, trusted_publication)
    return _status(history, trusted_authority, state)


def _check_scope(history, result):
    if result["divergence_sha256"] != history["divergence_sha256"]:
        raise LabError("Resolution concerns a different divergence exhibit")


def _next_publication(history, state, packet, trusted_authority, trusted_decision):
    number = integer(len(state.entries) + 1, "publication number", 1, MAX_REVISIONS)
    result = verify_policy_resolution(packet, trusted_authority, trusted_decision)
    _check_scope(history, result)
    return _publication_body(state.root, state.tip, number, result["decision_sha256"])


def sign_resolution_publication(history, packet, key, trusted_authority, trusted_publication, trusted_decision):
    state = _verified_history(history, trusted_authority, trusted_publication)
    body = _next_publication(history, state, packet, state.authority, trusted_decision)
    return _sign_approval(state.profile, body, key, domain=PUBLICATION_DOMAIN)


def append_resolution_publication(history, packet, approvals, trusted_authority, trusted_publication, trusted_decision):
    state = _verified_history(history, trusted_authority, trusted_publication)
    body = _next_publication(history, state, packet, state.authority, trusted_decision)
    ordered = sorted(approvals, key=_approval_signer)
    _verify_approvals(state.profile, body, ordered, domain=PUBLICATION_DOMAIN)
    entry = {"body": body, "approvals": ordered}
    return {**history, "publications": [*history["publications"], entry]}, digest(body)


def _next_handover(history, state, packet, successor, trusted_successor, trusted_decision):
    _validate_successor(state.profile, state.authority, successor, trusted_successor)
    publication = _next_publication(history, state, packet, trusted_successor, trusted_decision)
    return _handover_body(publication, successor)


def sign_resolution_handover(history, packet, successor, key, trusted_authority, trusted_publication, trusted_decision,
                             *, trusted_successor, role):
    if role not in HANDOVER_DOMAINS:
        raise LabError("Approval role must be outgoing or incoming")
    state = _verified_history(history, trusted_authority, trusted_publication)
    body = _next_handover(history, state, packet, successor, trusted_successor, trusted_decision)
    profile = state.profile if role == "outgoing" else successor
    return _sign_approval(profile, body, key, domain=HANDOVER_DOMAINS[role])


def append_resolution_handover(history, packet, successor, approvals, trusted_authority, trusted_publication,
                               trusted_decision, *, trusted_successor):
    state = _verified_history(history, trusted_authority, trusted_publication)
    body = _next_handover(history, state, packet, successor, trusted_successor, trusted_decision)
    fields(approvals, "outgoing incoming", "authority handover approvals")
    ordered = {role: sorted(approvals[role], key=_approval_signer) for role in HANDOVER_DOMAINS}
    _verify_handover_approvals(state.profile, successor, body, ordered)
    entry = {"body": body, "approvals": ordered}
    return {**history, "schema": 2, "publications": [*history["publications"], entry]}, digest(body)


def _verify_publication_resolution(scope, packet, authority, expected, *, bundle=None, trusted_manifest=None,
                                   trusted_checkpoint=None, expected_proof=None, proof=None):
    if bundle is None:
        if any(value is not None for value in (proof, trusted_manifest, trusted_checkpoint, expected_proof)):
            raise LabError("A joint confirmation is required to apply proof fingerprints or recheck evidence")
        result = verify_policy_resolution(packet, authority, expected)
    else:
        result = verify_resolved_review(packet, bundle, authority, expected, trusted_manifest=trusted_manifest,
                                       trusted_checkpoint=trusted_checkpoint, expected_proof=expected_proof, proof=proof)
    _check_scope(scope, result)
    return result


def verify_published_resolution(history, packet, trusted_authority, trusted_publication, *, number=None,
                                bundle=None, trusted_manifest=None, trusted_checkpoint=None,
                                expected_proof=None, proof=None):
    state = _verified_history(history, trusted_authority, trusted_publication)
    entries = state.entries
    if not entries:
        raise LabError("The verified history has no published decision")
    number = len(entries) if number is None else integer(number, "selected publication number", 1, len(entries))
    selected, authority = entries[number - 1]
    result = _verify_publication_resolution(history, packet, authority, selected["decision_sha256"], bundle=bundle,
                                            trusted_manifest=trusted_manifest, trusted_checkpoint=trusted_checkpoint,
                                            expected_proof=expected_proof, proof=proof)
    if history["schema"] == 2:
        result["verified_authority_sha256"] = authority
        result["authority_sha256"] = trusted_authority
    return {**_status(history, trusted_authority, state), **result,
            "verified_publication": number, "verified_publication_sha256": digest(selected)}
