"""Derive portable receipt witnesses from an independently audited ledger prefix."""

from __future__ import annotations

from .keys import KeyRegistry
from .lab import replay_receipt_evidence, verify_review
from .ledger import head_document, summarized_history, validate_manifest, verify_appended_blocks, verify_chain
from .merkle import MerkleTree, verify_multiproof, verify_path
from .model import LabError, digest, fields, hex_digest, ident, integer, sequence
from .review_plan import validate_review_plan
from .temporal import POLICY_FIELDS, PolicyHistory, knowledge_view

PROFILE = "educreditlab-receipt-checkpoint-v1"
BASE_PROOF_FIELDS = "schema manifest checkpoint receipt_witness"
BATCH_PROOF_FIELDS = "schema manifest checkpoint leaves siblings"
ARCHIVE_FIELDS = {"schema", "manifest", "chain"}
DELTA_KIND = "educreditlab-checkpoint-delta"
SCOPE_FIELDS = ("issuer", "receiver", "programme")


def _scope(policy):
    return {key: policy[key] for key in SCOPE_FIELDS}


def _read_scope(scope):
    fields(scope, " ".join(SCOPE_FIELDS), "policy scope")
    for key in SCOPE_FIELDS:
        ident(scope[key], key)
    return scope


def _receipt_refs(commitments, maximum):
    sequence(commitments, "Receipt list", 1, maximum)
    references = {hex_digest(value, "receipt commitment") for value in commitments}
    if len(references) != len(commitments):
        raise LabError("A receipt list must contain distinct commitments")
    return references


class CheckpointIndex:
    """Build a deterministic index from an already verified prefix."""

    def __init__(self, manifest, chain):
        self.manifest = manifest
        self._receipts = {}
        self._scopes = {}
        history = PolicyHistory(chain)
        keys = KeyRegistry(manifest)
        for block in chain:
            core = block["core"]
            event = core["event"]["body"]
            if event["kind"] == "receipt":
                payload = event["payload"]
                policy = history.policies[payload["policy_sha256"]]["policy"]
                scope = _scope(policy)
                knowledge = (knowledge_view(chain, known_height=payload["knowledge"]["height"])
                             if "knowledge" in payload else None)
                self._receipts[payload["receipt_sha256"]] = {
                    "kind": "receipt", "height": core["height"], "block_sha256": block["hash"],
                    "event": event, "scope": scope, "knowledge": knowledge,
                    "actor_keys": {name: keys.active_key("actor", name)
                                   for name in (scope["issuer"], scope["receiver"])},
                }
            keys.apply(core)
        for registration in history.policies.values():
            scope = _scope(registration["policy"])
            timeline = self._scopes.setdefault(digest(scope), {"kind": "policy-scope", "scope": scope,
                                                               "registrations": []})
            timeline["registrations"].append(registration)
        # Leaf order is part of the checkpoint profile and is independent of the exporter.
        self._entries = [self._scopes[key] for key in sorted(self._scopes)]
        self._scope_indices = {key: index for index, key in enumerate(sorted(self._scopes))}
        self._receipt_indices = {key: index for index, key in enumerate(sorted(self._receipts), len(self._entries))}
        self._entries.extend(self._receipts[key] for key in sorted(self._receipts))
        self._tree = MerkleTree(self._entries)
        checked = summarized_history(manifest, chain, digest(manifest))
        self.descriptor = {"schema": 1, "profile": PROFILE, "manifest_sha256": checked["manifest_sha256"],
                           "height": checked["height"], "head_sha256": checked["head_sha256"],
                           "leaf_count": len(self._entries), "root_sha256": self._tree.root}
        self.fingerprint = digest(self.descriptor)

    def _witness(self, index):
        return {"index": index, "entry": self._entries[index], "path": self._tree.path(index)}

    def proof(self, commitment, evidence=None):
        commitment = hex_digest(commitment, "receipt commitment")
        if commitment not in self._receipt_indices:
            raise LabError("The receipt is not included in the selected checkpoint")
        receipt = self._witness(self._receipt_indices[commitment])
        bundle = {"schema": 2, "manifest": self.manifest, "checkpoint": self.descriptor,
                  "receipt_witness": receipt}
        if evidence is not None:
            fields(evidence, "policy transcript receipt", "receipt evidence")
            scope = self._witness(self._scope_indices[digest(receipt["entry"]["scope"])])
            bundle.update({"scope_witness": scope, **evidence})
            verify_compact(bundle, self.descriptor["manifest_sha256"], self.fingerprint)
        return bundle

    def batch_proof(self, commitments, evidence=None):
        """Package a set of receipts with one checkpoint, frontier and shared policy artifacts."""
        references = _receipt_refs(commitments, len(self._receipt_indices))
        self._require_receipts(references)
        if evidence is not None and (not isinstance(evidence, dict) or evidence.keys() != references):
            raise LabError("Batch review requires exactly the evidence for the requested receipts")
        bundle = {"schema": 3, **self._batch_document(references, evidence)}
        if evidence is not None:
            verify_batch(bundle, self.descriptor["manifest_sha256"], self.fingerprint)
        return bundle

    def review_proof(self, plan, trusted_plan, evidence_for):
        """Build a proof while loading private records only for the pinned replay requirements."""
        manifest = self.descriptor["manifest_sha256"]
        modes = validate_review_plan(plan, trusted_plan, manifest, self.fingerprint)
        self._require_receipts(modes.keys())
        evidence = {ref: evidence_for(ref) for ref, mode in modes.items() if mode == "replay"}
        bundle = {"schema": 4, "review_plan": plan, **self._batch_document(modes.keys(), evidence)}
        verify_review_proof(bundle, manifest, self.fingerprint, trusted_plan)
        return bundle

    def _require_receipts(self, references):
        if not references <= self._receipt_indices.keys():
            raise LabError("A requested receipt is not included in the selected checkpoint")

    def _batch_document(self, references, evidence):
        indices = {self._receipt_indices[reference] for reference in references}
        policies, receipts = {}, {}
        if evidence is not None:
            for reference, raw in evidence.items():
                artifact = fields(raw, "policy transcript receipt", "receipt evidence")
                entry = self._receipts[reference]
                indices.add(self._scope_indices[digest(entry["scope"])])
                policy_ref = entry["event"]["payload"]["policy_sha256"]
                if policies.setdefault(policy_ref, artifact["policy"]) != artifact["policy"]:
                    raise LabError("Receipt artifacts disagree on the same committed policy")
                receipts[reference] = {key: artifact[key] for key in ("transcript", "receipt")}
        bundle = {"manifest": self.manifest, "checkpoint": self.descriptor,
                  "leaves": [{"index": index, "entry": self._entries[index]} for index in sorted(indices)],
                  "siblings": self._tree.multipath(indices)}
        if evidence is not None:
            bundle.update(policies=policies, evidence=receipts)
        return bundle


def audit_checkpoint(archive, trusted_fingerprint):
    """Independently certify the input before deriving any accepted fingerprint."""
    if isinstance(archive, dict) and set(archive) == ARCHIVE_FIELDS:
        integer(archive["schema"], "checkpoint archive schema", 1, 1)
        verify_chain(archive["manifest"], archive["chain"], trusted_fingerprint)
    elif isinstance(archive, dict) and type(archive.get("schema")) is int and archive["schema"] == 1:
        verify_review(archive, trusted_fingerprint)
    else:
        raise LabError("Checkpoint audit needs a signed ledger archive or a full-prefix proof")
    return CheckpointIndex(archive["manifest"], archive["chain"])


def workspace_checkpoint(ledger, *, height=None, replica=None):
    if height is not None:
        integer(height, "checkpoint height", 0)
    chain = ledger.prefix(replica, through=height)
    if height is not None and len(chain) != height:
        raise LabError("The selected checkpoint height has not been committed in this store")
    return CheckpointIndex(ledger.manifest, chain), head_document(ledger.manifest, chain)


def checkpoint_delta(archive, base_height):
    """Export the signed suffix of a workspace archive at a committed boundary."""
    chain = archive["chain"]
    base = integer(base_height, "base checkpoint height", 0, len(chain) - 1)
    return {
        "schema": 1, "kind": DELTA_KIND, "manifest_sha256": digest(archive["manifest"]),
        "base_height": base, "base_head_sha256": knowledge_view(chain, known_height=base)["head_sha256"],
        "blocks": chain[base:],
    }


def extend_checkpoint(archive, delta, trusted_manifest, trusted_archive, *,
                      expected_height=None, expected_head=None):
    """Authenticate an independently audited archive, then verify its signed continuation."""
    fields(archive, "schema manifest chain", "audited public archive")
    integer(archive["schema"], "checkpoint archive schema", 1, 1)
    pinned = hex_digest(trusted_archive, "independently trusted archive fingerprint")
    if digest(archive) != pinned:
        raise LabError("Archive does not match the independently trusted archive fingerprint")
    manifest, prefix = archive["manifest"], archive["chain"]
    if trusted_manifest is None:
        raise LabError("An independently trusted manifest fingerprint is required")
    fingerprint = validate_manifest(manifest, trusted_manifest)
    if not isinstance(prefix, list):
        raise LabError("An audited archive must contain an array of blocks")

    fields(delta, "schema kind manifest_sha256 base_height base_head_sha256 blocks", "checkpoint delta")
    integer(delta["schema"], "checkpoint delta schema", 1, 1)
    if delta["kind"] != DELTA_KIND or delta["manifest_sha256"] != fingerprint:
        raise LabError("Checkpoint delta kind or manifest does not match the audited archive")
    base = len(prefix)
    integer(delta["base_height"], "delta base height", base, base)
    if delta["base_head_sha256"] != knowledge_view(prefix)["head_sha256"]:
        raise LabError("Checkpoint delta does not start at the audited archive head")
    blocks = delta["blocks"]
    if not isinstance(blocks, list) or not blocks:
        raise LabError("A checkpoint delta must supply at least one new signed block")
    if expected_height is not None:
        integer(expected_height, "expected target height", base + len(blocks), base + len(blocks))
    verify_appended_blocks(manifest, prefix, blocks)
    if expected_head is not None and blocks[-1]["hash"] != hex_digest(expected_head, "expected target head digest"):
        raise LabError("The extended checkpoint does not match the expected target head")
    chain = prefix + blocks
    return CheckpointIndex(manifest, chain), head_document(manifest, chain)


def _open_witness(witness, descriptor):
    fields(witness, "index entry path", "checkpoint witness")
    entry = witness["entry"]
    verify_path(entry, witness["index"], witness["path"], descriptor["leaf_count"], descriptor["root_sha256"])
    return entry


def _receipt_entry(entry, descriptor, manifest):
    fields(entry, "kind height block_sha256 event scope knowledge actor_keys", "receipt checkpoint entry")
    scope = _read_scope(entry["scope"])
    height = integer(entry["height"], "receipt height", 1, descriptor["height"])
    hex_digest(entry["block_sha256"], "receipt block digest")
    event = fields(entry["event"], "network kind actor payload", "certified receipt event")
    if (entry["kind"] != "receipt" or event["kind"] != "receipt" or event["network"] != manifest["network"]
            or event["actor"] != scope["receiver"] or not {scope["issuer"], scope["receiver"]} <= manifest["actors"].keys()):
        raise LabError("Checkpoint receipt identity or network does not match")
    payload = event["payload"]
    has_knowledge = isinstance(payload, dict) and "knowledge" in payload
    managed = manifest["schema"] == 2
    fields(payload, "policy_sha256 receipt_sha256" + (" knowledge" if has_knowledge else "")
           + (" approval" if managed else ""), "receipt anchor")
    hex_digest(payload["policy_sha256"], "policy commitment")
    hex_digest(payload["receipt_sha256"], "receipt commitment")
    if managed:
        approval = fields(payload["approval"], "height head_sha256", "receipt approval")
        integer(approval["height"], "approval height", height - 1, height - 1)
        hex_digest(approval["head_sha256"], "approval block digest")
        if not has_knowledge:
            raise LabError("Institution-managed receipts require a policy knowledge view")
    if has_knowledge:
        ref = fields(payload["knowledge"], "height head_sha256", "receipt knowledge")
        integer(ref["height"], "knowledge height", 1, height - 1)
        hex_digest(ref["head_sha256"], "knowledge block digest")
        view = fields(entry["knowledge"], "height head_sha256 recorded_at time_basis", "checkpoint knowledge view")
        if any(view[key] != value for key, value in ref.items()) or view["time_basis"] not in ("proposal", "finalization"):
            raise LabError("Checkpoint knowledge view differs from the receipt anchor")
    elif entry["knowledge"] is not None:
        raise LabError("Legacy receipt should have an empty checkpoint knowledge view")
    signer_keys = entry["actor_keys"]
    if not isinstance(signer_keys, dict) or set(signer_keys) != {scope["issuer"], scope["receiver"]}:
        raise LabError("Checkpoint signer keys do not match the receipt scope")
    for key in signer_keys.values():
        hex_digest(key, "historical actor public key")
    return entry


def _policy_history(entry, descriptor, scope):
    fields(entry, "kind scope registrations", "policy timeline entry")
    if entry["kind"] != "policy-scope" or _read_scope(entry["scope"]) != scope:
        raise LabError("Checkpoint policy timeline does not match the receipt scope")
    registrations = entry["registrations"]
    if not isinstance(registrations, list) or not registrations:
        raise LabError("Checkpoint policy timeline must supply ordered registrations")
    history = PolicyHistory()
    last = 0
    for registration in registrations:
        fields(registration, "policy height recorded_at time_basis block_sha256 supersedes reason", "policy registration")
        last = integer(registration["height"], "policy registration height", last + 1, descriptor["height"])
        policy = fields(registration["policy"], POLICY_FIELDS, "policy registration descriptor")
        policy_hash = hex_digest(policy["policy_sha256"], "policy commitment")
        if _scope(policy) != scope or policy_hash in history.policies:
            raise LabError("Checkpoint policy registration is outside the authenticated scope")
        history.policies[policy_hash] = registration
    return history


def _verify_checkpoint(manifest, descriptor, trusted_fingerprint, trusted_checkpoint):
    if trusted_fingerprint is None or trusted_checkpoint is None:
        raise LabError("Compact proof requires independent manifest and checkpoint fingerprints")
    fingerprint = validate_manifest(manifest, trusted_fingerprint)
    fields(descriptor, "schema profile manifest_sha256 height head_sha256 leaf_count root_sha256", "checkpoint descriptor")
    integer(descriptor["schema"], "checkpoint descriptor schema", 1, 1)
    height = integer(descriptor["height"], "checkpoint height", 1)
    integer(descriptor["leaf_count"], "checkpoint leaf count", 1, height)
    hex_digest(descriptor["head_sha256"], "checkpoint block digest")
    pinned = hex_digest(trusted_checkpoint, "independently trusted checkpoint fingerprint")
    if (descriptor["profile"] != PROFILE or descriptor["manifest_sha256"] != fingerprint
            or digest(descriptor) != pinned):
        raise LabError("Checkpoint descriptor does not match the independently trusted fingerprint or manifest")
    return {"manifest_sha256": fingerprint, "checkpoint_sha256": pinned, "checkpoint_height": height,
            "quorum": manifest["quorum"], "mode": manifest["mode"]}


def _receipt_result(entry, manifest, history=None, evidence=None):
    outcome = {"height": entry["height"], "head_sha256": entry["block_sha256"]}
    if evidence is None:
        return {**outcome, "receipt_sha256": entry["event"]["payload"]["receipt_sha256"],
                "anchor_verified": True, "replayed": False}
    keys = KeyRegistry(manifest)
    keys.active["actors"] = entry["actor_keys"]
    replay = replay_receipt_evidence(evidence, manifest, keys, entry["event"], history,
                                     entry["knowledge"], entry["height"])
    return {**outcome, **replay}


def verify_compact(bundle, trusted_fingerprint, trusted_checkpoint):
    full = isinstance(bundle, dict) and "scope_witness" in bundle
    fields(bundle, BASE_PROOF_FIELDS + (" scope_witness policy transcript receipt" if full else ""), "compact proof")
    integer(bundle["schema"], "compact proof schema", 2, 2)
    manifest, descriptor = bundle["manifest"], bundle["checkpoint"]
    checkpoint = _verify_checkpoint(manifest, descriptor, trusted_fingerprint, trusted_checkpoint)
    entry = _receipt_entry(_open_witness(bundle["receipt_witness"], descriptor), descriptor, manifest)
    if not full:
        return {**checkpoint, **_receipt_result(entry, manifest)}
    history = _policy_history(_open_witness(bundle["scope_witness"], descriptor), descriptor, entry["scope"])
    evidence = {key: bundle[key] for key in ("policy", "transcript", "receipt")}
    return {**checkpoint, **_receipt_result(entry, manifest, history, evidence)}


def _batch_entries(bundle, manifest, descriptor, allow_scopes, expected_receipts):
    verify_multiproof(bundle["leaves"], bundle["siblings"], descriptor["leaf_count"], descriptor["root_sha256"])
    entries, histories = {}, {}
    for leaf in bundle["leaves"]:
        entry = leaf["entry"]
        if allow_scopes and isinstance(entry, dict) and entry.get("kind") == "policy-scope":
            scope = _read_scope(entry.get("scope"))
            scope_ref = digest(scope)
            if scope_ref in histories:
                raise LabError("Batch proof repeats a policy timeline")
            histories[scope_ref] = _policy_history(entry, descriptor, scope)
        else:
            checked = _receipt_entry(entry, descriptor, manifest)
            reference = checked["event"]["payload"]["receipt_sha256"]
            if reference in entries:
                raise LabError("Batch proof repeats a receipt")
            entries[reference] = checked
    if not entries:
        raise LabError("Batch proof must include at least one receipt")
    if expected_receipts is not None:
        if _receipt_refs(expected_receipts, descriptor["leaf_count"]) != entries.keys():
            raise LabError("Batch proof does not match the expected receipt set")
    return entries, histories


def _batch_replays(bundle, manifest, entries, histories, replay_refs):
    policies, evidence = bundle.get("policies", {}), bundle.get("evidence", {})
    replay_entries = [entries[ref] for ref in replay_refs]
    scope_refs = {digest(entry["scope"]) for entry in replay_entries}
    policy_refs = {entry["event"]["payload"]["policy_sha256"] for entry in replay_entries}
    if (histories.keys() != scope_refs or not isinstance(policies, dict) or policies.keys() != policy_refs
            or not isinstance(evidence, dict) or evidence.keys() != replay_refs):
        raise LabError("Batch timelines, policies and evidence must match the requested replay set")
    results = []
    for reference, entry in entries.items():
        if reference in replay_refs:
            private = fields(evidence[reference], "transcript receipt", "batch receipt evidence")
            policy_ref = entry["event"]["payload"]["policy_sha256"]
            artifact = {"policy": policies[policy_ref], **private}
            results.append(_receipt_result(entry, manifest, histories[digest(entry["scope"])], artifact))
        else:
            results.append(_receipt_result(entry, manifest))
    return sorted(results, key=lambda result: result["height"])


def verify_batch(bundle, trusted_fingerprint, trusted_checkpoint, *, expected_receipts=None):
    """Authenticate the selected receipts atomically and optionally bind the set to the review request."""
    full = isinstance(bundle, dict) and "evidence" in bundle
    fields(bundle, BATCH_PROOF_FIELDS + (" policies evidence" if full else ""), "batch proof")
    integer(bundle["schema"], "batch proof schema", 3, 3)
    manifest, descriptor = bundle["manifest"], bundle["checkpoint"]
    checkpoint = _verify_checkpoint(manifest, descriptor, trusted_fingerprint, trusted_checkpoint)
    entries, histories = _batch_entries(bundle, manifest, descriptor, full, expected_receipts)
    results = _batch_replays(bundle, manifest, entries, histories, entries.keys() if full else set())
    return {**checkpoint, "batch": True, "receipt_count": len(results), "replayed": full,
            "receipts": results}


def verify_review_proof(bundle, trusted_fingerprint, trusted_checkpoint, trusted_plan, *, expected_receipts=None):
    fields(bundle, BATCH_PROOF_FIELDS + " policies evidence review_plan", "plan-bound proof")
    integer(bundle["schema"], "plan-bound proof schema", 4, 4)
    manifest, descriptor = bundle["manifest"], bundle["checkpoint"]
    checkpoint = _verify_checkpoint(manifest, descriptor, trusted_fingerprint, trusted_checkpoint)
    modes = validate_review_plan(bundle["review_plan"], trusted_plan, checkpoint["manifest_sha256"],
                                 checkpoint["checkpoint_sha256"])
    entries, histories = _batch_entries(bundle, manifest, descriptor, True, expected_receipts)
    if modes.keys() != entries.keys():
        raise LabError("Plan-bound proof must include exactly the planned receipts")
    replay_refs = {ref for ref, mode in modes.items() if mode == "replay"}
    results = _batch_replays(bundle, manifest, entries, histories, replay_refs)
    return {**checkpoint, "batch": True, "receipt_count": len(results), "replayed": len(replay_refs) == len(results),
            "review_plan_sha256": trusted_plan, "replay_count": len(replay_refs),
            "anchor_count": len(results) - len(replay_refs), "receipts": results}
