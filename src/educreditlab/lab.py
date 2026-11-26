"""Publish signed policy snapshots, issue review receipts and replay a checked case."""

from __future__ import annotations

from importlib.resources import files
from secrets import token_hex

import sqlite3

from .keys import KeyRegistry, verify
from .ledger import Ledger, policy_descriptor, summarized_history, verify_chain
from .model import (LabError, canonical, day, digest, fields, hex_digest, integer, loads,
                    normalize_policy, normalize_transcript, text)
from .solver import evaluate
from .temporal import PolicyHistory, knowledge_view

DEMO_ACTORS = ("glendale-cc", "uc-irvine", "uc-merced")
DEMO_AMENDMENT = "uc-irvine-sim-ay2022-23-r2.json"
DEMO_REASON = "Synthetic case: raise both programming-series thresholds from C to B from June 2023"


def bundled_data(name):
    return loads(files("educreditlab").joinpath("data", name).read_bytes())


def verify_transcript(envelope, manifest, keys=None):
    fields(envelope, "body signature", "signed transcript")
    body = fields(envelope["body"], "network transcript salt", "transcript body")
    if body["network"] != manifest["network"]:
        raise LabError("Transcript is signed for a different network")
    hex_digest(body["salt"], "transcript salt")
    transcript = normalize_transcript(body["transcript"])
    if canonical(transcript) != canonical(body["transcript"]):
        raise LabError("Transcript is not in normalized form")
    keys = KeyRegistry(manifest) if keys is None else keys
    verify(keys.active_key("actor", transcript["issuer"]), "transcript", body, envelope["signature"])
    return transcript


class Lab:
    """Application API over the same solver and either ledger backend."""

    def __init__(self, directory, mode="consortium", actors=DEMO_ACTORS, *, managed_manifest=None):
        self.ledger = Ledger(directory, mode, actors, managed_manifest=managed_manifest)

    @classmethod
    def open(cls, directory):
        manifest = Ledger.read_manifest(directory)
        if manifest is None:
            raise LabError("Workspace has not been initialized. Run educreditlab init first.")
        return cls(directory, manifest["mode"], manifest["actors"])

    @classmethod
    def workbench(cls, directory, mode="consortium", *, seed=False):
        manifest = Ledger.read_manifest(directory)
        if manifest is None:
            lab = cls(directory, mode)
        else:
            lab = cls(directory, manifest["mode"], manifest["actors"])
        if manifest is None or (seed and not lab.ledger.managed):
            lab.seed()
        return lab

    def publish(self, policy):
        policy = normalize_policy(policy)
        descriptor = policy_descriptor(policy)
        event = self.ledger.event("policy", policy["receiver"], descriptor)
        return self.ledger.append(event, artifact=policy)

    def revise(self, policy, supersedes, reason, *, available=None):
        policy = normalize_policy(policy)
        event = self.ledger.event("policy-revision", policy["receiver"], {
            "policy": policy_descriptor(policy),
            "supersedes": hex_digest(supersedes, "superseded policy hash"),
            "reason": text(reason, "revision reason", 400),
        })
        return self.ledger.append(event, available, artifact=policy)

    def descriptors(self):
        return [item["policy"] for item in self.policy_history()]

    def policy_history(self, prefix=None):
        return list(PolicyHistory(self.ledger.prefix() if prefix is None else prefix).policies.values())

    def _choose_policy(self, prefix, issuer, receiver, programme, as_of, *, known_height=None, known_at=None):
        knowledge = knowledge_view(prefix, known_height=known_height, known_at=known_at)
        entry = PolicyHistory(prefix).select(issuer, receiver, programme, as_of, knowledge["height"])
        return self.registered_policy(entry["policy"]), {"knowledge": knowledge, "registration": entry}

    def policy(self, issuer, receiver, programme, as_of, *, known_height=None, known_at=None):
        selected, _ = self._choose_policy(self.ledger.prefix(), issuer, receiver, programme, as_of,
                                          known_height=known_height, known_at=known_at)
        return selected

    def registered_policy(self, descriptor):
        policy = normalize_policy(self.ledger.artifact(descriptor["policy_sha256"], "policy"))
        if policy_descriptor(policy) != descriptor:
            raise LabError("Stored policy does not match its registered commitment")
        return policy

    def assess(self, transcript, receiver, programme, as_of, *, known_height=None, known_at=None, **options):
        return self._assess_from_verified_prefix(self.ledger.prefix(), transcript, receiver, programme, as_of,
                                                 known_height=known_height, known_at=known_at, **options)

    def _assess_from_verified_prefix(self, prefix, transcript, receiver, programme, as_of, *,
                                     known_height=None, known_at=None, **options):
        transcript = normalize_transcript(transcript)
        policy, view = self._choose_policy(prefix, transcript["issuer"], receiver,
                                           programme, as_of, known_height=known_height, known_at=known_at)
        return {"decision": evaluate(policy, transcript, as_of, **options), "policy_view": view}

    def preview(self, transcript, receiver, programme, as_of, **options):
        return self.assess(transcript, receiver, programme, as_of, **options)["decision"]

    def compare(self, transcript, receiver, programme, as_of, before_height, after_height=None):
        transcript = normalize_transcript(transcript)
        prefix = self.ledger.prefix()
        before_height = integer(before_height, "earlier knowledge height", 0, len(prefix))
        assessments = []
        for height in (before_height, after_height):
            policy, view = self._choose_policy(prefix, transcript["issuer"], receiver, programme, as_of,
                                               known_height=height)
            assessments.append({"decision": evaluate(policy, transcript, as_of), "policy_view": view})
        before, after = assessments
        if before["policy_view"]["knowledge"]["height"] > after["policy_view"]["knowledge"]["height"]:
            raise LabError("The earlier knowledge height must not exceed the later one")
        previous, revised = before["decision"], after["decision"]
        old_rules = {row["id"] for row in previous["rules"] if row["status"] == "recognized"}
        new_rules = {row["id"] for row in revised["rules"] if row["status"] == "recognized"}
        units = (revised["recognized_units"] - previous["recognized_units"]
                 if previous["unit"] == revised["unit"] else None)
        return {"as_of": day(as_of, "as_of"), "before": before, "after": after,
                "delta": {"units": units, "added_rules": sorted(new_rules - old_rules),
                          "removed_rules": sorted(old_rules - new_rules)}}

    def sign_transcript(self, transcript, *, salt=None):
        transcript = normalize_transcript(transcript)
        body = {"network": self.ledger.manifest["network"], "transcript": transcript,
                "salt": token_hex(32) if salt is None else hex_digest(salt, "transcript salt")}
        return {"body": body, "signature": self.ledger.sign_as(transcript["issuer"],
                                                              "transcript", body)}

    def record(self, signed, receiver, programme, as_of, *, nonce=None, available=None,
               known_height=None, known_at=None):
        self.ledger.require_local_signing()
        transcript = verify_transcript(signed, self.ledger.manifest)
        selected, view = self._choose_policy(self.ledger.prefix(), transcript["issuer"], receiver,
                                             programme, as_of, known_height=known_height, known_at=known_at)
        if nonce is not None and known_height is None and known_at is None:
            key = digest({"purpose": "cli receipt", "transcript": digest(signed), "receiver": receiver,
                          "programme": programme, "as_of": as_of,
                          "nonce": hex_digest(nonce, "receipt salt")})
            saved = self.ledger.reserve_request(key, _selection(view))
            selected, view = self._restore_selection(saved, transcript, receiver, programme, as_of)
        return self._record_selected(signed, transcript, selected, view, as_of, nonce, available)

    def _restore_selection(self, saved, transcript, receiver, programme, as_of):
        fields(saved, "height head_sha256", "saved knowledge selection")
        selected, view = self._choose_policy(self.ledger.prefix(), transcript["issuer"], receiver,
                                             programme, as_of, known_height=saved["height"])
        if _selection(view) != saved:
            raise LabError("The saved receipt request refers to a different committed history")
        return selected, view

    def _record_selected(self, signed, transcript, policy, view, as_of, nonce, available):
        decision = evaluate(policy, transcript, as_of)
        receipt_body = {"network": self.ledger.manifest["network"], "schema": 1,
                        "salt": token_hex(32) if nonce is None else hex_digest(nonce, "receipt salt"),
                        "transcript_commitment": digest(signed), "decision": decision}
        receipt = {"body": receipt_body,
                   "signature": self.ledger.sign_as(policy["receiver"], "receipt", receipt_body)}
        commitment = digest(receipt)
        block = self.ledger.append(
            self.ledger.event("receipt", policy["receiver"], {"policy_sha256": decision["policy_sha256"],
                                                              "receipt_sha256": commitment,
                                                              "knowledge": _selection(view)}), available,
            artifact={"policy": policy, "transcript": signed, "receipt": receipt})
        actual = block["core"]["event"]["body"]["payload"].get("knowledge")
        knowledge = view["knowledge"]
        if actual != _selection(view):
            knowledge = (None if actual is None else
                         knowledge_view(self.ledger.prefix(), known_height=actual["height"]))
        return {"receipt_sha256": commitment, "height": block["core"]["height"],
                "head_sha256": block["hash"], "decision": decision, "votes": sorted(block["votes"]),
                "policy_view": {"knowledge": knowledge, "registration": view["registration"]}}

    def issue_workbench_receipt(self, transcript, receiver, programme, as_of, *,
                                available=None, known_height=None, known_at=None):
        self.ledger.require_local_signing()
        transcript = normalize_transcript(transcript)
        policy, view = self._choose_policy(self.ledger.prefix(), transcript["issuer"], receiver,
                                           programme, as_of, known_height=known_height, known_at=known_at)
        key = digest({"transcript": transcript, "policy_sha256": digest(policy), "as_of": as_of})
        saved = self.ledger.reserve_request(key, {"transcript_salt": token_hex(32),
                                                   "nonce": token_hex(32), "knowledge": _selection(view)})
        has_knowledge = isinstance(saved, dict) and "knowledge" in saved
        fields(saved, "transcript_salt nonce knowledge" if has_knowledge else "transcript_salt nonce",
               "stored workbench request")
        if has_knowledge:
            first_policy, view = self._restore_selection(saved["knowledge"], transcript, receiver, programme, as_of)
            if digest(first_policy) != digest(policy):
                raise LabError("Stored workbench request selects a different policy")
        signed = self.sign_transcript(transcript, salt=saved["transcript_salt"])
        return self._record_selected(signed, transcript, policy, view, as_of, saved["nonce"], available)

    def _collect_bundle(self, commitment, replica, anchor_only):
        prefix = self.ledger.receipt_prefix(commitment, replica)
        proof = {"schema": 1, "manifest": self.ledger.manifest, "chain": prefix}
        if anchor_only:
            return {**proof, "receipt_sha256": commitment}
        artifacts = self.ledger.artifact(commitment, "receipt")
        fields(artifacts, "policy transcript receipt", "stored receipt artifacts")
        return {**proof, **artifacts}

    def bundle(self, commitment, replica=None, *, anchor_only=False):
        bundle = self._collect_bundle(commitment, replica, anchor_only)
        if not anchor_only:
            self._check_collected_bundle(bundle)
        return bundle

    def _check_collected_bundle(self, collected):
        # _collect_bundle obtains its prefix only from the checked local ledger.
        manifest, chain = collected["manifest"], collected["chain"]
        return {**summarized_history(manifest, chain, self.ledger.fingerprint),
                **_receipt_from_verified_bundle(collected)}

    def replay_from_replica(self, commitment):
        commitment = hex_digest(commitment, "receipt commitment")
        if self.ledger.managed:
            bundle = self._collect_bundle(commitment, None, anchor_only=False)
            return {**self._check_collected_bundle(bundle), "replica": "coordinator"}
        for name in self.ledger.manifest["validators"]:
            try:
                bundle = self._collect_bundle(commitment, name, anchor_only=False)
                checked = self._check_collected_bundle(bundle)
            except (LabError, OSError, sqlite3.Error):
                continue
            return {**checked, "replica": name}
        raise LabError("No replica can replay this receipt. Check replica status and stored evidence.")

    def seed(self):
        if tuple(self.ledger.manifest["actors"]) != DEMO_ACTORS:
            raise LabError("The built-in scenarios require the demonstration institution registry")
        return [self.publish(policy) for policy in bundled_data("policies.json")]

    def seed_amendment(self):
        if tuple(self.ledger.manifest["actors"]) != DEMO_ACTORS:
            raise LabError("The built-in revision requires the demonstration institution registry")
        parent = normalize_policy(bundled_data("policies.json")[0])
        return self.revise(bundled_data(DEMO_AMENDMENT), digest(parent), DEMO_REASON)


def _selection(view):
    return {key: view["knowledge"][key] for key in ("height", "head_sha256")}


def verify_review(bundle, trusted_fingerprint, *, trusted_checkpoint=None, expected_receipts=None,
                  trusted_plan=None):
    schema = bundle.get("schema") if isinstance(bundle, dict) else None
    if type(schema) is int and schema == 4:
        from .checkpoint import verify_review_proof
        return verify_review_proof(bundle, trusted_fingerprint, trusted_checkpoint, trusted_plan,
                                   expected_receipts=expected_receipts)
    if trusted_plan is not None:
        raise LabError("A review plan fingerprint applies to plan-bound proofs only")
    if type(schema) is int and schema == 3:
        from .checkpoint import verify_batch
        return verify_batch(bundle, trusted_fingerprint, trusted_checkpoint, expected_receipts=expected_receipts)
    if expected_receipts is not None:
        raise LabError("An expected receipt set applies to batch proofs only")
    if type(schema) is int and schema == 2:
        from .checkpoint import verify_compact
        return verify_compact(bundle, trusted_fingerprint, trusted_checkpoint)
    if trusted_checkpoint is not None:
        raise LabError("A checkpoint fingerprint applies to compact proofs only")
    if isinstance(bundle, dict) and set(bundle) == {"schema", "manifest", "chain", "receipt_sha256"}:
        integer(bundle["schema"], "anchor schema", 1, 1)
        commitment = hex_digest(bundle["receipt_sha256"], "receipt commitment")
        chain = bundle["chain"]
        verified = verify_chain(bundle["manifest"], chain, trusted_fingerprint)
        if not chain:
            raise LabError("The anchor bundle has no receipt block")
        event = chain[-1]["core"]["event"]["body"]
        if event["kind"] != "receipt" or event["payload"]["receipt_sha256"] != commitment:
            raise LabError("The final certified block does not anchor this receipt")
        return {**verified, "receipt_sha256": commitment, "anchor_verified": True, "replayed": False}
    return verify_bundle(bundle, trusted_fingerprint)


def verify_bundle(bundle, trusted_fingerprint):
    fields(bundle, "schema manifest chain policy transcript receipt", "review bundle")
    integer(bundle["schema"], "bundle schema", 1, 1)
    manifest, chain = bundle["manifest"], bundle["chain"]
    verified = verify_chain(manifest, chain, trusted_fingerprint)
    if not chain:
        raise LabError("The review bundle has no receipt block")
    return {**verified, **_receipt_from_verified_bundle(bundle)}


def _receipt_from_verified_bundle(bundle):
    artifact = {key: bundle[key] for key in ("policy", "transcript", "receipt")}
    chain = bundle["chain"]
    return verify_receipt_evidence(artifact, bundle["manifest"], chain[:-1], chain[-1]["core"]["event"]["body"])


def verify_receipt_evidence(artifact, manifest, prefix, event):
    """Check the private evidence against a verified public receipt approval view."""
    history = PolicyHistory(prefix)
    height = event["payload"]["knowledge"]["height"] if "knowledge" in event["payload"] else None
    knowledge = knowledge_view(prefix, known_height=height) if height is not None else None
    return replay_receipt_evidence(artifact, manifest, KeyRegistry(manifest, prefix), event, history,
                                  knowledge, len(prefix) + 1)


def replay_receipt_evidence(artifact, manifest, keys, event, history, knowledge, receipt_height):
    """Replay receipt evidence with a previously authenticated policy and signing state."""
    fields(artifact, "policy transcript receipt", "receipt evidence")
    transcript = verify_transcript(artifact["transcript"], manifest, keys)
    policy = normalize_policy(artifact["policy"])
    if canonical(policy) != canonical(artifact["policy"]):
        raise LabError("Policy is not in normalized form")
    receipt = fields(artifact["receipt"], "body signature", "signed receipt")
    body = fields(receipt["body"], "schema network salt transcript_commitment decision",
                  "receipt body")
    integer(body["schema"], "receipt schema", 1, 1)
    hex_digest(body["salt"], "receipt salt")
    if body["network"] != manifest["network"] or body["transcript_commitment"] != digest(
            artifact["transcript"]):
        raise LabError("Receipt does not match the signed transcript and trust domain")
    descriptor = policy_descriptor(policy)
    verify(keys.active_key("actor", policy["receiver"]), "receipt", body, receipt["signature"])
    commitment = digest(receipt)
    if (event["kind"] != "receipt" or event["actor"] != policy["receiver"]
            or event["payload"]["policy_sha256"] != descriptor["policy_sha256"]
            or event["payload"]["receipt_sha256"] != commitment):
        raise LabError("The final certified block does not anchor this receipt")
    registration = history.policies.get(descriptor["policy_sha256"])
    if (registration is None or registration["policy"] != descriptor
            or registration["height"] >= receipt_height):
        raise LabError("The committed policy was unavailable at the receipt's height")
    decision = body["decision"]
    if not isinstance(decision, dict):
        raise LabError("A receipt must contain a decision object")
    if "knowledge" in event["payload"]:
        expected = event["payload"]["knowledge"]
        if knowledge is None or any(knowledge[key] != value for key, value in expected.items()):
            raise LabError("Receipt knowledge view differs from the authenticated history")
        applicable = history.select(transcript["issuer"], policy["receiver"], policy["programme"],
                                    decision.get("as_of"), knowledge["height"])
        if applicable != registration:
            raise LabError("Receipt policy is not effective in the signed knowledge view")
    replay = evaluate(policy, transcript, decision.get("as_of"))
    if canonical(replay) != canonical(decision):
        raise LabError("Replayed decision differs from its signed receipt")
    return {"receipt_sha256": commitment, "replayed": True, "decision": replay,
            "policy_view": {"knowledge": knowledge, "registration": registration}}

