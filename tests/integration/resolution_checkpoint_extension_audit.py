"""Compare signed publication deltas with a complete audit of the same endpoint."""

import argparse
from copy import deepcopy
import json
import platform
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from checkpoint_audit import time_trials
from policy_resolution_audit import make_packet
from revision_review_audit import expect_rejection
from educreditlab import __version__
from educreditlab.keys import public_key
from educreditlab.model import digest, read_json, write_bytes, write_json
from educreditlab.policy_resolution import _approval_signer, _sign_approval, make_resolution_authority
from educreditlab.resolution_checkpoint import (audit_resolution_checkpoint, extend_resolution_checkpoint,
                                               resolution_checkpoint_delta, verify_checkpoint_resolution)
from educreditlab.resolution_history import (HANDOVER_DOMAINS, PUBLICATION_DOMAIN, _handover_body, _publication_body,
                                            init_resolution_history)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.transport import decode_proof, gzip_proof, read_proof, write_proof

PREFIX_SIZES = {"short": 31, "long": 1023}
NEW_PUBLICATIONS = 8


def make_authority(initial_policy, threshold):
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    profile = make_resolution_authority(initial_policy, [reviewer_fingerprint(public_key(key)) for key in keys],
                                        threshold)
    return profile, keys[:threshold]


def approvals(profile, body, keys, domain):
    return sorted((_sign_approval(profile, body, key, domain=domain) for key in keys), key=_approval_signer)


def generate(source, output, *, prefix_sizes=PREFIX_SIZES, new_publications=NEW_PUBLICATIONS):
    policy = source / "policy-divergence"
    evidence = read_proof(policy / "divergence.json.gz")
    pins = read_json(policy / "long/pins.json")
    original, outgoing_keys = make_authority(pins["initial_policy_sha256"], 2)
    successor, incoming_keys = make_authority(pins["initial_policy_sha256"], 3)
    initial, incoming = digest(original), digest(successor)
    decisions = []
    for label, branch, authority, keys in (("outgoing", "left", original, outgoing_keys),
                                           ("incoming", "right", successor, incoming_keys)):
        packet = make_packet(authority, evidence, read_proof(policy / f"long/{branch}.json.gz"), keys,
                             digest(authority), pins[f"{branch}_latest_revision_sha256"])
        write_proof(output / f"{label}-resolution.json.gz", packet)
        decisions.append(digest(packet["decision"]))
    old_decision, new_decision = decisions
    history, root = init_resolution_history(original, evidence, initial)
    # Construct controlled, signed sequences, then validate each with the public audit API.
    prefix = []
    tip = root
    for number in range(1, max(prefix_sizes.values()) + 1):
        body = _publication_body(root, tip, number, old_decision)
        prefix.append({"body": body, "approvals": approvals(original, body, outgoing_keys, PUBLICATION_DOMAIN)})
        tip = digest(body)
    for label, size in prefix_sizes.items():
        base_tip = digest(prefix[size - 1]["body"])
        handover = _handover_body(_publication_body(root, base_tip, size + 1, new_decision), successor)
        signed = {role: approvals(profile, handover, keys, HANDOVER_DOMAINS[role])
                  for role, profile, keys in (("outgoing", original, outgoing_keys),
                                               ("incoming", successor, incoming_keys))}
        suffix = [{"body": handover, "approvals": signed}]
        tip = digest(handover)
        for number in range(size + 2, size + new_publications + 1):
            body = _publication_body(root, tip, number, new_decision)
            suffix.append({"body": body, "approvals": approvals(successor, body, incoming_keys, PUBLICATION_DOMAIN)})
            tip = digest(body)
        case = output / label
        case.mkdir()
        write_proof(case / "history.json.gz", {**history, "schema": 2, "publications": [*prefix[:size], *suffix]})
        write_json(case / "endpoints.json", {"initial_authority_sha256": initial, "incoming_authority_sha256": incoming,
                                            "base_publication_count": size, "base_publication_sha256": base_tip,
                                            "latest_publication_sha256": tip})


def measure(source, fixture, output, repeats, evidence, expected_review):
    history_wire = (fixture / "history.json.gz").read_bytes()
    pins = read_json(fixture / "endpoints.json")
    base_number, latest = pins["base_publication_count"], pins["latest_publication_sha256"]
    initial = pins["initial_authority_sha256"]
    history = decode_proof(history_wire)
    base = {**history, "schema": 1, "publications": history["publications"][:base_number]}
    index = audit_resolution_checkpoint(base, initial, pins["base_publication_sha256"])
    base_pin = index.fingerprint
    base_wire = gzip_proof(index.witness())
    delta = resolution_checkpoint_delta(history, initial, latest, from_number=base_number)
    delta_wire = gzip_proof(delta)
    assert len(delta["publications"]) == NEW_PUBLICATIONS

    def full_audit():
        complete = audit_resolution_checkpoint(decode_proof(history_wire), initial, latest)
        return complete.witness(), complete.fingerprint

    def extend():
        advanced = extend_resolution_checkpoint(decode_proof(base_wire), decode_proof(delta_wire), base_pin, latest)
        return advanced, digest(advanced["checkpoint"])

    expected, full_time = time_trials(full_audit, repeats)
    (advanced, next_pin), extension_time = time_trials(extend, repeats)
    assert (advanced, next_pin) == expected
    assert advanced["entry"]["authority_sha256"] == pins["incoming_authority_sha256"]
    assert advanced["entry"]["number"] == base_number + NEW_PUBLICATIONS
    expect_rejection(lambda: extend_resolution_checkpoint(index.witness(), {**delta, "publications": delta["publications"][:-1]},
                                                         base_pin, latest), "independently expected latest publication")
    for role in ("outgoing", "incoming"):
        short = deepcopy(delta)
        short["publications"][0]["approvals"][role].pop()
        expect_rejection(lambda: extend_resolution_checkpoint(index.witness(), short, base_pin, latest),
                         f"{role.capitalize()} authority approval failed")

    for selection, authority, witness, pin, branch in (
            ("outgoing", initial, index.witness(), base_pin, "left"),
            ("incoming", pins["incoming_authority_sha256"], advanced, next_pin, "right")):
        packet = read_proof(fixture.parent / f"{selection}-resolution.json.gz")
        confirmation = read_proof(source / f"policy-divergence/long/{branch}-quorum.json.gz")
        review = verify_checkpoint_resolution(witness, packet, pin, bundle=confirmation, proof=evidence,
                                              trusted_manifest=expected_review["manifest_sha256"],
                                              trusted_checkpoint=expected_review["checkpoint_sha256"],
                                              expected_proof=expected_review["proof_sha256"])
        assert review["proof_rechecked"] and review["verified_authority_sha256"] == authority
        for field in ("receipt_count", "replay_count", "anchor_count", "result_sha256"):
            assert review[field] == expected_review[field]

    output.mkdir(parents=True, exist_ok=True)
    for name, wire in (("base-witness.json.gz", base_wire), ("delta.json.gz", delta_wire),
                       ("advanced-witness.json.gz", gzip_proof(advanced))):
        write_bytes(output / name, wire)
    write_json(output / "pins.json", {**pins, "base_checkpoint_sha256": base_pin, "advanced_checkpoint_sha256": next_pin})
    return {"base_publication_count": base_number, "verified_new_publications": NEW_PUBLICATIONS,
            "publication_count": advanced["entry"]["number"], "history_gzip_bytes": len(history_wire),
            "base_witness_gzip_bytes": len(base_wire), "delta_gzip_bytes": len(delta_wire),
            "extension_input_gzip_bytes": len(base_wire) + len(delta_wire), "full_audit": full_time, "extension": extension_time,
            "advanced_checkpoint_sha256": next_pin, "matches_full_audit": True, "receipt_evidence_rechecked": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Directory containing packaged signed fixtures")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    parser.add_argument("--generate", action="store_true", help="Generate a fresh synthetic fixture in an empty output directory")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    source, output = Path(args.source), Path(args.out_dir)
    fixture = source / "resolution-checkpoint-extension"
    if args.generate:
        output.mkdir(parents=True, exist_ok=True)
        if any(output.iterdir()):
            parser.error("Use an empty directory to generate new signed fixtures")
        generate(source, output)
        fixture = output
    expected = json.loads((source / "resolution-handover/measurement.json").read_text(encoding="utf-8"))["review"]
    evidence = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(evidence) == expected["proof_sha256"]
    cases = [measure(source, fixture / label, output / label, args.repeats, evidence, expected) for label in PREFIX_SIZES]
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                             "python": platform.python_version(), "repeats": args.repeats,
                                             "original_review": expected, "cases": cases})
    for case in cases:
        print(f'{case["base_publication_count"]} + {case["verified_new_publications"]} publications: '
              f'{case["history_gzip_bytes"]} -> {case["extension_input_gzip_bytes"]} bytes, '
              f'{case["full_audit"]["median_ms"]:.3f} -> {case["extension"]["median_ms"]:.3f} ms, '
              "identical advance and complete audit")


if __name__ == "__main__":
    main()
