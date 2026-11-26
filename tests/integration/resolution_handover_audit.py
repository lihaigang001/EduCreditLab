"""Measure authority handover and review at pre- and post-handover publications."""

import argparse
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
from educreditlab.policy_resolution import make_resolution_authority
from educreditlab.resolution_history import (append_resolution_handover, append_resolution_publication,
                                             init_resolution_history, sign_resolution_handover,
                                             sign_resolution_publication, verify_published_resolution,
                                             verify_resolution_history)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(history, tip, initial, incoming, packets, source, response, repeats, output):
    history_bytes = gzip_proof(history)
    old_bytes, current_bytes = packets
    branch = source / "policy-divergence/long"
    left, right = ((branch / f"{side}-quorum.json.gz").read_bytes() for side in ("left", "right"))
    original = (source / "review-plan/review-128.json.gz").read_bytes()

    def verify_archived():
        return verify_published_resolution(decode_proof(history_bytes), decode_proof(old_bytes), initial, tip,
                                           number=1, bundle=decode_proof(left))

    def verify_current(recheck=False):
        evidence = {}
        if recheck:
            evidence = {"proof": decode_proof(original), "trusted_manifest": response["manifest_sha256"],
                        "trusted_checkpoint": response["checkpoint_sha256"]}
        return verify_published_resolution(decode_proof(history_bytes), decode_proof(current_bytes), initial, tip,
                                           bundle=decode_proof(right), **evidence)

    verified, history_time = time_trials(
        lambda: verify_resolution_history(decode_proof(history_bytes), initial, tip), repeats)
    historic, archived_time = time_trials(verify_archived, repeats)
    current, current_time = time_trials(verify_current, repeats)
    checked, replay_time = time_trials(lambda: verify_current(recheck=True), repeats)
    assert verified["authority_handover_count"] == 1 and verified["active_authority_sha256"] == incoming
    assert historic["verified_authority_sha256"] == initial and historic["verified_publication"] == 1
    assert current["verified_authority_sha256"] == incoming
    assert current["verified_publication"] == verified["publication_count"]
    assert historic["result_sha256"] == current["result_sha256"] == checked["result_sha256"] == response["result_sha256"]
    assert checked["proof_rechecked"]
    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "history.json.gz", history_bytes)
    write_json(output / "pins.json", {"initial_authority_sha256": initial, "active_authority_sha256": incoming,
                                      "latest_publication_sha256": tip,
                                      "current_decision_sha256": verified["current_decision_sha256"]})
    return {**verified, "history_gzip_bytes": len(history_bytes), "verify_history": history_time,
            "verify_archived_review": archived_time, "verify_current_review": current_time,
            "with_evidence": replay_time}


def experiment(source, output, repeats):
    baseline = source / "policy-divergence"
    exhibit = read_proof(baseline / "divergence.json.gz")
    pins = read_json(baseline / "long/pins.json")

    def make_authority(threshold):
        keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        profile = make_resolution_authority(pins["initial_policy_sha256"],
                                            [reviewer_fingerprint(public_key(k)) for k in keys], threshold)
        return profile, digest(profile), keys[:threshold]

    original, initial_pin, outgoing_keys = make_authority(2)
    successor, incoming_pin, incoming_keys = make_authority(3)
    old, new = [make_packet(profile, exhibit, read_proof(baseline / f"long/{side}.json.gz"), keys,
                            pin, pins[f"{side}_latest_revision_sha256"])
                for side, profile, pin, keys in (("left", original, initial_pin, outgoing_keys),
                                                 ("right", successor, incoming_pin, incoming_keys))]
    old_decision, new_decision = (digest(packet["decision"]) for packet in (old, new))
    empty, genesis = init_resolution_history(original, exhibit, initial_pin)

    def publish(history, tip, packet, decision, keys):
        approvals = [sign_resolution_publication(history, packet, key, initial_pin, tip, decision)
                     for key in keys]
        return append_resolution_publication(history, packet, approvals, initial_pin, tip, decision)

    initial, old_tip = publish(empty, genesis, old, old_decision, outgoing_keys)
    approvals = {
        role: [sign_resolution_handover(initial, new, successor, key, initial_pin, old_tip, new_decision,
                                        trusted_successor=incoming_pin, role=role) for key in keys]
        for role, keys in (("outgoing", outgoing_keys), ("incoming", incoming_keys))
    }
    handover, handover_tip = append_resolution_handover(initial, new, successor, approvals, initial_pin, old_tip,
                                                        new_decision, trusted_successor=incoming_pin)
    for role in approvals:
        insufficient = {**approvals, role: approvals[role][:-1]}
        expect_rejection(lambda: append_resolution_handover(initial, new, successor, insufficient, initial_pin, old_tip,
                                                            new_decision, trusted_successor=incoming_pin),
                         f"{role.capitalize()} authority approval failed")
    short, short_tip = publish(handover, handover_tip, new, new_decision, incoming_keys)
    longer, long_tip = short, short_tip
    for _ in range(24):
        longer, long_tip = publish(longer, long_tip, new, new_decision, incoming_keys)
    assert longer["publications"][:1] == initial["publications"] and len(longer["publications"]) == 27
    expect_rejection(lambda: sign_resolution_publication(longer, new, outgoing_keys[0], initial_pin,
                                                         long_tip, new_decision), "outside the trusted resolution authority")
    expect_rejection(lambda: verify_resolution_history(initial, initial_pin, long_tip),
                     "independently expected latest publication")

    response = json.loads((baseline / "measurement.json").read_text(encoding="utf-8"))["review"]
    evidence = read_proof(source / "review-plan/review-128.json.gz")
    assert digest(evidence) == response["proof_sha256"]
    historical = verify_published_resolution(longer, old, initial_pin, long_tip, number=1,
                                             bundle=read_proof(baseline / "long/left-quorum.json.gz"),
                                             proof=evidence, trusted_manifest=response["manifest_sha256"],
                                             trusted_checkpoint=response["checkpoint_sha256"])
    assert historical["proof_rechecked"] and historical["result_sha256"] == response["result_sha256"]
    assert (historical["receipt_count"], historical["replay_count"], historical["anchor_count"]) == (128, 16, 112)
    assert historical["verified_authority_sha256"] == initial_pin
    packets = (gzip_proof(old), gzip_proof(new))
    cases = [measure(log, tip, initial_pin, incoming_pin, packets, source, response, repeats, output / label)
             for label, (log, tip) in zip(("short", "long"), ((short, short_tip), (longer, long_tip)), strict=True)]
    write_bytes(output / "outgoing-resolution.json.gz", packets[0])
    write_bytes(output / "incoming-resolution.json.gz", packets[1])
    write_bytes(output / "prior-history.json.gz", gzip_proof(initial))
    write_json(output / "prior-pins.json", {"initial_authority_sha256": initial_pin, "latest_publication_sha256": old_tip})
    write_json(output / "outgoing-authority.json", original)
    write_json(output / "incoming-authority.json", successor)
    return {"cases": cases, "initial_threshold": original["threshold"], "successor_threshold": successor["threshold"],
            "initial_roster_size": len(original["resolver_sha256"]), "successor_roster_size": len(successor["resolver_sha256"]),
            "handover_publication": 2, "review": response, "historical_publication_verified": 1,
            "legacy_entries_preserved": True, "both_thresholds_required": True,
            "retired_key_rejected": True, "stale_history_rejected": True, "historical_result_replayed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default="results", help="Result directory with packaged histories and proof")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--repeats", type=int, default=21)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("Use a positive repeat count")
    output = Path(args.out_dir)
    measured = experiment(Path(args.source), output, args.repeats)
    write_json(output / "measurement.json", {"software_version": __version__, "platform": platform.platform(),
                                               "python": platform.python_version(), **measured})
    for case in measured["cases"]:
        print(f'{case["publication_count"]} entries, {case["history_gzip_bytes"]} history bytes, '
              f'{case["verify_history"]["median_ms"]:.3f} ms history verification, '
              f'{case["verify_archived_review"]["median_ms"]:.3f} ms archived review', flush=True)


if __name__ == "__main__":
    main()
