"""Measure ordered institutional publications and archival review of a chosen decision."""

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
from educreditlab.resolution_history import (append_resolution_publication, init_resolution_history,
                                             sign_resolution_publication, verify_published_resolution,
                                             verify_resolution_history)
from educreditlab.review_attestation import reviewer_fingerprint
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(history, tip, authority, packet_bytes, confirmation, evidence, prior_review, repeats, output):
    history_bytes = gzip_proof(history)
    manifest, checkpoint = (prior_review[k] for k in ("manifest_sha256", "checkpoint_sha256"))

    def verify_review(recheck=False):
        options = {}
        if recheck:
            options = {"proof": decode_proof(evidence), "trusted_manifest": manifest, "trusted_checkpoint": checkpoint}
        return verify_published_resolution(decode_proof(history_bytes), decode_proof(packet_bytes), authority, tip,
                                           bundle=decode_proof(confirmation), **options)

    status, history_time = time_trials(
        lambda: verify_resolution_history(decode_proof(history_bytes), authority, tip), repeats)
    confirmed, review_time = time_trials(verify_review, repeats)
    checked, evidence_time = time_trials(lambda: verify_review(recheck=True), repeats)
    assert status["resolution_history_verified"] and status["publication_count"] == confirmed["verified_publication"]
    assert status["current_decision_sha256"] == confirmed["decision_sha256"] == checked["decision_sha256"]
    assert confirmed["revision_binding_verified"] and checked["proof_rechecked"]
    assert (checked["receipt_count"], checked["replay_count"], checked["anchor_count"]) == (128, 16, 112)
    assert checked["result_sha256"] == confirmed["result_sha256"] == prior_review["result_sha256"]
    output.mkdir(parents=True, exist_ok=True)
    write_bytes(output / "history.json.gz", history_bytes)
    pins = {key: status[key] for key in ("authority_sha256", "latest_publication_sha256", "current_decision_sha256")}
    write_json(output / "pins.json", pins)
    return {**status, "history_gzip_bytes": len(history_bytes), "packet_gzip_bytes": len(packet_bytes),
            "verify_history": history_time, "verify_review": review_time, "with_evidence": evidence_time}


def experiment(source, output, repeats):
    previous = source / "policy-divergence"
    exhibits = read_proof(previous / "divergence.json.gz")
    pins = read_json(previous / "long/pins.json")
    keys = [Ed25519PrivateKey.generate() for _ in range(3)]
    profile = make_resolution_authority(pins["initial_policy_sha256"],
                                        [reviewer_fingerprint(public_key(key)) for key in keys], 2)
    authority = digest(profile)
    first, second = [make_packet(profile, exhibits, read_proof(previous / f"long/{side}.json.gz"),
                                 keys[:2], authority, pins[f"{side}_latest_revision_sha256"])
                     for side in ("left", "right")]
    first_decision, second_decision = (digest(packet["decision"]) for packet in (first, second))
    initial, initial_tip = init_resolution_history(profile, exhibits, authority)

    def publish(history, tip, packet, decision):
        approvals = [sign_resolution_publication(history, packet, key, authority, tip, decision) for key in keys[:2]]
        return append_resolution_publication(history, packet, approvals, authority, tip, decision)

    once, first_tip = publish(initial, initial_tip, first, first_decision)
    twice, second_tip = publish(once, first_tip, second, second_decision)
    short, short_tip = publish(twice, second_tip, first, first_decision)
    longer, long_tip = short, short_tip
    for _ in range(12):
        changed, changed_tip = publish(longer, long_tip, second, second_decision)
        longer, long_tip = publish(changed, changed_tip, first, first_decision)
    assert len(longer["publications"]) == 27
    assert len({first_tip, short_tip, long_tip}) == 3
    expect_rejection(lambda: verify_resolution_history(twice, authority, long_tip),
                     "independently expected latest publication")
    expect_rejection(lambda: verify_published_resolution(longer, second, authority, long_tip),
                     "independently expected decision")

    former = read_proof(previous / "long/right-quorum.json.gz")
    prior_review = json.loads((previous / "measurement.json").read_text(encoding="utf-8"))["review"]
    proof_bytes = (source / "review-plan/review-128.json.gz").read_bytes()
    assert digest(decode_proof(proof_bytes)) == prior_review["proof_sha256"]
    historical = verify_published_resolution(longer, second, authority, long_tip, number=2, bundle=former,
                                             trusted_manifest=prior_review["manifest_sha256"],
                                             trusted_checkpoint=prior_review["checkpoint_sha256"],
                                             proof=decode_proof(proof_bytes))
    assert historical["proof_rechecked"] and historical["verified_publication"] == 2
    assert historical["verified_publication_sha256"] == second_tip
    assert historical["current_decision_sha256"] == first_decision
    assert historical["decision_sha256"] == second_decision and historical["result_sha256"] == prior_review["result_sha256"]
    short_form, long_form = ((short, short_tip), (longer, long_tip))
    packet_bytes = gzip_proof(first)
    confirmation = (previous / "long/left-quorum.json.gz").read_bytes()
    assert decode_proof(confirmation)["policy"] == former["policy"]
    expect_rejection(lambda: verify_published_resolution(longer, first, authority, long_tip, bundle=former),
                     "selected reviewer policy revision")
    cases = [measure(history, tip, authority, packet_bytes, confirmation, proof_bytes, prior_review, repeats, output / label)
             for label, (history, tip) in zip(("short", "long"), (short_form, long_form), strict=True)]
    write_json(output / "authority.json", profile)
    write_bytes(output / "first-resolution.json.gz", packet_bytes)
    write_bytes(output / "second-resolution.json.gz", gzip_proof(second))
    write_bytes(output / "short/history-before-reinstatement.json.gz", gzip_proof(twice))
    write_json(output / "short/earlier-pins.json", {"first_publication_sha256": first_tip,
                                                   "second_publication_sha256": second_tip})
    return {"cases": cases, "authority_roster_size": len(keys), "authority_threshold": 2,
            "original_decision_sha256": first_decision, "alternate_decision_sha256": second_decision,
            "first_publication_sha256": first_tip, "reinstatement_publication_sha256": short_tip,
            "review": prior_review, "historical_publication_verified": 2, "stale_history_rejected": True,
            "historical_packet_rejected_as_current": True, "wrong_branch_confirmation_rejected": True,
            "historical_result_independently_replayed": True}


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
        print(f'{case["publication_count"]} publications, {case["history_gzip_bytes"]} history bytes, '
              f'{case["verify_history"]["median_ms"]:.3f} ms history verification, '
              f'{case["with_evidence"]["median_ms"]:.3f} ms including evidence recheck', flush=True)


if __name__ == "__main__":
    main()
