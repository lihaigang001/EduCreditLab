"""Compare a full public archive audit with signed continuations to the same height."""

import argparse
from pathlib import Path
import platform

from checkpoint_audit import time_trials
from educreditlab import __version__
from educreditlab.checkpoint import audit_checkpoint, checkpoint_delta, extend_checkpoint
from educreditlab.lab import verify_review
from educreditlab.ledger import head_document
from educreditlab.model import digest, write_json
from educreditlab.transport import decode_proof, gzip_proof, read_proof


def measure(source, trusted_manifest, base_heights, full_repeats, extension_repeats):
    bundle = read_proof(source)
    archive = head_document(bundle["manifest"], bundle["chain"])
    zip_full = gzip_proof(archive)
    latest, full_timing = time_trials(lambda: audit_checkpoint(decode_proof(zip_full), trusted_manifest),
                                      full_repeats)
    height = latest.descriptor["height"]
    head = latest.descriptor["head_sha256"]
    cases = []
    for base_height in base_heights:
        delta = checkpoint_delta(archive, base_height)
        base = head_document(archive["manifest"], archive["chain"][:base_height])
        audit_checkpoint(base, trusted_manifest)
        base_pin = digest(base)
        zip_base = gzip_proof(base)
        zip_delta = gzip_proof(delta)

        def extend():
            return extend_checkpoint(decode_proof(zip_base), decode_proof(zip_delta),
                                     trusted_manifest, base_pin, expected_height=height, expected_head=head)

        (extended, combined), timing = time_trials(extend, extension_repeats)
        if extended.descriptor != latest.descriptor or extended.fingerprint != latest.fingerprint or combined != archive:
            raise ValueError("The incremental and full audits disagree")
        cases.append({
            "base_height": base_height, "new_blocks": height - base_height, "base_archive_gzip_bytes": len(zip_base),
            "delta_gzip_bytes": len(zip_delta), "extension": timing, "checkpoint_match": True,
        })
        print(f"from {base_height:,} to {height:,}: {timing['median_ms']:.3f} ms, {len(zip_delta):,} transmitted bytes",
              flush=True)

    # The input proof supplies the same signed private evidence in both replay modes.
    full_replay = verify_review(bundle, trusted_manifest)
    evidence = {key: bundle[key] for key in ("policy", "receipt", "transcript")}
    short = extended.proof(full_replay["receipt_sha256"], evidence)
    replay = verify_review(short, trusted_manifest, trusted_checkpoint=extended.fingerprint)
    if {key: replay[key] for key in full_replay} != full_replay:
        raise ValueError("The receipt replay differs after extension")
    return {
        "software_version": __version__, "python": platform.python_version(), "platform": platform.platform(),
        "target_height": height, "full_archive_gzip_bytes": len(zip_full), "full_audit": full_timing,
        "checkpoint": latest.descriptor, "checkpoint_sha256": latest.fingerprint, "cases": cases,
        "receipt_sha256": replay["receipt_sha256"], "recognized_units_centi": replay["decision"]["recognized_units"],
        "same_replay_result": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="Full-prefix proof with replay evidence")
    parser.add_argument("--trust", required=True, help="Independently established manifest SHA-256")
    parser.add_argument("--base-heights", nargs="+", type=int, default=[9000, 9900, 9990])
    parser.add_argument("--full-repeats", type=int, default=3)
    parser.add_argument("--extension-repeats", type=int, default=5)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    if args.full_repeats < 1 or args.extension_repeats < 1:
        parser.error("trial counts must be positive")
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    result = measure(args.source, args.trust, args.base_heights, args.full_repeats, args.extension_repeats)
    write_json(output, result)
    print(f"full audit median {result['full_audit']['median_ms']:.3f} ms, {result['full_archive_gzip_bytes']:,} bytes")


if __name__ == "__main__":
    main()
