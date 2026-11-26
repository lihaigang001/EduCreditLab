"""Compare both proof formats for the same receipt and audit the checkpoint independently."""

import argparse
from pathlib import Path
import platform
from statistics import median
from time import perf_counter_ns

from educreditlab import __version__
from educreditlab.checkpoint import audit_checkpoint
from educreditlab.lab import verify_review
from educreditlab.model import write_bytes, write_json, write_text
from educreditlab.transport import GZIP_MAGIC, decode_proof, gzip_proof


def time_trials(operation, count):
    samples = []
    for _ in range(count):
        start = perf_counter_ns()
        result = operation()
        samples.append(round((perf_counter_ns() - start) / 1e6, 5))
    return result, {"samples_ms": samples, "median_ms": median(samples)}


def measure(original_path, trust, output, full_repeats=3, compact_repeats=30):
    path = Path(output)
    path.mkdir(parents=True, exist_ok=True)
    original = Path(original_path).read_bytes()
    document = decode_proof(original)
    if not original.startswith(GZIP_MAGIC):
        original = gzip_proof(document)
    verified, full = time_trials(lambda: verify_review(decode_proof(original), trust), full_repeats)
    print(f"height {verified['height']:,}: full median {full['median_ms']:.3f} ms", flush=True)
    index, audit = time_trials(lambda: audit_checkpoint(decode_proof(original), trust), 1)
    evidence = {key: document[key] for key in ("policy", "transcript", "receipt")}
    compact_proof = index.proof(verified["receipt_sha256"], evidence)
    compact_bytes = gzip_proof(compact_proof)
    compact, short = time_trials(lambda: verify_review(decode_proof(compact_bytes), trust,
                                                      trusted_checkpoint=index.fingerprint), compact_repeats)
    if {field: compact[field] for field in verified} != verified:
        raise ValueError("Compact and full verifiers disagree")
    anchor_bytes = gzip_proof(index.proof(verified["receipt_sha256"]))
    anchor = verify_review(decode_proof(anchor_bytes), trust, trusted_checkpoint=index.fingerprint)
    if not anchor["anchor_verified"] or anchor["receipt_sha256"] != verified["receipt_sha256"]:
        raise ValueError("The compact commitment does not match the full receipt")
    result = {
        "software_version": __version__, "python": platform.python_version(), "machine": platform.machine(),
        "receipt_height": verified["height"], "receipt_sha256": verified["receipt_sha256"],
        "manifest_sha256": trust, "checkpoint_sha256": index.fingerprint, "checkpoint": index.descriptor,
        "full_gzip_bytes": len(original), "compact_gzip_bytes": len(compact_bytes),
        "compact_anchor_gzip_bytes": len(anchor_bytes), "original_full_verification": full,
        "checkpoint_audit_once": audit, "compact_full_verification": short,
        "receipt_path_nodes": len(compact_proof["receipt_witness"]["path"]),
        "scope_path_nodes": len(compact_proof["scope_witness"]["path"]),
        "scope_policy_count": len(compact_proof["scope_witness"]["entry"]["registrations"]),
        "recognized_units_centi": compact["decision"]["recognized_units"],
        "same_verification_result": True,
    }
    write_json(path / "measurement.json", result)
    write_json(path / "checkpoint-descriptor.json", index.descriptor)
    write_text(path / "checkpoint-fingerprint.txt", index.fingerprint + "\n")
    write_text(path / "manifest-fingerprint.txt", trust + "\n")
    write_bytes(path / "compact-full-proof.json.gz", compact_bytes)
    write_bytes(path / "compact-anchor-proof.json.gz", anchor_bytes)
    print(f"height {verified['height']:,}: audit {audit['median_ms']:.3f} ms, compact "
          f"{short['median_ms']:.3f} ms, size {len(original):,} -> {len(compact_bytes):,} bytes", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_proof")
    parser.add_argument("--trust", required=True, help="independently verified original manifest SHA-256")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--full-repeats", type=int, default=3)
    parser.add_argument("--compact-repeats", type=int, default=30)
    args = parser.parse_args()
    if args.full_repeats < 1 or args.compact_repeats < 1:
        parser.error("trial counts must be positive")
    measure(args.original_proof, args.trust, args.out_dir, args.full_repeats, args.compact_repeats)


if __name__ == "__main__":
    main()
