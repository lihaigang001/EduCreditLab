"""Command-line entry points for analysis, auditing and the bundled web workbench."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

from . import __version__
from .checkpoint import audit_checkpoint, checkpoint_delta, extend_checkpoint, workspace_checkpoint
from .custody_cli import add_commands, add_private_key_args, new_signing_key, read_passphrase, run as run_custody
from .keys import KeyRegistry, load_private_key, public_key, save_private_key
from .lab import DEMO_ACTORS, DEMO_AMENDMENT, Lab, bundled_data, verify_bundle, verify_review
from .ledger import head_document, summarized_history, verify_chain
from .model import LabError, canonical, digest, read_json, write_json, write_text
from .policy_divergence import compare_policy_histories, verify_policy_divergence
from .policy_history import (append_policy_change, approve_policy_change, attest_review_at_revision,
                             bundle_review_at_revision, init_policy_history, verify_policy_history,
                             verify_review_at_revision)
from .policy_resolution import (bundle_policy_resolution, make_resolution_authority, sign_policy_resolution,
                                verify_policy_resolution, verify_resolved_review)
from .resolution_checkpoint import (
    _merge_resolution_chain, advance_and_merge_resolution_witnesses,
    audit_resolution_checkpoint, extend_resolution_checkpoint,
    merge_resolution_witnesses, refresh_resolution_batch,
    refresh_resolution_witness, resolution_checkpoint_delta, select_resolution_witness,
    verify_checkpoint_batch_resolution, verify_checkpoint_resolution, verify_resolution_batch, verify_resolution_witness,
)
from .resolution_history import (append_resolution_handover, append_resolution_publication, init_resolution_history,
                                 sign_resolution_handover, sign_resolution_publication, verify_published_resolution,
                                 verify_resolution_history)
from .review_attestation import attest_review, reviewer_fingerprint, verify_attestation
from .review_plan import make_review_plan
from .review_quorum import bundle_quorum, make_quorum_policy, verify_quorum
from .solver import evaluate
from .transport import read_proof, write_proof


def _proof_recheck_arguments(command):
    command.add_argument("--proof-trust", help="Expected SHA-256 of the original canonical proof JSON")
    command.add_argument("--proof", help="Original plan-bound proof to recheck")
    command.add_argument("--trust", help="Expected manifest SHA-256, required with --proof")
    command.add_argument("--checkpoint-trust", help="Expected checkpoint SHA-256, required with --proof")


def _add_resolution_history_commands(parent):
    commands = parent.add_parser("resolution-history", help="Publish and verify successive institutional decisions")
    actions = commands.add_subparsers(dest="publication_action", required=True)
    initial = actions.add_parser("init", help="Create an empty history for one verified divergence exhibit")
    sign = actions.add_parser("sign", help="Approve publication of a verified resolution after a pinned predecessor")
    append = actions.add_parser("append", help="Collect approvals and append a signed publication")
    handover_sign = actions.add_parser("handover-sign", help="Approve the authority handover and the incoming decision")
    handover_append = actions.add_parser("handover-append", help="Install the successor and publish its approved decision")
    check = actions.add_parser("verify", help="Verify the publication history to an independently expected endpoint")
    review = actions.add_parser("review", help="Verify the resolution and optional confirmation for a published choice")
    checkpoint = actions.add_parser("checkpoint", help="Audit a history and optionally export a single-publication witness")
    witness = actions.add_parser("checkpoint-verify", help="Verify a witness and optionally recheck a published decision")
    delta = actions.add_parser("checkpoint-delta", help="Export a signed suffix from an audited publication history")
    extend = actions.add_parser("checkpoint-extend", help="Extend a pinned head witness using a signed suffix")
    refresh = actions.add_parser("checkpoint-refresh", help="Refresh a retained publication witness using a signed suffix")
    batch = actions.add_parser("checkpoint-batch", help="Audit a history and prove the selected publications together")
    batch_refresh = actions.add_parser("checkpoint-refresh-batch", help="Refresh a retained batch using a signed suffix")
    batch_verify = actions.add_parser("checkpoint-verify-batch", help="Verify exactly the selected publications")
    batch_select = actions.add_parser("checkpoint-select-batch", help="Derive a witness for a subset of a verified batch")
    batch_merge = actions.add_parser("checkpoint-merge-batch", help="Merge publication witnesses at one pinned checkpoint")
    batch_advance_merge = actions.add_parser("checkpoint-advance-merge-batch",
                                             help="Advance and merge witnesses from the base and resulting checkpoints")
    batch_chain_merge = actions.add_parser("checkpoint-chain-merge-batch",
                                           help="Merge publication witnesses after consecutive signed continuations")
    for action in (initial, sign, append, handover_sign, handover_append, check, review, checkpoint, delta, batch):
        action.add_argument("--authority-trust", required=True, help="Independently trusted initial resolution authority SHA-256")
    initial.add_argument("authority", help="Resolution authority profile in JSON or gzip")
    initial.add_argument("evidence", help="Verified policy divergence exhibit in JSON or gzip")
    for action in (sign, append, handover_sign, handover_append, check, review, checkpoint, delta, batch):
        action.add_argument("history", help="Resolution publication history in JSON or gzip")
    for action in (sign, append, handover_sign, handover_append, check, review, checkpoint, delta, extend, refresh,
                   batch, batch_refresh, batch_advance_merge):
        action.add_argument("--publication-trust", required=True,
                            help="Independently expected latest publication SHA-256")
    for action in (sign, append, handover_sign, handover_append, review):
        action.add_argument("resolution", help="Signed resolution packet in JSON or gzip")
    for action in (sign, append, handover_sign, handover_append):
        action.add_argument("--decision-trust", required=True, help="Independently expected decision to publish")
    for action in (initial, sign, append, handover_sign, handover_append):
        action.add_argument("--out", required=True)
    add_private_key_args(sign)
    append.add_argument("approvals", nargs="+", help="Approvals of the same next publication")
    for action in (handover_sign, handover_append):
        action.add_argument("successor", help="Incoming authority profile in JSON or gzip")
        action.add_argument("--successor-trust", required=True, help="Independently expected incoming authority SHA-256")
    add_private_key_args(handover_sign)
    handover_sign.add_argument("--role", required=True, choices=("outgoing", "incoming"))
    handover_append.add_argument("--outgoing", required=True, nargs="+", help="Approvals from the current authority")
    handover_append.add_argument("--incoming", required=True, nargs="+", help="Approvals from the successor authority")
    for action in (review, checkpoint, witness):
        action.add_argument("--publication", type=int, help="Historical publication number, defaults to the pinned head")
    for action in (review, witness, batch_verify):
        action.add_argument("--review", help="Joint confirmation signed at the endpoint specified by the resolution")
        _proof_recheck_arguments(action)
    checkpoint.add_argument("--out", required=True, help="Audited checkpoint descriptor in JSON or gzip")
    checkpoint.add_argument("--witness-out", help="Inclusion witness for the selected publication in JSON or gzip")
    witness.add_argument("witness", help="Single-publication witness in JSON or gzip")
    witness.add_argument("--resolution", help="Signed resolution packet for the selected publication")
    delta.add_argument("--from-publication", type=int, required=True, help="Last publication in the verified base")
    delta.add_argument("--out", required=True, help="Signed suffix in JSON or gzip")
    for action in (extend, refresh, batch_refresh, batch_advance_merge, batch_chain_merge):
        action.add_argument("witness", help="Head witness for the pinned base checkpoint in JSON or gzip")
    for action in (extend, refresh, batch_refresh, batch_advance_merge):
        action.add_argument("delta", help="Signed continuation in JSON or gzip")
    extend.add_argument("--out", required=True, help="New head witness, including the new descriptor, in JSON or gzip")
    refresh.add_argument("archived", help="Retained witness for the selected publication in the pinned base")
    refresh.add_argument("--publication", type=int, required=True, help="Independently expected publication number to refresh")
    refresh.add_argument("--out", required=True, help="Refreshed historical witness in JSON or gzip")
    for action in (witness, extend, refresh, batch_refresh, batch_verify, batch_select, batch_merge,
                   batch_advance_merge, batch_chain_merge):
        action.add_argument("--publication-checkpoint-trust", required=True,
                            help="Independently trusted publication checkpoint SHA-256")
    for action in (batch, batch_refresh, batch_verify, batch_select, batch_merge, batch_advance_merge, batch_chain_merge):
        action.add_argument("--publication", dest="publication_numbers", type=int, action="append", required=True,
                            help="An expected publication number, repeat for the complete set")
    for action in (batch, batch_refresh):
        action.add_argument("--out", required=True, help="Batch witness in JSON or gzip")
    batch_refresh.add_argument("archived", help="Retained batch for the pinned base")
    batch_verify.add_argument("archived", help="Batch witness in JSON or gzip")
    batch_verify.add_argument("--select-publication", type=int, help="Batch member to review with --resolution")
    batch_verify.add_argument("--resolution", help="Signed resolution packet for --select-publication")
    batch_select.add_argument("archived", help="Source batch witness in JSON or gzip")
    batch_select.add_argument("--select-publication", dest="selected_publications", type=int, action="append", required=True,
                              help="A source publication number to retain, repeat for the complete subset")
    batch_select.add_argument("--single", action="store_true", help="Use the single-witness format for one selected number")
    batch_select.add_argument("--out", required=True, help="Subset witness in JSON or gzip")
    batch_merge.add_argument("witnesses", nargs="+", help="Batch or single publication witness files in JSON or gzip")
    for action in (batch_advance_merge, batch_chain_merge):
        action.add_argument("witnesses", nargs="*", help="Retained batch or single publication witness files")
        action.add_argument("--include-new-publication", type=int, action="append",
                            help="Derive a proof for a publication in the signed additions. Repeat as needed")
    batch_chain_merge.add_argument("--step", nargs=2, metavar=("DELTA", "EXPECTED_SHA256"), action="append", required=True,
                                   help="Signed continuation and independently expected endpoint SHA-256, in chronological order")
    for action in (batch_merge, batch_advance_merge, batch_chain_merge):
        action.add_argument("--out", required=True, help="Merged batch witness in JSON or gzip")


def _add_resolution_commands(actions):
    authority = actions.add_parser("resolution-authority", help="Define the keys authorized to resolve rule divergence")
    authority.add_argument("--initial-trust", required=True, help="Initial reviewer policy SHA-256 for this authority")
    authority.add_argument("--resolver-trust", action="append", required=True, help="Resolver key SHA-256, repeat as needed")
    authority.add_argument("--threshold", type=int, required=True)
    authority.add_argument("--out", required=True)
    approve = actions.add_parser("resolution-sign", help="Authorize the chosen endpoint of a demonstrated branch")
    bundle = actions.add_parser("resolution-bundle", help="Collect institutional approvals for the same choice")
    check = actions.add_parser("verify-resolution", help="Verify an independently expected institutional decision")
    for action in (approve, bundle, check):
        action.add_argument("--authority-trust", required=True, help="Independently trusted resolution authority SHA-256")
    for action in (approve, bundle):
        action.add_argument("authority", help="Resolution authority profile in JSON or gzip")
        action.add_argument("evidence", help="Verified policy divergence evidence in JSON or gzip")
        action.add_argument("history", help="Selected policy history in JSON or gzip")
        action.add_argument("--selected-trust", required=True, help="Independently expected selected revision SHA-256")
        action.add_argument("--out", required=True)
    add_private_key_args(approve)
    bundle.add_argument("approvals", nargs="+", help="Approvals for the same exact decision")
    check.add_argument("resolution", help="Signed policy resolution packet in JSON or gzip")
    check.add_argument("--decision-trust", required=True, help="Independently expected decision body SHA-256")
    check.add_argument("--review", help="Joint confirmation signed at the selected revision")
    _proof_recheck_arguments(check)


def _add_policy_history_commands(parent):
    commands = parent.add_parser("policy-history", help="Authorize reviewer rule changes and attest under a verified revision")
    actions = commands.add_subparsers(dest="policy_action", required=True)
    initial = actions.add_parser("init", help="Start a history from an independently trusted reviewer policy")
    initial.add_argument("policy")
    initial.add_argument("--policy-trust", required=True)
    initial.add_argument("--out", required=True)
    approve = actions.add_parser("approve", help="Sign the proposed next policy and the current revision")
    append = actions.add_parser("append", help="Verify both signature thresholds and append the successor")
    check = actions.add_parser("verify", help="Check all changes against two independent fingerprints")
    attest = actions.add_parser("attest", help="Verify evidence and sign a review bound to the current policy revision")
    collect = actions.add_parser("bundle", help="Collect reviews signed for the same verified policy revision")
    review = actions.add_parser("review", help="Verify a joint attestation against a selected policy revision")
    compare = actions.add_parser("compare", help="Compare two independently pinned policy histories")
    divergence = actions.add_parser("verify-divergence", help="Verify portable evidence of two distinct signed successors")
    for action in (approve, append, check, attest, collect, review, compare, divergence):
        action.add_argument("--initial-trust", required=True, help="Independently trusted initial policy SHA-256")
    for action in (approve, append, check, attest, collect, review):
        action.add_argument("history", help="Reviewer policy history in JSON or gzip")
        action.add_argument("--revision-trust", required=True, help="Independently expected latest revision SHA-256")
    for action in (approve, append):
        action.add_argument("next_policy", help="Successor reviewer policy made with review-quorum")
    for action in (approve, append, attest, collect):
        action.add_argument("--out", required=True)
    add_private_key_args(approve)
    append.add_argument("approvals", nargs="+")
    attest.add_argument("proof", help="Original plan-bound proof to verify")
    attest.add_argument("--trust", required=True, help="Independently audited manifest SHA-256")
    attest.add_argument("--checkpoint-trust", required=True, help="Independently audited checkpoint SHA-256")
    add_private_key_args(attest)
    collect.add_argument("attestations", nargs="+", help="Individual reviews that sign the selected policy revision")
    review.add_argument("bundle", help="Joint attestation in JSON or gzip")
    for action in (collect, review):
        action.add_argument("--revision", type=int, help="Explicit historical revision, defaults to the verified latest revision")
    review.add_argument("--require-revision-binding", action="store_true",
                        help="Require every signature to cover the selected policy revision")
    _proof_recheck_arguments(review)
    compare.add_argument("left_history", help="First reviewer policy history in JSON or gzip")
    compare.add_argument("right_history", help="Second reviewer policy history in JSON or gzip")
    compare.add_argument("--left-trust", required=True, help="Independently expected endpoint of the first history")
    compare.add_argument("--right-trust", required=True, help="Independently expected endpoint of the second history")
    compare.add_argument("--out", help="Export verified divergence evidence in JSON or gzip")
    divergence.add_argument("evidence", help="Divergence evidence in JSON or gzip")
    _add_resolution_commands(actions)


def parser():
    root = argparse.ArgumentParser(prog="educreditlab",
                                  description="Replayable cross-institutional academic credit decisions")
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--workspace", default=".educreditlab", help="Local ledger and artifact directory")
    sub = root.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="Initialize a local research workspace")
    init.add_argument("--mode", choices=("central", "consortium"), default="consortium")
    init.add_argument("--actors", nargs="+", help="Institution IDs for a custom workspace")
    init.add_argument("--seed", action="store_true", help="Publish the bundled historical and simulated policies")
    serve = sub.add_parser("serve", help="Run the browser workbench on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--mode", choices=("central", "consortium"), default="consortium")
    serve.add_argument("--seed", action="store_true", help="Resume publishing the demonstration policies")
    sub.add_parser("policies", help="List registered policy snapshots")
    sub.add_parser("timeline", help="Show policy effective dates, signed registration times and parent versions")
    sub.add_parser("status", help="Show committed height, replicas and the trust fingerprint")
    sub.add_parser("sync", help="Finish a pending proposal and synchronize replicas")
    load_policy = sub.add_parser("publish", help="Publish a local policy JSON file")
    load_policy.add_argument("policy")
    revise = sub.add_parser("revise", help="Register a scoped amendment to an existing policy")
    revise.add_argument("policy")
    revise.add_argument("--supersedes", required=True, help="SHA-256 of the immediately applicable parent policy")
    revise.add_argument("--reason", required=True, help="Signed change explanation")
    fixture = sub.add_parser("case", help="Export a synthetic transcript")
    fixture.add_argument("case_id")
    fixture.add_argument("--out")
    offline = sub.add_parser("solve", help="Use a policy file and transcript without a ledger")
    offline.add_argument("policy")
    offline.add_argument("transcript")
    offline.add_argument("--as-of", required=True)
    offline.add_argument("--method", choices=("optimal", "greedy"), default="optimal")
    preview = sub.add_parser("preview", help="Evaluate an unsigned local transcript against the policy registry")
    preview.add_argument("transcript")
    _target_arguments(preview)
    comparison = sub.add_parser("compare-policy", help="Compare two knowledge views on the same assessment date")
    comparison.add_argument("transcript")
    _target_arguments(comparison, knowledge=False)
    comparison.add_argument("--before-height", required=True, type=int)
    comparison.add_argument("--after-height", type=int, help="Defaults to the latest committed height")
    sign = sub.add_parser("sign", help="Sign a transcript for the initialized lab network")
    sign.add_argument("transcript")
    sign.add_argument("--out", required=True)
    record = sub.add_parser("record", help="Commit the decision on a signed transcript")
    record.add_argument("signed_transcript")
    _target_arguments(record)
    record.add_argument("--nonce", help="Reuse a 64-hex-character salt on a retry")
    proof = sub.add_parser("bundle", help="Export a review bundle with an independently checkable ledger prefix")
    proof.add_argument("receipt_sha256")
    proof.add_argument("--replica", help="Read the signed prefix from a validator's store")
    proof.add_argument("--anchor-only", action="store_true", help="Export the signed commitment without grades")
    proof.add_argument("--compact", action="store_true", help="Use inclusion witnesses at a separately trusted checkpoint")
    proof.add_argument("--checkpoint-height", type=int, help="Committed height for a compact proof, defaulting to the head")
    proof.add_argument("--out", required=True, help="Output .json or .json.gz for compressed transport")
    batch = sub.add_parser("bundle-batch", help="Export a group of receipts against one checkpoint")
    batch.add_argument("receipt_sha256", nargs="+", help="Distinct committed receipt digests")
    batch.add_argument("--replica", help="Read the signed prefix from a validator's store")
    batch.add_argument("--anchor-only", action="store_true", help="Export commitments without grade evidence")
    batch.add_argument("--checkpoint-height", type=int, help="Committed height, defaulting to the head")
    batch.add_argument("--out", required=True, help="Output .json or .json.gz for compressed transport")
    plan = sub.add_parser("review-plan", help="Specify the exact receipt scope for a review")
    plan.add_argument("--trust", required=True, help="Independently audited manifest SHA-256")
    plan.add_argument("--checkpoint-trust", required=True, help="Independently audited checkpoint SHA-256")
    plan.add_argument("--replay", action="append", default=[], help="Receipt requiring full replay; repeat as needed")
    plan.add_argument("--anchor", action="append", default=[], help="Receipt requiring only commitment review")
    plan.add_argument("--out", required=True, help="Review plan JSON destination")
    planned = sub.add_parser("bundle-review", help="Export a batch with the disclosure specified by a review plan")
    planned.add_argument("plan", help="Review plan JSON")
    planned.add_argument("--plan-trust", required=True, help="Review plan SHA-256 supplied independently")
    planned.add_argument("--replica", help="Read the signed prefix from a validator's store")
    planned.add_argument("--checkpoint-height", type=int, help="Committed height, defaulting to the head")
    planned.add_argument("--out", required=True, help="Output .json or .json.gz for compressed transport")
    check = sub.add_parser("verify", help="Verify a single receipt or batch offline")
    check.add_argument("bundle", help="Original JSON proof or gzip transport")
    check.add_argument("--trust", required=True, help="Manifest SHA-256 obtained independently")
    check.add_argument("--checkpoint-trust", help="Independently audited checkpoint SHA-256 for compact proofs")
    check.add_argument("--expect-receipt", action="append", help="Expected batch member digest, repeat for each member")
    check.add_argument("--plan-trust", help="Independently agreed review plan SHA-256 for a plan-bound proof")
    reviewer = sub.add_parser("review-keygen", help="Create a private reviewer signing key")
    add_private_key_args(reviewer)
    sign_review = sub.add_parser("review-attest", help="Verify a plan-bound proof and sign its evidence-free summary")
    sign_review.add_argument("proof", help="Plan-bound proof in JSON or gzip")
    sign_review.add_argument("--trust", required=True, help="Independently audited manifest SHA-256")
    sign_review.add_argument("--checkpoint-trust", required=True, help="Independently audited checkpoint SHA-256")
    sign_review.add_argument("--plan-trust", required=True, help="Independently agreed review plan SHA-256")
    sign_review.add_argument("--out", required=True, help="Signed review attestation destination")
    add_private_key_args(sign_review)
    attestation = sub.add_parser("verify-attestation", help="Verify an attestation and optionally recheck its proof")
    attestation.add_argument("attestation", help="Signed review attestation in JSON or gzip")
    attestation.add_argument("--reviewer-trust", required=True, help="Expected fingerprint of the reviewer's public key")
    attestation.add_argument("--plan-trust", required=True, help="Independently agreed review plan SHA-256")
    _proof_recheck_arguments(attestation)
    quorum_policy = sub.add_parser("review-quorum", help="Define a reviewer roster and signature threshold for a plan")
    quorum_policy.add_argument("--plan-trust", required=True, help="Independently agreed review plan SHA-256")
    quorum_policy.add_argument("--reviewer-trust", required=True, action="append", help="Authorized reviewer key SHA-256; repeat")
    quorum_policy.add_argument("--threshold", required=True, type=int, help="Required number of distinct reviewer keys")
    quorum_policy.add_argument("--out", required=True, help="Reviewer policy JSON destination")
    quorum_bundle = sub.add_parser("bundle-quorum", help="Collect matching, signed reviews under one trusted policy")
    quorum_bundle.add_argument("policy", help="Reviewer policy JSON")
    quorum_bundle.add_argument("attestations", nargs="+", help="Reviewer attestations in JSON or gzip")
    quorum_bundle.add_argument("--policy-trust", required=True, help="Independently trusted reviewer policy SHA-256")
    quorum_bundle.add_argument("--out", required=True, help="Joint attestation destination")
    quorum = sub.add_parser("verify-quorum", help="Verify the joint attestation and optionally recheck its proof once")
    quorum.add_argument("bundle", help="Joint attestation in JSON or gzip")
    quorum.add_argument("--policy-trust", required=True, help="Independently trusted reviewer policy SHA-256")
    _proof_recheck_arguments(quorum)
    _add_policy_history_commands(sub)
    _add_resolution_history_commands(sub)
    checkpoint = sub.add_parser("checkpoint", help="Export or independently audit a certified history snapshot")
    operations = checkpoint.add_subparsers(dest="checkpoint_command", required=True)
    export = operations.add_parser("export", help="Export a signed public archive without receipt evidence")
    export.add_argument("--height", type=int, help="Committed height, defaulting to the head")
    export.add_argument("--from-height", type=int, help="Export only the signed blocks after this audited height")
    export.add_argument("--replica", help="Use the signed prefix held by a validator")
    export.add_argument("--out", required=True, help="Archive output .json or .json.gz")
    audit = operations.add_parser("audit", help="Validate a signed archive or full-prefix proof and derive its checkpoint")
    audit.add_argument("archive", help="The signed archive or original full-prefix proof")
    audit.add_argument("--trust", required=True, help="Manifest SHA-256 obtained independently")
    audit.add_argument("--out", help="Save the independently derived checkpoint descriptor as JSON")
    audit.add_argument("--archive-out", help="Save the audited public archive and emit its canonical JSON SHA-256")
    extend = operations.add_parser("extend", help="Audit a signed continuation of a previously audited public archive")
    extend.add_argument("archive", help="The saved, independently audited public archive")
    extend.add_argument("delta", help="A signed delta beginning immediately after the archive")
    extend.add_argument("--trust", required=True, help="Manifest SHA-256 obtained independently")
    extend.add_argument("--archive-trust", required=True, help="Canonical archive SHA-256 retained from a prior audit")
    extend.add_argument("--expect-height", type=int, help="Require this target height when known")
    extend.add_argument("--expect-head", help="Require this target block digest when known")
    extend.add_argument("--out", help="Save the independently derived checkpoint descriptor as JSON")
    extend.add_argument("--archive-out", help="Save the extended public archive and emit its canonical JSON SHA-256")
    demo = sub.add_parser("demo", help="Run counterparts, policy replay and an offline proof on bundled data")
    demo.add_argument("--mode", choices=("central", "consortium"), default="consortium")
    demo.add_argument("--out", default="demo-output")
    amendment = sub.add_parser("demo-revision", help="Reproduce a synthetic same-year amendment and two review proofs")
    amendment.add_argument("--mode", choices=("central", "consortium"), default="consortium")
    amendment.add_argument("--out", default="revision-demo-output")
    bench = sub.add_parser("benchmark", help="Reproduce correctness, allocation and ledger measurements")
    bench.add_argument("--out", default="benchmark-output")
    bench.add_argument("--repeats", type=int, default=30, help="Ledger commits per mode after warm-up")
    add_commands(sub)
    return root


def _target_arguments(command, *, knowledge=True):
    command.add_argument("--receiver", required=True)
    command.add_argument("--programme", default="cse-bs")
    command.add_argument("--as-of", required=True)
    if knowledge:
        group = command.add_mutually_exclusive_group()
        group.add_argument("--known-height", type=int, help="Use the committed prefix ending at this block")
        group.add_argument("--known-at", help="Use a signed ISO 8601 time with a UTC offset")


def status(lab, chain=None):
    if chain is None:
        chain = lab.ledger.prefix()
    else:
        verify_chain(lab.ledger.manifest, chain, lab.ledger.fingerprint, cached=True)
    return _status_from_verified_prefix(lab, chain)


def _status_from_verified_prefix(lab, chain):
    ledger = lab.ledger
    trusted_rows = ([(block["core"]["height"], block["hash"], canonical(block)) for block in chain]
                    if not ledger.managed else ())
    replica_status = {}
    for name in ledger.manifest["validators"]:
        if ledger.managed:
            replica_status[name] = {"height": None, "state": "external"}
            continue
        try:
            replica_status[name] = ledger.replica_status(name, trusted_rows)
        except (LabError, OSError, sqlite3.Error):
            replica_status[name] = {"height": None, "state": "invalid"}
    result = {
        **summarized_history(ledger.manifest, chain, ledger.fingerprint),
        "replica_heights": {key: item["height"] for key, item in replica_status.items()},
        "replica_status": replica_status, "pending_height": ledger.pending_height(),
        "key_management": "managed" if ledger.managed else "local",
    }
    if ledger.managed:
        registry = KeyRegistry(ledger.manifest, chain)
        result["active_public_keys"] = registry.active
        result["rotation_count"] = len(registry.rotations)
    return result


def _demo(args):
    lab = Lab(args.workspace, args.mode)
    policies = bundled_data("policies.json")
    for policy in policies:
        if policy["kind"] == "historical-extract":
            lab.publish(policy)
    cases = bundled_data("cases.json")
    transcript = cases[0]["transcript"]
    before = lab.preview(transcript, "uc-irvine", "cse-bs", "2023-06-15")
    peer = lab.preview(transcript, "uc-merced", "cse-bs", "2023-06-15")
    issued = lab.record(lab.sign_transcript(transcript), "uc-irvine", "cse-bs", "2023-06-15")
    for policy in policies:
        if policy["kind"] == "synthetic":
            lab.publish(policy)
    after = lab.preview(transcript, "uc-irvine", "cse-bs", "2023-07-15")
    replica = next(iter(lab.ledger.manifest["validators"]))
    bundle = lab.bundle(issued["receipt_sha256"], replica)
    check = verify_bundle(bundle, lab.ledger.fingerprint)
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "transcript.json", transcript)
    write_json(output / "uc-irvine.json", before)
    write_json(output / "uc-merced.json", peer)
    write_json(output / "simulated-revision.json", after)
    write_json(output / "review-bundle.json", bundle)
    write_text(output / "trusted-manifest-sha256.txt", lab.ledger.fingerprint + "\n")
    return {
        "output": str(output), "receipt_sha256": issued["receipt_sha256"],
        "replayed": check["replayed"], "trust_fingerprint": lab.ledger.fingerprint,
        "results": [{"receiver": r["receiver"], "version": r["policy_version"],
                     "target_units": r["recognized_units"] / 100, "unit": r["unit"],
                     "rules": [entry["id"] for entry in r["rules"] if entry["status"] == "recognized"]}
                    for r in (before, peer, after)],
    }


def _demo_revision(args):
    lab = Lab(args.workspace, args.mode)
    lab.seed()
    revised_version = bundled_data(DEMO_AMENDMENT)["version"]
    old_entry = next((row for row in lab.policy_history()
                      if row["policy"]["version"] == revised_version
                      and row["policy"]["receiver"] == "uc-irvine"), None)
    before_height = old_entry["height"] - 1 if old_entry else len(lab.ledger.prefix())
    transcript = bundled_data("cases.json")[0]["transcript"]
    target = ("uc-irvine", "cse-bs", "2023-06-15")
    before = lab.issue_workbench_receipt(transcript, *target, known_height=before_height)
    amendment = lab.seed_amendment()
    after_height = amendment["core"]["height"]
    after = lab.issue_workbench_receipt(transcript, *target, known_height=after_height)
    before_knowledge = before["policy_view"]["knowledge"]
    after_knowledge = after["policy_view"]["knowledge"]
    if before_knowledge is not None:
        before_height = before_knowledge["height"]
    if after_knowledge is not None:
        after_height = after_knowledge["height"]
    comparison = lab.compare(transcript, *target, before_height, after_height)
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "comparison.json", comparison)
    checks = {}
    for name, receipt in (("before", before), ("after", after)):
        proof = lab.bundle(receipt["receipt_sha256"])
        write_json(output / f"proof-{name}.json", proof)
        checks[name] = verify_bundle(proof, lab.ledger.fingerprint)["replayed"]
    write_text(output / "trusted-manifest-sha256.txt", lab.ledger.fingerprint + "\n")
    return {"output": str(output), "as_of": target[2], "trust_fingerprint": lab.ledger.fingerprint,
            "before": comparison["before"]["decision"]["recognized_units"],
            "after": comparison["after"]["decision"]["recognized_units"],
            "unit": comparison["after"]["decision"]["unit"], "units_scale": 100,
            "before_height": before_height, "after_height": after_height, "replayed": checks}


def _offline_checkpoint(args):
    source = read_proof(args.archive)
    outputs = [Path(path).resolve() for path in (args.out, args.archive_out) if path]
    inputs = [Path(args.archive).resolve()]
    if args.checkpoint_command == "extend":
        inputs.append(Path(args.delta).resolve())
    if len(outputs) != len(set(outputs)) or set(inputs).intersection(outputs):
        raise LabError("Checkpoint inputs and output files must use separate paths")
    result = {}
    if args.checkpoint_command == "audit":
        index = audit_checkpoint(source, args.trust)
        archive = head_document(source["manifest"], source["chain"])
    else:
        delta = read_proof(args.delta)
        index, archive = extend_checkpoint(source, delta, args.trust, args.archive_trust,
                                           expected_height=args.expect_height, expected_head=args.expect_head)
        result.update(base_height=delta["base_height"], verified_new_blocks=len(delta["blocks"]))
    if args.archive_out:
        result["archive_sha256"] = digest(archive)
        write_proof(args.archive_out, archive)
    if args.out:
        write_json(args.out, index.descriptor)
    return {**result, "checkpoint_sha256": index.fingerprint, "checkpoint": index.descriptor}


def _optional_proof(path):
    if path is None:
        return None
    proof = read_proof(path)
    if proof is None:
        raise LabError("Expected a plan-bound proof in --proof")
    return proof


def _optional_confirmation(path):
    if path is None:
        return None
    bundle = read_proof(path)
    if bundle is None:
        raise LabError("Expected a joint confirmation in --review")
    return bundle


def _policy_output(path, document, inputs):
    if Path(path).resolve() in {Path(name).resolve() for name in inputs}:
        raise LabError("Choose a policy history output separate from the input files")
    write_proof(path, document)


def _run_resolution_checkpoint(args):
    action = args.publication_action
    if action == "checkpoint-delta":
        delta = resolution_checkpoint_delta(read_proof(args.history), args.authority_trust, args.publication_trust,
                                            from_number=args.from_publication)
        _policy_output(args.out, delta, [args.history])
        return {"output": args.out, "base_publication_count": args.from_publication,
                "exported_publications": len(delta["publications"])}
    if action in ("checkpoint-extend", "checkpoint-refresh"):
        witness, delta = read_proof(args.witness), read_proof(args.delta)
        inputs = [args.witness, args.delta]
        trust = (args.publication_checkpoint_trust, args.publication_trust)
        selected = {}
        if action == "checkpoint-refresh":
            inputs.append(args.archived)
            advanced = refresh_resolution_witness(witness, delta, read_proof(args.archived), *trust, number=args.publication)
            selected["refreshed_publication"] = args.publication
        else:
            advanced = extend_resolution_checkpoint(witness, delta, *trust)
        _policy_output(args.out, advanced, inputs)
        descriptor = advanced["checkpoint"]
        return {**selected, "output": args.out, "base_publication_count": delta["base_publication_count"],
                "verified_new_publications": len(delta["publications"]), "checkpoint": descriptor,
                "publication_checkpoint_sha256": digest(descriptor),
                "verified_authority_sha256": advanced["entry"]["authority_sha256"]}
    if action == "checkpoint":
        outputs = {Path(args.out).resolve()}
        if args.witness_out is not None:
            outputs.add(Path(args.witness_out).resolve())
            if len(outputs) != 2:
                raise LabError("Use separate checkpoint and witness output paths")
        elif args.publication is not None:
            raise LabError("Use --witness-out to select a publication")
        if Path(args.history).resolve() in outputs:
            raise LabError("Publication checkpoint outputs must be separate from the history input")
        index = audit_resolution_checkpoint(read_proof(args.history), args.authority_trust, args.publication_trust)
        descriptor = index.descriptor
        witness = index.witness(args.publication) if args.witness_out is not None else None
        write_proof(args.out, descriptor)
        result = {"output": args.out, "publication_checkpoint_sha256": index.fingerprint, "checkpoint": descriptor}
        if witness is not None:
            write_proof(args.witness_out, witness)
            result.update(witness_output=args.witness_out, publication=witness["entry"]["number"])
        return result
    witness = read_proof(args.witness)
    if args.resolution is None:
        if any(value is not None for value in (args.review, args.proof, args.trust, args.checkpoint_trust, args.proof_trust)):
            raise LabError("Use --resolution to review the published decision and its evidence")
        return verify_resolution_witness(witness, args.publication_checkpoint_trust, number=args.publication)
    return verify_checkpoint_resolution(
        witness, read_proof(args.resolution), args.publication_checkpoint_trust, number=args.publication,
        bundle=_optional_confirmation(args.review), proof=_optional_proof(args.proof), trusted_manifest=args.trust,
        trusted_checkpoint=args.checkpoint_trust, expected_proof=args.proof_trust)


def _run_resolution_batch(args):
    action, numbers = args.publication_action, args.publication_numbers
    if action == "checkpoint-verify-batch":
        batch, trust = read_proof(args.archived), args.publication_checkpoint_trust
        if args.resolution is None:
            if any(value is not None for value in (args.select_publication, args.review, args.proof, args.trust,
                                                   args.checkpoint_trust, args.proof_trust)):
                raise LabError("Use --select-publication with --resolution to review a batch member")
            return verify_resolution_batch(batch, trust, numbers=numbers)
        if args.select_publication is None:
            raise LabError("Use --select-publication with --resolution to review a batch member")
        return verify_checkpoint_batch_resolution(
            batch, read_proof(args.resolution), trust, numbers=numbers, number=args.select_publication,
            bundle=_optional_confirmation(args.review), proof=_optional_proof(args.proof), trusted_manifest=args.trust,
            trusted_checkpoint=args.checkpoint_trust, expected_proof=args.proof_trust)
    if action == "checkpoint-batch":
        index = audit_resolution_checkpoint(read_proof(args.history), args.authority_trust, args.publication_trust)
        batch, inputs = index.batch_witness(numbers), [args.history]
    elif action == "checkpoint-select-batch":
        inputs = [args.archived]
        batch = select_resolution_witness(read_proof(args.archived), args.publication_checkpoint_trust,
                                          numbers=numbers, selected=args.selected_publications, single=args.single)
    elif action == "checkpoint-merge-batch":
        inputs = args.witnesses
        batch = merge_resolution_witnesses([read_proof(path) for path in inputs], args.publication_checkpoint_trust,
                                           numbers=numbers)
    elif action == "checkpoint-advance-merge-batch":
        inputs = [args.witness, args.delta, *args.witnesses]
        batch = advance_and_merge_resolution_witnesses(
            read_proof(args.witness), read_proof(args.delta), [read_proof(path) for path in args.witnesses],
            args.publication_checkpoint_trust, args.publication_trust, numbers=numbers,
            new_publications=args.include_new_publication)
    elif action == "checkpoint-chain-merge-batch":
        delta_paths, tips = zip(*args.step, strict=True)
        inputs = [args.witness, *delta_paths, *args.witnesses]
        batch = _merge_resolution_chain(
            read_proof(args.witness), list(delta_paths),
            [read_proof(path) for path in args.witnesses], args.publication_checkpoint_trust, list(tips),
            numbers=numbers, new_publications=args.include_new_publication, load_delta=read_proof)
    else:
        inputs = [args.witness, args.delta, args.archived]
        witness, delta, archived = (read_proof(path) for path in inputs)
        batch = refresh_resolution_batch(witness, delta, archived, args.publication_checkpoint_trust,
                                         args.publication_trust, numbers=numbers)
    descriptor = batch["checkpoint"]
    _policy_output(args.out, batch, inputs)
    entries = [batch["entry"]] if "entry" in batch else batch["entries"]
    return {"output": args.out, "checkpoint": descriptor, "publication_checkpoint_sha256": digest(descriptor),
            "publications": [entry["number"] for entry in entries]}


def _run_resolution_history(args):
    action = args.publication_action
    if action in ("checkpoint", "checkpoint-verify", "checkpoint-delta", "checkpoint-extend", "checkpoint-refresh"):
        return _run_resolution_checkpoint(args)
    if action in ("checkpoint-batch", "checkpoint-refresh-batch", "checkpoint-verify-batch", "checkpoint-select-batch",
                  "checkpoint-merge-batch", "checkpoint-advance-merge-batch", "checkpoint-chain-merge-batch"):
        return _run_resolution_batch(args)
    authority = args.authority_trust
    if action == "init":
        history, tip = init_resolution_history(read_proof(args.authority), read_proof(args.evidence), authority)
        _policy_output(args.out, history, [args.authority, args.evidence])
        return {"output": args.out, "latest_publication_sha256": tip, "publication_count": 0}
    history, tip = read_proof(args.history), args.publication_trust
    if action == "verify":
        return verify_resolution_history(history, authority, tip)
    packet = read_proof(args.resolution)
    if action == "review":
        return verify_published_resolution(history, packet, authority, tip, number=args.publication,
                                            bundle=_optional_confirmation(args.review),
                                            trusted_manifest=args.trust, trusted_checkpoint=args.checkpoint_trust,
                                            expected_proof=args.proof_trust, proof=_optional_proof(args.proof))
    if action in ("handover-sign", "handover-append"):
        successor = read_proof(args.successor)
        inputs = [args.history, args.resolution, args.successor]
        if action == "handover-sign":
            key = load_private_key(args.key, read_passphrase(args))
            approval = sign_resolution_handover(history, packet, successor, key, authority, tip, args.decision_trust,
                                                trusted_successor=args.successor_trust, role=args.role)
            _policy_output(args.out, approval, [*inputs, args.key])
            return {"output": args.out, "role": args.role, "resolver_sha256": reviewer_fingerprint(approval["resolver_public_key"])}
        approvals = {"outgoing": [read_proof(p) for p in args.outgoing],
                     "incoming": [read_proof(p) for p in args.incoming]}
        advanced, latest = append_resolution_handover(history, packet, successor, approvals, authority, tip,
                                                      args.decision_trust, trusted_successor=args.successor_trust)
        _policy_output(args.out, advanced, [*inputs, *args.outgoing, *args.incoming])
        return {"output": args.out, "latest_publication_sha256": latest,
                "current_decision_sha256": args.decision_trust, "publication_count": len(advanced["publications"]),
                "active_authority_sha256": args.successor_trust}
    if action == "sign":
        key = load_private_key(args.key, read_passphrase(args))
        approval = sign_resolution_publication(history, packet, key, authority, tip, args.decision_trust)
        _policy_output(args.out, approval, [args.history, args.resolution, args.key])
        return {"output": args.out, "resolver_sha256": reviewer_fingerprint(approval["resolver_public_key"])}
    advanced, latest = append_resolution_publication(history, packet, [read_proof(p) for p in args.approvals],
                                                     authority, tip, args.decision_trust)
    _policy_output(args.out, advanced, [args.history, args.resolution, *args.approvals])
    return {"output": args.out, "latest_publication_sha256": latest, "current_decision_sha256": args.decision_trust,
            "publication_count": len(advanced["publications"])}


def _run_resolution_command(args):
    action = args.policy_action
    if action == "resolution-authority":
        authority = make_resolution_authority(args.initial_trust, args.resolver_trust, args.threshold)
        write_proof(args.out, authority)
        return {"output": args.out, "authority_sha256": digest(authority)}
    if action == "verify-resolution":
        packet = read_proof(args.resolution)
        if args.review is None:
            if any(pin is not None for pin in (args.proof, args.trust, args.checkpoint_trust, args.proof_trust)):
                raise LabError("Use --review to apply evidence or proof fingerprints to a joint confirmation")
            return verify_policy_resolution(packet, args.authority_trust, args.decision_trust)
        return verify_resolved_review(packet, read_proof(args.review), args.authority_trust, args.decision_trust,
                                      trusted_manifest=args.trust, trusted_checkpoint=args.checkpoint_trust,
                                      expected_proof=args.proof_trust, proof=_optional_proof(args.proof))
    inputs = [args.authority, args.evidence, args.history]
    authority, evidence, history = (read_proof(path) for path in inputs)
    if action == "resolution-sign":
        key = load_private_key(args.key, read_passphrase(args))
        approval = sign_policy_resolution(authority, evidence, history, key, args.authority_trust,
                                          args.selected_trust)
        _policy_output(args.out, approval, [*inputs, args.key])
        return {"output": args.out, "resolver_sha256": reviewer_fingerprint(approval["resolver_public_key"]),
                "selected_revision_sha256": args.selected_trust}
    packet = bundle_policy_resolution(authority, evidence, history, [read_proof(path) for path in args.approvals],
                                      args.authority_trust, args.selected_trust)
    _policy_output(args.out, packet, [*inputs, *args.approvals])
    return {"output": args.out, "decision_sha256": digest(packet["decision"]),
            "selected_revision_sha256": args.selected_trust, "resolution_signer_count": len(packet["approvals"])}


def _run_policy_history(args):
    action = args.policy_action
    if action in ("resolution-authority", "resolution-sign", "resolution-bundle", "verify-resolution"):
        return _run_resolution_command(args)
    if action == "init":
        history = init_policy_history(read_json(args.policy), args.policy_trust)
        _policy_output(args.out, history, [args.policy])
        return {"output": args.out, **verify_policy_history(history, args.policy_trust, args.policy_trust)}
    if action == "compare":
        result, evidence = compare_policy_histories(read_proof(args.left_history), read_proof(args.right_history),
                                                    args.initial_trust, args.left_trust, args.right_trust)
        if args.out is not None:
            if evidence is None:
                raise LabError(f"Policy history relationship is {result['relationship']}. "
                               "Export requires divergence")
            _policy_output(args.out, evidence, [args.left_history, args.right_history])
            result["output"] = args.out
        return result
    if action == "verify-divergence":
        return verify_policy_divergence(read_proof(args.evidence), args.initial_trust)
    history = read_proof(args.history)
    initial, revision = args.initial_trust, args.revision_trust
    if action == "verify":
        return verify_policy_history(history, initial, revision)
    if action == "review":
        return verify_review_at_revision(history, read_proof(args.bundle), initial, revision,
                                         revision=args.revision, proof=_optional_proof(args.proof),
                                         trusted_manifest=args.trust, trusted_checkpoint=args.checkpoint_trust,
                                         expected_proof=args.proof_trust,
                                         require_revision_binding=args.require_revision_binding)
    if action == "attest":
        key = load_private_key(args.key, read_passphrase(args))
        statement = attest_review_at_revision(history, read_proof(args.proof), key, initial, revision,
                                              trusted_manifest=args.trust, trusted_checkpoint=args.checkpoint_trust)
        _policy_output(args.out, statement, [args.history, args.proof, args.key])
        body = statement["body"]
        return {"output": args.out, "reviewer_sha256": reviewer_fingerprint(body["reviewer_public_key"]),
                "policy_revision_sha256": body["policy_revision_sha256"], "proof_sha256": body["proof_sha256"]}
    if action == "bundle":
        statements = [read_proof(path) for path in args.attestations]
        bundle = bundle_review_at_revision(history, statements, initial, revision, revision=args.revision)
        _policy_output(args.out, bundle, [args.history, *args.attestations])
        return {"output": args.out, "signer_count": len(bundle["attestations"]),
                "policy_revision_sha256": bundle["attestations"][0]["body"]["policy_revision_sha256"]}
    next_policy = read_json(args.next_policy)
    if action == "approve":
        key = load_private_key(args.key, read_passphrase(args))
        statement = approve_policy_change(history, next_policy, key, initial, revision)
        _policy_output(args.out, statement, [args.history, args.next_policy, args.key])
        return {"output": args.out, "reviewer_sha256": reviewer_fingerprint(statement["reviewer_public_key"])}
    advanced, latest = append_policy_change(history, next_policy, [read_proof(path) for path in args.approvals],
                                           initial, revision)
    _policy_output(args.out, advanced, [args.history, args.next_policy, *args.approvals])
    return {"output": args.out, "latest_revision": len(advanced["changes"]) + 1,
            "latest_revision_sha256": latest, "current_policy_sha256": digest(next_policy)}


def _run(args):
    command = args.command
    if command == "custody":
        return run_custody(args)
    if command == "init":
        if args.seed and args.actors:
            raise LabError("Bundled policies use the bundled institution IDs")
        lab = Lab(args.workspace, args.mode, args.actors or DEMO_ACTORS)
        if args.seed:
            lab.seed()
        return status(lab)
    if command == "serve":
        from .server import serve
        lab = Lab.workbench(args.workspace, args.mode, seed=args.seed)
        serve(lab, args.port)
        return None
    if command == "solve":
        return evaluate(read_json(args.policy), read_json(args.transcript), args.as_of,
                        method=args.method)
    if command == "verify":
        return verify_review(read_proof(args.bundle), args.trust, trusted_checkpoint=args.checkpoint_trust,
                             expected_receipts=args.expect_receipt, trusted_plan=args.plan_trust)
    if command == "review-keygen":
        if Path(args.key).exists():
            raise LabError("Choose an unused path for the encrypted reviewer key")
        key, password = new_signing_key(args)
        save_private_key(args.key, key, password)
        return {"key": args.key, "reviewer_sha256": reviewer_fingerprint(public_key(key))}
    if command == "review-attest":
        if Path(args.out).resolve() in (Path(args.proof).resolve(), Path(args.key).resolve()):
            raise LabError("Choose an attestation output separate from the proof and private key")
        key = load_private_key(args.key, read_passphrase(args))
        statement = attest_review(read_proof(args.proof), key, args.trust, args.checkpoint_trust, args.plan_trust)
        write_proof(args.out, statement)
        return {"output": args.out, "reviewer_sha256": reviewer_fingerprint(statement["body"]["reviewer_public_key"]),
                "proof_sha256": statement["body"]["proof_sha256"]}
    if command == "verify-attestation":
        return verify_attestation(read_proof(args.attestation), args.reviewer_trust, args.plan_trust,
                                  proof=_optional_proof(args.proof),
                                  trusted_manifest=args.trust, trusted_checkpoint=args.checkpoint_trust,
                                  expected_proof=args.proof_trust)
    if command == "review-quorum":
        policy = make_quorum_policy(args.plan_trust, args.reviewer_trust, args.threshold)
        write_json(args.out, policy)
        return {"output": args.out, "policy_sha256": digest(policy), "threshold": policy["threshold"],
                "reviewer_count": len(policy["reviewer_sha256"])}
    if command == "bundle-quorum":
        inputs = [args.policy, *args.attestations]
        if Path(args.out).resolve() in {Path(path).resolve() for path in inputs}:
            raise LabError("Choose a joint attestation output separate from the policy and signed reviews")
        bundle = bundle_quorum(read_json(args.policy), [read_proof(path) for path in args.attestations],
                               args.policy_trust)
        write_proof(args.out, bundle)
        return {"output": args.out, "policy_sha256": args.policy_trust, "signer_count": len(bundle["attestations"])}
    if command == "verify-quorum":
        return verify_quorum(read_proof(args.bundle), args.policy_trust, proof=_optional_proof(args.proof),
                             trusted_manifest=args.trust, trusted_checkpoint=args.checkpoint_trust,
                             expected_proof=args.proof_trust)
    if command == "policy-history":
        return _run_policy_history(args)
    if command == "resolution-history":
        return _run_resolution_history(args)
    if command == "review-plan":
        plan = make_review_plan(args.trust, args.checkpoint_trust, replay=args.replay, anchor=args.anchor)
        write_json(args.out, plan)
        return {"output": args.out, "review_plan_sha256": digest(plan),
                "replay_count": len(args.replay), "anchor_count": len(args.anchor)}
    if command == "checkpoint" and args.checkpoint_command in ("audit", "extend"):
        return _offline_checkpoint(args)
    if command == "case":
        cases = {entry["id"]: entry["transcript"] for entry in bundled_data("cases.json")}
        if args.case_id not in cases:
            raise LabError("Available case IDs: " + ", ".join(cases))
        transcript = cases[args.case_id]
        if args.out:
            write_json(args.out, transcript)
        return {"output": args.out} if args.out else transcript
    if command == "demo":
        return _demo(args)
    if command == "demo-revision":
        return _demo_revision(args)
    if command == "benchmark":
        from .benchmark import run_benchmark
        return run_benchmark(args.out, args.repeats)
    lab = Lab.open(args.workspace)
    if command == "checkpoint":
        index, archive = workspace_checkpoint(lab.ledger, height=args.height, replica=args.replica)
        document = archive if args.from_height is None else checkpoint_delta(archive, args.from_height)
        write_proof(args.out, document)
        return {"output": args.out, "checkpoint_sha256": index.fingerprint, "checkpoint": index.descriptor}
    if command == "policies":
        return lab.descriptors()
    if command == "timeline":
        return lab.policy_history()
    if command == "status":
        return status(lab)
    if command == "sync":
        return lab.ledger.sync()
    if command == "publish":
        return lab.publish(read_json(args.policy))
    if command == "revise":
        return lab.revise(read_json(args.policy), args.supersedes, args.reason)
    if command == "preview":
        result = lab.assess(read_json(args.transcript), args.receiver, args.programme, args.as_of,
                            known_height=args.known_height, known_at=args.known_at)
        return {**result["decision"], "policy_view": result["policy_view"]}
    if command == "compare-policy":
        return lab.compare(read_json(args.transcript), args.receiver, args.programme, args.as_of,
                           args.before_height, args.after_height)
    if command == "sign":
        signed = lab.sign_transcript(read_json(args.transcript))
        write_json(args.out, signed)
        return {"output": args.out}
    if command == "record":
        return lab.record(read_json(args.signed_transcript), args.receiver, args.programme,
                          args.as_of, nonce=args.nonce, known_height=args.known_height, known_at=args.known_at)
    if command == "bundle-batch":
        index, _ = workspace_checkpoint(lab.ledger, height=args.checkpoint_height, replica=args.replica)
        evidence = None if args.anchor_only else {ref: lab.ledger.artifact(ref, "receipt")
                                                 for ref in args.receipt_sha256}
        proof = index.batch_proof(args.receipt_sha256, evidence)
        write_proof(args.out, proof)
        return {"output": args.out, "trust_fingerprint": lab.ledger.fingerprint,
                "checkpoint_sha256": index.fingerprint, "checkpoint_height": index.descriptor["height"],
                "receipt_count": len(args.receipt_sha256)}
    if command == "bundle-review":
        index, _ = workspace_checkpoint(lab.ledger, height=args.checkpoint_height, replica=args.replica)
        plan = read_json(args.plan)
        proof = index.review_proof(plan, args.plan_trust, lambda reference: lab.ledger.artifact(reference, "receipt"))
        write_proof(args.out, proof)
        return {"output": args.out, "review_plan_sha256": args.plan_trust, "checkpoint_sha256": index.fingerprint,
                "receipt_count": len(plan["requirements"]), "replay_count": len(proof["evidence"])}
    if command == "bundle":
        output = {"output": args.out, "trust_fingerprint": lab.ledger.fingerprint}
        if args.compact:
            index, _ = workspace_checkpoint(lab.ledger, height=args.checkpoint_height, replica=args.replica)
            evidence = None if args.anchor_only else lab.ledger.artifact(args.receipt_sha256, "receipt")
            proof = index.proof(args.receipt_sha256, evidence)
            output.update(checkpoint_sha256=index.fingerprint, checkpoint_height=index.descriptor["height"])
        else:
            if args.checkpoint_height is not None:
                raise LabError("--checkpoint-height requires --compact")
            proof = lab.bundle(args.receipt_sha256, args.replica, anchor_only=args.anchor_only)
        write_proof(args.out, proof)
        return output
    raise LabError("Unknown command")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        result = _run(args)
        if result is not None:
            # ASCII-safe JSON also works when a Windows terminal uses a legacy code page.
            print(json.dumps(result, ensure_ascii=True, indent=2, allow_nan=False))
    except (LabError, OSError, sqlite3.Error) as exc:
        print(f"EduCreditLab: {str(exc).encode('ascii', 'backslashreplace').decode()}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 0

