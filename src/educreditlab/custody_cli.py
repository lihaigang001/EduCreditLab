"""CLI for exchanging public proposals, institution approvals and validator votes."""

from __future__ import annotations

from getpass import GetPassWarning, getpass
from pathlib import Path
import sys
import warnings

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import custody
from .keys import ROLES, enroll, load_private_key, save_private_key
from .lab import Lab
from .ledger import head_document
from .model import LabError, read_json, write_json


def _output(command):
    command.add_argument("--out", required=True)


def _trust(command):
    command.add_argument("--trust", required=True, help="SHA-256 of the agreed initial manifest")


def add_private_key_args(command, *, single=True):
    if single:
        command.add_argument("--key", required=True, help="The signer's encrypted PKCS#8 file")
    command.add_argument("--passphrase-stdin", action="store_true", help="Read each passphrase as one line")


def _node(command):
    command.add_argument("--validator", required=True, help="This validator's registered identity")
    command.add_argument("--state", required=True, help="Path to this validator's durable SQLite state")
    _trust(command)


def add_commands(parent):
    custody_group = parent.add_parser("custody", help="Work with a separately managed signing network")
    commands = custody_group.add_subparsers(dest="custody_command", required=True)
    keygen = commands.add_parser("keygen", help="Generate one encrypted private key and its public enrollment")
    keygen.add_argument("role", choices=ROLES)
    keygen.add_argument("name")
    keygen.add_argument("--enrollment", required=True)
    add_private_key_args(keygen)
    init = commands.add_parser("init", help="Initialize a coordinator from signed public enrollments")
    init.add_argument("enrollments", nargs="+")
    _output(init)
    _output(commands.add_parser("head", help="Export a certified public ledger view"))
    for name, description in (
        ("validator-init", "Bind a new validator state to the agreed genesis"),
        ("validator-sync", "Update a validator's durable copy from a certified head"),
    ):
        cmd = commands.add_parser(name, help=description)
        cmd.add_argument("head")
        _node(cmd)
    policy = commands.add_parser("sign-policy", help="Sign a policy or amendment on the receiving side")
    policy.add_argument("policy")
    policy.add_argument("--head", required=True)
    policy.add_argument("--supersedes", help="SHA-256 of the currently applicable parent policy")
    policy.add_argument("--reason", help="Signed reason for the policy amendment")
    transcript = commands.add_parser("sign-transcript", help="Sign course evidence on the sending side")
    transcript.add_argument("transcript")
    transcript.add_argument("--head", required=True)
    approve = commands.add_parser("approve-receipt", help="Independently recompute and sign a receiving decision")
    approve.add_argument("request")
    for cmd in (policy, transcript, approve):
        add_private_key_args(cmd)
        _trust(cmd)
        _output(cmd)
    prepare = commands.add_parser("prepare-receipt", help="Prepare the receiving side's private review request")
    prepare.add_argument("signed_transcript")
    prepare.add_argument("--receiver", required=True)
    prepare.add_argument("--programme", default="cse-bs")
    prepare.add_argument("--as-of", required=True)
    prepare.add_argument("--known-height", type=int)
    _output(prepare)
    rotate = commands.add_parser("rotate", help="Authorize a key rotation on the owner's device")
    rotate.add_argument("role", choices=ROLES)
    rotate.add_argument("name")
    rotate.add_argument("--head", required=True)
    rotate.add_argument("--old-key", required=True)
    rotate.add_argument("--new-key", required=True)
    rotate.add_argument("--reason", required=True)
    add_private_key_args(rotate, single=False)
    _trust(rotate)
    _output(rotate)
    submit = commands.add_parser("submit", help="Reserve a proposal from a signed operation")
    submit.add_argument("operation")
    _output(submit)
    _output(commands.add_parser("pending", help="Recover the original reserved proposal for voting"))
    vote = commands.add_parser("vote", help="Check a proposal and persist one validator's detached vote")
    vote.add_argument("proposal")
    _node(vote)
    add_private_key_args(vote)
    _output(vote)
    commit = commands.add_parser("commit", help="Commit a proposal after receiving three distinct valid votes")
    commit.add_argument("votes", nargs="+")
    _output(commit)
    _output(commands.add_parser("demo", help="Rehearse planned rotations using synthetic data"))


def read_passphrase(args, prompt="Private key passphrase: "):
    if args.passphrase_stdin:
        data = sys.stdin.buffer.readline(2049)
        if len(data) == 2049 or not data:
            raise LabError("Expected one nonempty passphrase line of at most 2048 bytes")
        return data.rstrip(b"\r\n")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            return getpass(prompt).encode("utf-8")
    except (EOFError, GetPassWarning) as exc:
        raise LabError("Use a terminal password prompt or supply --passphrase-stdin") from exc


def new_signing_key(args):
    password = read_passphrase(args, "New private key passphrase: ")
    if not args.passphrase_stdin and password != read_passphrase(args, "Repeat passphrase: "):
        raise LabError("Passphrases differ")
    return Ed25519PrivateKey.generate(), password


def _emit(args, document, **details):
    output = Path(args.out).resolve()
    reserved = [getattr(args, name, None) for name in ("key", "old_key", "new_key", "state")]
    reserved.append(Path(args.workspace) / "ledger.sqlite3")
    if any(output == Path(path).resolve() for path in reserved if path is not None):
        raise LabError("An exchange file needs a separate path from private keys and ledger databases")
    write_json(args.out, document)
    return {"output": args.out, **details}


def _keygen(args):
    secret, enrollment = Path(args.key), Path(args.enrollment)
    if secret.resolve() == enrollment.resolve() or secret.exists() or enrollment.exists():
        raise LabError("Choose unused, separate paths for the private key and public enrollment")
    key, password = new_signing_key(args)
    entry = enroll(args.role, args.name, key)
    if not enrollment.parent.is_dir():
        raise LabError("Create the enrollment output directory first")
    save_private_key(secret, key, password)
    write_json(enrollment, entry)
    return {"role": args.role, "name": args.name, "enrollment": args.enrollment,
            "public_key": entry["body"]["public_key"]}


def run(args):
    command = args.custody_command
    if command == "keygen":
        return _keygen(args)
    if command == "demo":
        from .custody_demo import run_demo
        return run_demo(args.out)
    if command in {"validator-init", "validator-sync", "vote"}:
        node = custody.ValidatorStore(args.state, args.validator, args.trust)
        if command == "validator-init":
            node.initialize(read_json(args.head))
            return {"validator": args.validator, "trust_fingerprint": args.trust}
        if command == "validator-sync":
            return node.accept_head(read_json(args.head))
        key = load_private_key(args.key, read_passphrase(args))
        vote = node.vote(read_json(args.proposal), key)
        return _emit(args, vote, validator=args.validator, height=vote["height"], block_sha256=vote["block_sha256"])
    if command in {"sign-transcript", "sign-policy", "approve-receipt"}:
        key = load_private_key(args.key, read_passphrase(args))
        if command == "approve-receipt":
            operation = custody.approve_receipt(read_json(args.request), args.trust, key)
            decision = operation["artifact"]["receipt"]["body"]["decision"]
            return _emit(args, operation, as_of=decision["as_of"], policy_version=decision["policy_version"],
                         recognized_units=decision["recognized_units"], unit=decision["unit"],
                         receipt_sha256=operation["event"]["body"]["payload"]["receipt_sha256"])
        head = read_json(args.head)
        if command == "sign-policy":
            document = custody.sign_policy(head, args.trust, read_json(args.policy), key,
                                           supersedes=args.supersedes, reason=args.reason)
        else:
            document = custody.sign_transcript(head, args.trust, read_json(args.transcript), key)
        return _emit(args, document)
    if command == "rotate":
        previous = load_private_key(args.old_key, read_passphrase(args, "Current key passphrase: "))
        replacement = load_private_key(args.new_key, read_passphrase(args, "Replacement key passphrase: "))
        return _emit(args, custody.authorize_rotation(read_json(args.head), args.trust, args.role, args.name,
                                                       previous, replacement, args.reason))
    if command == "init":
        lab = custody.initialize(args.workspace, [read_json(path) for path in args.enrollments])
    else:
        lab = Lab.open(args.workspace)
        lab.ledger.require_managed()
    if command in {"init", "head"}:
        return _emit(args, head_document(lab.ledger.manifest, lab.ledger.prefix()),
                     trust_fingerprint=lab.ledger.fingerprint)
    if command == "prepare-receipt":
        request = custody.prepare_receipt(lab, read_json(args.signed_transcript), args.receiver, args.programme,
                                          args.as_of, known_height=args.known_height)
        return _emit(args, request)
    if command == "submit":
        result = custody.submit(lab, read_json(args.operation))
        if result["status"] == "committed":
            return result
        request = result.pop("request")
        return _emit(args, request, **result)
    if command == "pending":
        return _emit(args, lab.ledger.external_pending())
    if command == "commit":
        block = lab.ledger.commit_external([read_json(path) for path in args.votes])
        return _emit(args, head_document(lab.ledger.manifest, lab.ledger.prefix()), height=block["core"]["height"],
                     block_sha256=block["hash"], validators=sorted(block["votes"]))
    raise LabError("Unknown custody command")
