"""Ed25519 signing, enrollment and the public key history of a ledger."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import os
import re

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, Encoding, PrivateFormat, load_pem_private_key,
)

from .model import LabError, canonical, fields, hex_digest, ident, integer, text

ROLES = {"actor": "actors", "validator": "validators"}


def _message(domain, body):
    return b"EduCreditLab/v1/" + domain.encode("ascii") + b"\x00" + canonical(body)


def public_key(key):
    return key.public_key().public_bytes_raw().hex()


def sign(key, domain, body):
    return key.sign(_message(domain, body)).hex()


def sign_local(private_hex, domain, body):
    material = hex_digest(private_hex, "local signing key")
    return sign(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(material)), domain, body)


def _verify_signature(public_hex, message, signature):
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
    key.verify(bytes.fromhex(signature), message)


_verify_local_signature = lru_cache(maxsize=4096)(_verify_signature)


def verify(public_hex, domain, body, signature, *, cached=False):
    try:
        if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{128}", signature):
            raise ValueError("invalid signature encoding")
        message = _message(domain, body)
        if cached and domain in ("event", "vote", "finalization", "key-possession") and len(message) <= 4096:
            _verify_local_signature(public_hex, message, signature)
        else:
            _verify_signature(public_hex, message, signature)
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise LabError(f"Invalid {domain} signature") from exc


def local_keypair():
    key = Ed25519PrivateKey.generate()
    return key.private_bytes_raw().hex(), public_key(key)


def save_private_key(path, key, password):
    if not password:
        raise LabError("A passphrase is required to encrypt the private key")
    try:
        pem = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(password))
    except (ValueError, UnsupportedAlgorithm) as exc:
        raise LabError("The supplied passphrase cannot be used to encrypt the key") from exc
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(pem)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        Path(path).unlink(missing_ok=True)
        raise


def load_private_key(path, password):
    with Path(path).open("rb") as stream:
        if os.name == "posix" and os.fstat(stream.fileno()).st_mode & 0o077:
            raise LabError("The private key file must be accessible only to its owner")
        pem = stream.read(4097)
    if not password or len(pem) > 4096 or not pem.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
        raise LabError("Expected a passphrase and an encrypted Ed25519 PKCS#8 key")
    try:
        key = load_pem_private_key(pem, password=password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise LabError("Cannot unlock the encrypted private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise LabError("Expected an Ed25519 private key")
    return key


def role_group(role):
    if not isinstance(role, str) or role not in ROLES:
        raise LabError("Signing role must be actor or validator")
    return ROLES[role]


def enroll(role, name, key):
    role_group(role)
    body = {"schema": 1, "role": role, "name": ident(name, "signer name"), "public_key": public_key(key)}
    return {"body": body, "signature": sign(key, "enrollment", body)}


def read_enrollment(document):
    fields(document, "body signature", "signed enrollment")
    body = fields(document["body"], "schema role name public_key", "enrollment body")
    integer(body["schema"], "enrollment schema", 1, 1)
    role_group(body["role"])
    ident(body["name"], "signer name")
    key = hex_digest(body["public_key"], "enrollment public key")
    verify(key, "enrollment", body, document["signature"])
    return body


def rotation_message(body):
    payload = body["payload"]
    return {"network": body["network"], "name": body["actor"], **{
        key: payload[key] for key in ("role", "previous_key", "replacement_key", "reason")
    }}


class KeyRegistry:
    """Active keys and retired keys, advanced only after a certified rotation."""

    def __init__(self, manifest, prefix=()):
        self.active = {group: dict(manifest[group]) for group in ROLES.values()}
        self.used = {key for members in self.active.values() for key in members.values()}
        self.rotations = []
        if manifest["schema"] == 2:
            for block in prefix:
                self.apply(block["core"])

    def active_key(self, role, name):
        group = self.active[role_group(role)]
        if name not in group:
            raise LabError("Signer is outside the configured role and identity registry")
        return group[name]

    def require_owner(self, role, name, private_key):
        if self.active_key(role, name) != public_key(private_key):
            raise LabError("The key is not active for this role and identity")

    def check_rotation(self, body, *, cached=False):
        change = fields(body["payload"], "role previous_key replacement_key reason possession", "key rotation")
        previous = hex_digest(change["previous_key"], "previous public key")
        replacement = hex_digest(change["replacement_key"], "replacement public key")
        if text(change["reason"], "rotation reason", 400) != change["reason"]:
            raise LabError("Rotation reason must be normalized text")
        if previous != self.active_key(change["role"], body["actor"]):
            raise LabError("A rotation must authorize replacement of the currently active key")
        if replacement in self.used:
            raise LabError("A replacement key must be unused in this network")
        verify(replacement, "key-possession", rotation_message(body), change["possession"], cached=cached)

    def apply(self, core):
        body = core["event"]["body"]
        if body["kind"] == "key-rotation":
            change = body["payload"]
            key, name = change["replacement_key"], body["actor"]
            self.active[role_group(change["role"])][name] = key
            self.used.add(key)
            self.rotations.append({"height": core["height"], **rotation_message(body)})
