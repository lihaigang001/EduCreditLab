"""Resolve signed policy versions over assessment dates and committed ledger views."""

from __future__ import annotations

from datetime import datetime, timezone

from .model import LabError, applies, day, fields, hex_digest, ident, integer, same_catalog, text

POLICY_FIELDS = "issuer receiver programme version valid_from valid_until policy_sha256"
POLICY_EVENTS = ("policy", "policy-revision")
ZERO = "0" * 64


def _overlaps(left, right):
    return max(left["valid_from"], right["valid_from"]) < min(left["valid_until"],
                                                              right["valid_until"])


def _instant(value):
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is not None and parsed.utcoffset() is not None:
            return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        pass
    raise LabError("Knowledge time must be an ISO 8601 timestamp with a UTC offset")


def block_timestamp(block):
    finalization = block.get("finalization")
    if finalization is not None:
        return finalization["recorded_at"], "finalization"
    return block["core"]["recorded_at"], "proposal"


def knowledge_view(chain, *, known_height=None, known_at=None):
    """Select an exact prefix. UTC points are resolved only for ordered signed times."""
    if known_height is not None and known_at is not None:
        raise LabError("Choose either a knowledge height or a UTC knowledge instant")
    if known_at is not None:
        cutoff = _instant(known_at)
        timed = [(height, _instant(block_timestamp(block)[0])) for height, block in enumerate(chain, 1)
                 if block_timestamp(block)[1] == "finalization"]
        if not timed:
            raise LabError("This history has no certified finalization times. Select a knowledge height.")
        certified_from = timed[0][0]
        if len(timed) != len(chain) - certified_from + 1:
            raise LabError("A finalization time is missing after the first timed block. Select a knowledge height.")
        if certified_from > 1 and cutoff < timed[0][1]:
            raise LabError("This instant predates the certified time series. Select a knowledge height.")
        times = [timestamp for _, timestamp in timed]
        if any(before > after for before, after in zip(times, times[1:])):
            raise LabError("The ledger clock moved backwards. Select an exact knowledge height.")
        known_height = certified_from - 1 + sum(recorded <= cutoff for recorded in times)
    height = len(chain) if known_height is None else integer(known_height, "knowledge height", 0, len(chain))
    if height == 0:
        return {"height": 0, "head_sha256": ZERO, "recorded_at": None, "time_basis": None}
    block = chain[height - 1]
    timestamp, basis = block_timestamp(block)
    return {"height": height, "head_sha256": block["hash"],
            "recorded_at": timestamp, "time_basis": basis}


class PolicyHistory:
    """The registry and receipt index derived by replaying a verified prefix."""

    def __init__(self, prefix=()):
        self.policies = {}
        self.receipts = set()
        self.hashes = [ZERO]
        for block in prefix:
            self.add(block)

    def add(self, block):
        core = block["core"]
        body = core["event"]["body"]
        payload = body["payload"]
        if body["kind"] in POLICY_EVENTS:
            revision = body["kind"] == "policy-revision"
            descriptor = payload["policy"] if revision else payload
            timestamp, basis = block_timestamp(block)
            self.policies[descriptor["policy_sha256"]] = {
                "policy": descriptor, "height": core["height"],
                "recorded_at": timestamp, "time_basis": basis, "block_sha256": block["hash"],
                "supersedes": payload["supersedes"] if revision else None,
                "reason": payload["reason"] if revision else None,
            }
        elif body["kind"] == "receipt":
            self.receipts.add(payload["receipt_sha256"])
        self.hashes.append(block["hash"])

    def validate_policy_event(self, kind, payload, actor, registered_actors):
        parent_hash = None
        if kind == "policy-revision":
            fields(payload, "policy supersedes reason", "policy revision")
            parent_hash = hex_digest(payload["supersedes"], "superseded policy hash")
            if text(payload["reason"], "revision reason", 400) != payload["reason"]:
                raise LabError("Revision reason must be normalized text")
            descriptor = payload["policy"]
        else:
            descriptor = payload
        fields(descriptor, POLICY_FIELDS, "policy registration")
        if (descriptor["receiver"] != actor
                or ident(descriptor["issuer"], "issuer") not in registered_actors):
            raise LabError("Only a receiving institution may register policy for a known issuer")
        ident(descriptor["programme"], "programme")
        ident(descriptor["version"], "version")
        policy_hash = hex_digest(descriptor["policy_sha256"], "policy hash")
        start = day(descriptor["valid_from"], "valid_from")
        end = day(descriptor["valid_until"], "valid_until")
        if end <= start or policy_hash in self.policies:
            raise LabError("Invalid interval or repeated policy registration")

        scoped = [item for item in self.policies.values() if same_catalog(descriptor, item["policy"])]
        if any(item["policy"]["version"] == descriptor["version"] for item in scoped):
            raise LabError("This policy version is already registered")
        overlaps = [item for item in scoped if _overlaps(descriptor, item["policy"])]
        if parent_hash is None:
            if overlaps:
                raise LabError("Overlapping policy dates require an explicit policy revision")
            return

        parent = self.policies.get(parent_hash)
        if parent is None or not same_catalog(descriptor, parent["policy"]):
            raise LabError("The parent policy must already be registered in the same institution and programme scope")
        if not parent["policy"]["valid_from"] <= start < end <= parent["policy"]["valid_until"]:
            raise LabError("A revision must be contained in its parent policy's effective interval")
        if any(item["height"] > parent["height"] for item in overlaps):
            raise LabError("The parent policy is no longer active throughout the requested revision interval")

    def validate_receipt_event(self, payload, actor, *, managed=False):
        has_knowledge = managed or (isinstance(payload, dict) and "knowledge" in payload)
        fields(payload, "policy_sha256 receipt_sha256" + (" knowledge" if has_knowledge else "")
               + (" approval" if managed else ""), "receipt anchor")
        if managed:
            approval = fields(payload["approval"], "height head_sha256", "receipt approval view")
            if (type(approval["height"]) is not int or approval["height"] != len(self.hashes) - 1
                    or approval["head_sha256"] != self.hashes[-1]):
                raise LabError("Receipt approval must bind the immediately preceding committed view")
        receipt_hash = hex_digest(payload["receipt_sha256"], "receipt hash")
        policy_hash = hex_digest(payload["policy_sha256"], "policy hash")
        entry = self.policies.get(policy_hash)
        if entry is None or entry["policy"]["receiver"] != actor:
            raise LabError("Receipt must follow its policy registration and be signed by its receiver")
        if receipt_hash in self.receipts:
            raise LabError("Repeated receipt commitment")
        if has_knowledge:
            knowledge = fields(payload["knowledge"], "height head_sha256", "receipt knowledge")
            height = integer(knowledge["height"], "receipt knowledge height", 1, len(self.hashes) - 1)
            if (hex_digest(knowledge["head_sha256"], "knowledge block hash") != self.hashes[height]
                    or entry["height"] > height):
                raise LabError("Receipt knowledge must bind a prior block containing its policy")
        elif any(item["supersedes"] is not None and same_catalog(entry["policy"], item["policy"])
                 for item in self.policies.values()):
            raise LabError("Receipts for revised policy scopes require a committed knowledge view")

    def select(self, issuer, receiver, programme, effective_on, height):
        when = day(effective_on, "as_of")
        issuer = ident(issuer, "issuer")
        receiver = ident(receiver, "receiver")
        programme = ident(programme, "programme")
        for entry in reversed(self.policies.values()):
            if entry["height"] <= height and applies(entry["policy"], issuer, receiver, programme, when):
                return entry
        raise LabError(f"No policy for {issuer} → {receiver}/{programme} on {when} at height {height}")

