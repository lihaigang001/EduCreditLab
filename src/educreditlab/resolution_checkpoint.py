"""Audit a signed publication history and verify selected decisions against its checkpoint."""

from .merkle import (MerkleTree, _append_to_last_path, _appended_siblings, _refresh_frontier, _refresh_path,
                     _sibling_positions, _verify_multiproof_hashes, verify_multiproof, verify_path)
from .model import LabError, digest, fields, hex_digest, integer, sequence
from .policy_history import MAX_REVISIONS
from .policy_resolution import _validate_authority
from .resolution_history import HANDOVER_KIND, _verified_history, _verify_publication_resolution, _verify_publications

CHECKPOINT_KIND = "educreditlab-resolution-publication-checkpoint"
WITNESS_KIND = "educreditlab-resolution-publication-witness"
BATCH_KIND = "educreditlab-resolution-publication-batch-witness"
DELTA_KIND = "educreditlab-resolution-publication-delta"
CHECKPOINT_HASHES = "history_sha256 initial_authority_sha256 divergence_sha256 latest_publication_sha256 merkle_root"
ENTRY_HASHES = "publication_sha256 decision_sha256 authority_sha256"


def _publication_leaf(body, authority):
    return {"number": body["number"], "publication_sha256": digest(body),
            "decision_sha256": body["decision_sha256"], "authority_sha256": authority}


def _publication_witness(descriptor, entry, siblings):
    return {"schema": 1, "kind": WITNESS_KIND, "checkpoint": descriptor, "entry": entry, "siblings": siblings}


def _publication_batch(descriptor, entries, siblings):
    return {"schema": 1, "kind": BATCH_KIND, "checkpoint": descriptor, "entries": entries, "siblings": siblings}


def _publication_numbers(numbers, size):
    requested = sequence(numbers, "expected publication numbers", 1, size)
    ordered = sorted(integer(number, "selected publication number", 1, size) for number in requested)
    if len(set(ordered)) != len(ordered):
        raise LabError("Expected publication numbers must be distinct")
    return ordered


class _PublicationIndex:
    def __init__(self, history, state, initial_authority):
        self._entries = [_publication_leaf(body, authority) for body, authority in state.entries]
        self._tree = MerkleTree(self._entries)
        self._descriptor = {"schema": 1, "kind": CHECKPOINT_KIND, "history_sha256": state.root,
                            "initial_authority_sha256": initial_authority,
                            "divergence_sha256": history["divergence_sha256"],
                            "publication_count": len(self._entries), "latest_publication_sha256": state.tip,
                            "merkle_root": self._tree.root}

    @property
    def descriptor(self):
        return self._descriptor.copy()

    @property
    def fingerprint(self):
        return digest(self._descriptor)

    def witness(self, number=None):
        """Select a publication by its one-based ordinal, defaulting to the audited head."""
        size = len(self._entries)
        selected = size if number is None else integer(number, "selected publication number", 1, size)
        index = selected - 1
        return _publication_witness(self.descriptor, self._entries[index].copy(), self._tree.path(index))

    def batch_witness(self, numbers):
        """Prove an explicit set of one-based publication numbers in a shared tree."""
        indices = [number - 1 for number in _publication_numbers(numbers, len(self._entries))]
        return _publication_batch(self.descriptor, [self._entries[index].copy() for index in indices],
                                 self._tree.multipath(indices))


def audit_resolution_checkpoint(history, trusted_authority, trusted_publication):
    """Check the initial trust anchor, all publication signatures, and the expected head."""
    state = _verified_history(history, trusted_authority, trusted_publication)
    if not state.entries:
        raise LabError("A resolution checkpoint requires at least one published decision")
    return _PublicationIndex(history, state, trusted_authority)


def _checkpoint_status(descriptor, trusted_publication_checkpoint):
    fields(descriptor, "schema kind publication_count " + CHECKPOINT_HASHES, "resolution publication checkpoint")
    integer(descriptor["schema"], "publication checkpoint schema", 1, 1)
    if descriptor["kind"] != CHECKPOINT_KIND:
        raise LabError("Expected an EduCreditLab resolution publication checkpoint")
    size = integer(descriptor["publication_count"], "publication count", 1, MAX_REVISIONS)
    for field in CHECKPOINT_HASHES.split():
        hex_digest(descriptor[field], field)
    expected = hex_digest(trusted_publication_checkpoint, "independently trusted publication checkpoint fingerprint")
    if digest(descriptor) != expected:
        raise LabError("Witness does not match the independently trusted publication checkpoint")
    return {"publication_checkpoint_sha256": expected, "history_sha256": descriptor["history_sha256"],
            "initial_authority_sha256": descriptor["initial_authority_sha256"],
            "divergence_sha256": descriptor["divergence_sha256"], "publication_count": size,
            "latest_publication_sha256": descriptor["latest_publication_sha256"]}


def _validate_entry(entry, selected, descriptor):
    fields(entry, "number " + ENTRY_HASHES, "publication checkpoint entry")
    size = descriptor["publication_count"]
    integer(entry["number"], "witness publication number", 1, size)
    if entry["number"] != selected:
        raise LabError("Witness does not cover the selected publication number")
    for field in ENTRY_HASHES.split():
        hex_digest(entry[field], field)
    if selected == size and entry["publication_sha256"] != descriptor["latest_publication_sha256"]:
        raise LabError("The head publication does not match the checkpoint endpoint")


def _publication_status(entry, descriptor):
    number = entry["number"]
    head = number == descriptor["publication_count"]
    return {"is_checkpoint_head": head, "verified_publication": number, "verified_publication_sha256": entry["publication_sha256"],
            "verified_authority_sha256": entry["authority_sha256"], "verified_decision_sha256": entry["decision_sha256"]}


def verify_resolution_witness(witness, trusted_publication_checkpoint, *, number=None):
    """Authenticate the expected publication against an independently pinned checkpoint."""
    fields(witness, "schema kind checkpoint entry siblings", "resolution publication witness")
    integer(witness["schema"], "publication witness schema", 1, 1)
    if witness["kind"] != WITNESS_KIND:
        raise LabError("Expected an EduCreditLab resolution publication witness")
    descriptor = witness["checkpoint"]
    checkpoint = _checkpoint_status(descriptor, trusted_publication_checkpoint)
    size = checkpoint["publication_count"]
    selected = size if number is None else integer(number, "selected publication number", 1, size)
    entry = witness["entry"]
    _validate_entry(entry, selected, descriptor)
    verify_path(entry, selected - 1, witness["siblings"], size, descriptor["merkle_root"])
    return {"publication_checkpoint_verified": True, **checkpoint, **_publication_status(entry, descriptor)}


def _verify_publication_multiproof(descriptor, entries, siblings, *, indices=None):
    leaves = [{"index": entry["number"] - 1, "entry": entry} for entry in entries]
    return verify_multiproof(leaves, siblings, descriptor["publication_count"], descriptor["merkle_root"],
                             project_indices=indices)


def _validate_batch(batch, trusted_publication_checkpoint, numbers):
    fields(batch, "schema kind checkpoint entries siblings", "resolution publication batch witness")
    integer(batch["schema"], "publication batch witness schema", 1, 1)
    if batch["kind"] != BATCH_KIND:
        raise LabError("Expected an EduCreditLab resolution publication batch witness")
    descriptor = batch["checkpoint"]
    checkpoint = _checkpoint_status(descriptor, trusted_publication_checkpoint)
    size = checkpoint["publication_count"]
    selected = _publication_numbers(numbers, size)
    entries = sequence(batch["entries"], "publication batch entries", len(selected), len(selected))
    for entry, number in zip(entries, selected, strict=True):
        _validate_entry(entry, number, descriptor)
    return checkpoint, entries


def verify_resolution_batch(batch, trusted_publication_checkpoint, *, numbers):
    """Authenticate exactly the expected set of publications against one checkpoint."""
    checkpoint, entries = _validate_batch(batch, trusted_publication_checkpoint, numbers)
    descriptor = batch["checkpoint"]
    _verify_publication_multiproof(descriptor, entries, batch["siblings"])
    return {"publication_checkpoint_batch_verified": True, **checkpoint,
            "verified_publications": [_publication_status(entry, descriptor) for entry in entries]}


def select_resolution_witness(batch, trusted_publication_checkpoint, *, numbers, selected, single=False):
    """Authenticate the entire source batch and prove only a requested subset."""
    checkpoint, entries = _validate_batch(batch, trusted_publication_checkpoint, numbers)
    size = checkpoint["publication_count"]
    target = _publication_numbers(selected, size)
    if single and len(target) != 1:
        raise LabError("A single witness requires exactly one selected publication")
    descriptor = batch["checkpoint"].copy()
    siblings = _verify_publication_multiproof(descriptor, entries, batch["siblings"],
                                              indices=[number - 1 for number in target])
    wanted = set(target)
    chosen = [entry.copy() for entry in entries if entry["number"] in wanted]
    if single:
        verify_path(chosen[0], target[0] - 1, siblings, size, descriptor["merkle_root"])
        return _publication_witness(descriptor, chosen[0], siblings)
    _verify_publication_multiproof(descriptor, chosen, siblings)
    return _publication_batch(descriptor, chosen, siblings)


def _verified_merge_entries(witness, trusted_publication_checkpoint):
    kind = witness.get("kind") if isinstance(witness, dict) else None
    if kind == WITNESS_KIND:
        entry = witness.get("entry")
        fields(entry, "number " + ENTRY_HASHES, "publication checkpoint entry")
        verify_resolution_witness(witness, trusted_publication_checkpoint, number=entry["number"])
        return [entry]
    if kind == BATCH_KIND:
        entries = sequence(witness.get("entries"), "publication batch entries", 1, MAX_REVISIONS)
        for entry in entries:
            fields(entry, "number " + ENTRY_HASHES, "publication checkpoint entry")
        verify_resolution_batch(witness, trusted_publication_checkpoint, numbers=[entry["number"] for entry in entries])
        return entries
    raise LabError("Merge inputs must be single or batch publication witnesses")


def _require_merge_sources(witnesses):
    if not isinstance(witnesses, list) or not witnesses:
        raise LabError("Supply at least one publication witness to merge")


def _merge_resolution_witnesses(witnesses, trusted_publication_checkpoint):
    descriptor = None
    merged_entries = {}
    known_siblings = {}
    for witness in witnesses:
        entries = _verified_merge_entries(witness, trusted_publication_checkpoint)
        if descriptor is None:
            descriptor = witness["checkpoint"]
        elif witness["checkpoint"] != descriptor:
            raise LabError("Merge inputs must describe the same publication checkpoint")
        for entry in entries:
            number = entry["number"]
            if merged_entries.setdefault(number, entry) != entry:
                raise LabError("Source witnesses disagree on a publication entry")
        indices = [entry["number"] - 1 for entry in entries]
        positions = _sibling_positions(indices, descriptor["publication_count"])
        for position, sibling in zip(positions, witness["siblings"], strict=True):
            if known_siblings.setdefault(position, sibling) != sibling:
                raise LabError("Source witnesses disagree on a Merkle sibling")

    size = descriptor["publication_count"]
    selected = sorted(merged_entries)
    # Every sibling needed by the union borders a selected subtree in at
    # least one source. That source supplied the hash for the sibling.
    positions = _sibling_positions([number - 1 for number in selected], size)
    try:
        siblings = [known_siblings[position] for position in positions]
    except KeyError as exc:
        raise LabError("Source witnesses do not cover the merged Merkle frontier") from exc
    entries = [merged_entries[number].copy() for number in selected]
    _verify_publication_multiproof(descriptor, entries, siblings)
    return _publication_batch(descriptor.copy(), entries, siblings)


def _require_union(batch, numbers):
    selected = _publication_numbers(numbers, batch["checkpoint"]["publication_count"])
    if selected != [entry["number"] for entry in batch["entries"]]:
        raise LabError("Merged witnesses must cover exactly the expected publication numbers")
    return batch


def merge_resolution_witnesses(witnesses, trusted_publication_checkpoint, *, numbers):
    """Verify each source and prove the exact expected union at the pinned checkpoint."""
    _require_merge_sources(witnesses)
    batch = _merge_resolution_witnesses(witnesses, trusted_publication_checkpoint)
    return _require_union(batch, numbers)


def _review_publication(selected, packet, **evidence):
    result = _verify_publication_resolution(selected, packet, selected["verified_authority_sha256"],
                                            selected["verified_decision_sha256"], **evidence)
    return {**result, **selected}


def verify_checkpoint_resolution(witness, packet, trusted_publication_checkpoint, *, number=None,
                                 bundle=None, trusted_manifest=None, trusted_checkpoint=None,
                                 expected_proof=None, proof=None):
    """Use the publication's decision and authority to verify its archived artifacts."""
    selected = verify_resolution_witness(witness, trusted_publication_checkpoint, number=number)
    return _review_publication(selected, packet, bundle=bundle, trusted_manifest=trusted_manifest,
                               trusted_checkpoint=trusted_checkpoint, expected_proof=expected_proof, proof=proof)


def verify_checkpoint_batch_resolution(batch, packet, trusted_publication_checkpoint, *, numbers, number,
                                       bundle=None, trusted_manifest=None, trusted_checkpoint=None,
                                       expected_proof=None, proof=None):
    """Verify a resolution for a specified member of the authenticated batch."""
    checkpoint = verify_resolution_batch(batch, trusted_publication_checkpoint, numbers=numbers)
    selected = integer(number, "publication selected for review", 1, checkpoint["publication_count"])
    for entry in checkpoint["verified_publications"]:
        if selected == entry["verified_publication"]:
            return _review_publication({**checkpoint, **entry}, packet, bundle=bundle, trusted_manifest=trusted_manifest,
                                       trusted_checkpoint=trusted_checkpoint, expected_proof=expected_proof, proof=proof)
    raise LabError("The publication selected for review must be in the verified batch")


def resolution_checkpoint_delta(history, trusted_authority, trusted_publication, *, from_number):
    """Export the signed suffix and base authority profile from an audited history."""
    state = _verified_history(history, trusted_authority, trusted_publication)
    size = len(state.entries)
    if size < 2:
        raise LabError("A publication delta requires a nonempty base and at least one new publication")
    number = integer(from_number, "base publication number", 1, size - 1)
    effective = history["authority"]
    for body, _ in reversed(state.entries[:number]):
        if body["kind"] == HANDOVER_KIND:
            effective = body["successor_authority"]
            break
    return {"schema": 1, "kind": DELTA_KIND, "base_publication_count": number,
            "base_publication_sha256": digest(state.entries[number - 1][0]), "base_authority": effective,
            "publications": history["publications"][number:]}


def _verified_extension(witness, delta, trusted_checkpoint, trusted_publication, *, recorded_hashes=None):
    base = verify_resolution_witness(witness, trusted_checkpoint)
    expected = hex_digest(trusted_publication, "independently expected publication fingerprint")
    fields(delta, "schema kind base_publication_count base_publication_sha256 base_authority publications",
           "resolution publication delta")
    integer(delta["schema"], "publication delta schema", 1, 1)
    if delta["kind"] != DELTA_KIND:
        raise LabError("Expected an EduCreditLab resolution publication delta")
    size = base["publication_count"]
    integer(delta["base_publication_count"], "delta base publication count", size, size)
    tip = base["latest_publication_sha256"]
    if hex_digest(delta["base_publication_sha256"], "delta base publication fingerprint") != tip:
        raise LabError("Publication delta does not match the checkpoint head")
    authority = base["verified_authority_sha256"]
    profile = delta["base_authority"]
    _validate_authority(profile, authority)
    if size == MAX_REVISIONS:
        raise LabError("The publication checkpoint is at the publication limit")
    records = sequence(delta["publications"], "new resolution publications", 1, MAX_REVISIONS - size)
    state = _verify_publications(records, base["history_sha256"], tip, profile, authority, schema=2, base_count=size)
    if state.tip != expected:
        raise LabError("Publication delta does not match the independently expected latest publication")
    additions = [_publication_leaf(body, authority) for body, authority in state.entries]
    root, siblings = _append_to_last_path(witness["entry"], witness["siblings"], size, additions,
                                          recorded_hashes=recorded_hashes)
    descriptor = {**witness["checkpoint"], "publication_count": size + len(records),
                  "latest_publication_sha256": state.tip, "merkle_root": root}
    return _publication_witness(descriptor, additions[-1], siblings), additions


def extend_resolution_checkpoint(witness, delta, trusted_checkpoint, trusted_publication):
    """Check a suffix against the pinned head and return the advanced head witness."""
    advanced, _ = _verified_extension(witness, delta, trusted_checkpoint, trusted_publication)
    return advanced


def refresh_resolution_witness(witness, delta, archived, trusted_checkpoint, trusted_publication, *, number):
    """Prove the same selected publication under the advanced checkpoint."""
    integer(number, "selected publication number", 1, MAX_REVISIONS)
    verify_resolution_witness(archived, trusted_checkpoint, number=number)
    advanced, additions = _verified_extension(witness, delta, trusted_checkpoint, trusted_publication)
    descriptor = advanced["checkpoint"]
    index = number - 1
    entry = archived["entry"].copy()
    siblings = _refresh_path(index, archived["siblings"], witness["checkpoint"]["publication_count"],
                             witness["entry"], witness["siblings"], additions)
    verify_path(entry, index, siblings, descriptor["publication_count"], descriptor["merkle_root"])
    return _publication_witness(descriptor, entry, siblings)


def refresh_resolution_batch(witness, delta, archived, trusted_checkpoint, trusted_publication, *, numbers):
    """Advance a retained batch, verifying the signed continuation once."""
    verify_resolution_batch(archived, trusted_checkpoint, numbers=numbers)
    advanced, additions = _verified_extension(witness, delta, trusted_checkpoint, trusted_publication)
    return _refresh_verified_batch(witness, archived, advanced["checkpoint"], additions)


def _refresh_verified_batch(witness, archived, descriptor, additions, *, final_subtrees=None, appended_hashes=None):
    entries = [entry.copy() for entry in archived["entries"]]
    indices = [entry["number"] - 1 for entry in entries]
    siblings = _refresh_frontier(indices, archived["siblings"], witness["checkpoint"]["publication_count"],
                                 witness["entry"], witness["siblings"], additions, final_subtrees=final_subtrees,
                                 appended_hashes=appended_hashes)
    _verify_publication_multiproof(descriptor, entries, siblings)
    return _publication_batch(descriptor, entries, siblings)


def _appended_publication_batch(head, descriptor, additions, numbers, *, appended_hashes=None):
    base_size = head["checkpoint"]["publication_count"]
    selected = _publication_numbers(numbers, descriptor["publication_count"])
    if selected[0] <= base_size:
        raise LabError("Requested new publications must be after the base checkpoint")
    frontier = _appended_siblings(base_size, head["entry"], head["siblings"])
    indices = [number - 1 for number in selected]
    if appended_hashes is None:
        siblings = _verify_publication_multiproof(descriptor, additions, frontier, indices=indices)
    else:
        # These digests were produced in order during the verified append.
        active = dict(enumerate(appended_hashes, base_size))
        siblings = _verify_multiproof_hashes(active, frontier, descriptor["publication_count"],
                                            bytes.fromhex(descriptor["merkle_root"]), project_indices=indices)
    entries = [additions[number - base_size - 1] for number in selected]
    return _publication_batch(descriptor, entries, siblings)


def _require_advance_sources(witnesses, new_publications):
    if new_publications is None:
        _require_merge_sources(witnesses)
    elif not isinstance(witnesses, list):
        raise LabError("Supply publication witnesses as a list")


def advance_and_merge_resolution_witnesses(head, delta, witnesses, trusted_checkpoint, trusted_publication, *,
                                          numbers, new_publications=None):
    """Advance retained witnesses and optionally derive proofs for selected signed additions."""
    _require_advance_sources(witnesses, new_publications)
    advanced, additions = _verified_extension(head, delta, trusted_checkpoint, trusted_publication)
    descriptor = advanced["checkpoint"]
    archived, current = [], []
    for witness in witnesses:
        checkpoint = witness.get("checkpoint") if isinstance(witness, dict) else None
        if checkpoint == head["checkpoint"]:
            archived.append(witness)
        elif checkpoint == descriptor:
            current.append(witness)
        else:
            raise LabError("Source witness must match the base or advanced publication checkpoint")
    if new_publications is not None:
        current.append(_appended_publication_batch(head, descriptor, additions, new_publications))
    if archived:
        base_batch = _merge_resolution_witnesses(archived, trusted_checkpoint)
        refreshed = _refresh_verified_batch(head, base_batch, descriptor, additions)
        if not current:
            return _require_union(refreshed, numbers)
        current.append(refreshed)
    return merge_resolution_witnesses(current, digest(descriptor), numbers=numbers)


def advance_chain_and_merge_resolution_witnesses(head, deltas, witnesses, trusted_checkpoint, trusted_publications, *,
                                                 numbers, new_publications=None):
    """Verify each pinned continuation and combine selected proofs at the final checkpoint."""
    return _merge_resolution_chain(head, deltas, witnesses, trusted_checkpoint, trusted_publications,
                                   numbers=numbers, new_publications=new_publications)


def _merge_resolution_chain(head, deltas, witnesses, trusted_checkpoint, trusted_publications, *,
                            numbers, new_publications, load_delta=None):
    """Check in-memory deltas or load each file immediately before verifying its stage."""
    _require_advance_sources(witnesses, new_publications)
    steps = sequence(deltas, "signed publication continuations", 1, MAX_REVISIONS - 1)
    tips = sequence(trusted_publications, "independently expected stage publication fingerprints", len(steps), len(steps))
    checkpoints = {}
    additions = []
    addition_hashes = []
    current_head, pin = head, trusted_checkpoint
    for step, tip in zip(steps, tips, strict=True):
        advanced, appended = _verified_extension(
            current_head, step if load_delta is None else load_delta(step), pin, tip, recorded_hashes=addition_hashes)
        checkpoints[current_head["checkpoint"]["publication_count"]] = (current_head, pin)
        additions.extend(appended)
        current_head, pin = advanced, digest(advanced["checkpoint"])
    descriptor = current_head["checkpoint"]
    final_size = descriptor["publication_count"]
    checkpoints[final_size] = (current_head, pin)

    groups = {}
    for witness in witnesses:
        claimed = witness.get("checkpoint") if isinstance(witness, dict) else None
        count = claimed.get("publication_count") if isinstance(claimed, dict) else None
        if type(count) is not int or count not in checkpoints:
            raise LabError("Source witness must match a checkpoint in the verified continuation chain")
        groups.setdefault(count, []).append(witness)

    base_size = head["checkpoint"]["publication_count"]
    current = groups.pop(final_size, [])
    # All refreshes end at the same authenticated Merkle tree. An affected
    # sibling at a given level and position has the same root for every source.
    final_subtrees = {}
    for size, sources in groups.items():
        source_head, source_pin = checkpoints[size]
        batch = _merge_resolution_witnesses(sources, source_pin)
        offset = size - base_size
        current.append(_refresh_verified_batch(source_head, batch, descriptor, additions[offset:],
                                               final_subtrees=final_subtrees, appended_hashes=addition_hashes[offset:]))
    if new_publications is not None:
        current.append(_appended_publication_batch(head, descriptor, additions, new_publications,
                                                   appended_hashes=addition_hashes))
    return merge_resolution_witnesses(current, pin, numbers=numbers)
