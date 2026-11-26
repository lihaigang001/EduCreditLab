"""SHA-256 Merkle trees with domain-separated leaves and inclusion paths."""

from hashlib import sha256

from .model import LabError, canonical, fields, hex_digest, integer, sequence


def _leaf(value):
    return sha256(b"\x00" + canonical(value)).digest()


def _pair(left, right):
    return sha256(b"\x01" + left + right).digest()


def _missing_siblings(active, width):
    return [index ^ 1 for index in sorted(active) if (index ^ 1) < width and (index ^ 1) not in active]


def _sibling_positions(indices, width):
    """Yield the canonical frontier positions for an existing selection."""
    active = set(indices)
    level = 0
    while width > 1:
        for index in _missing_siblings(active, width):
            yield level, index
        active = {index // 2 for index in active}
        width = (width + 1) // 2
        level += 1


class MerkleTree:
    """Pair adjacent nodes and carry an unpaired node up unchanged."""

    def __init__(self, entries):
        layer = [_leaf(entry) for entry in entries]
        self.layers = [layer]
        while len(layer) > 1:
            parent = [_pair(layer[index], layer[index + 1]) for index in range(0, len(layer) - 1, 2)]
            if len(layer) % 2:
                parent.append(layer[-1])
            self.layers.append(parent)
            layer = parent

    @property
    def root(self):
        return self.layers[-1][0].hex() if self.layers[0] else sha256(b"").hexdigest()

    def path(self, index):
        integer(index, "leaf index", 0, len(self.layers[0]) - 1)
        siblings = []
        for layer in self.layers[:-1]:
            sibling = index ^ 1
            if sibling < len(layer):
                siblings.append(layer[sibling].hex())
            index //= 2
        return siblings

    def multipath(self, indices):
        """Emit the frontier hashes in order of level and active leaf position."""
        active = {integer(index, "leaf index", 0, len(self.layers[0]) - 1) for index in indices}
        if not active:
            raise LabError("A Merkle multiproof must supply at least one leaf")
        return [self.layers[level][index].hex() for level, index in _sibling_positions(active, len(self.layers[0]))]


def verify_path(entry, index, path, size, root):
    """Verify an exact inclusion path, including the position in an odd-sized tree."""
    integer(size, "Merkle tree size", 1)
    integer(index, "leaf index", 0, size - 1)
    sequence(path, "Merkle path", 0, (size - 1).bit_length())
    expected = bytes.fromhex(hex_digest(root, "checkpoint Merkle root"))
    result, consumed = _leaf(entry), 0
    while size > 1:
        if (index ^ 1) < size:
            if consumed == len(path):
                raise LabError("Merkle path is missing a sibling")
            sibling = bytes.fromhex(hex_digest(path[consumed], "Merkle sibling"))
            result = _pair(sibling, result) if index % 2 else _pair(result, sibling)
            consumed += 1
        index //= 2
        size = (size + 1) // 2
    if consumed != len(path) or result != expected:
        raise LabError("Merkle path does not match the trusted checkpoint")


def _subtrees_before_last(size, siblings):
    # The set bits of the last index enumerate complete subtrees to its left.
    index = size - 1
    levels = (level for level in range(index.bit_length()) if index & (1 << level))
    return {level: bytes.fromhex(sibling) for level, sibling in zip(levels, siblings, strict=True)}


def _append_leaf_hash(subtrees, node):
    path = []
    level = 0
    while level in subtrees:
        left = subtrees.pop(level)
        path.append(left)
        node = _pair(left, node)
        level += 1
    subtrees[level] = node
    return level, path


def _subtree_root(right_to_left):
    remaining = iter(right_to_left)
    root = next(remaining)
    for left in remaining:
        root = _pair(left, root)
    return root


def _append_to_last_path(last_entry, siblings, size, entries, *, recorded_hashes=None):
    """Extend a verified rightmost path and optionally collect the new leaf hashes in order."""
    subtrees = _subtrees_before_last(size, siblings)
    level, path = _append_leaf_hash(subtrees, _leaf(last_entry))
    for entry in entries:
        node = _leaf(entry)
        level, path = _append_leaf_hash(subtrees, node)
        if recorded_hashes is not None:
            recorded_hashes.append(node)

    ordered = sorted(subtrees.items())
    path.extend(node for height, node in ordered if height > level)
    root = _subtree_root(node for _, node in ordered)
    return root.hex(), [sibling.hex() for sibling in path]


def _refresh_path(index, path, size, last_entry, last_path, entries):
    """Update a verified old path using the verified right edge and new entries."""
    return _refresh_frontier((index,), path, size, last_entry, last_path, entries)


def _prefix_subtrees(size, last_entry, last_path):
    base_subtrees = _subtrees_before_last(size, last_path)
    _append_leaf_hash(base_subtrees, _leaf(last_entry))
    return base_subtrees


def _appended_siblings(size, last_entry, last_path):
    """Get the canonical sibling hashes for proving the entire nonempty suffix."""
    subtrees = _prefix_subtrees(size, last_entry, last_path)
    # The suffix borders one complete base subtree at each set bit of size.
    # These roots occur in increasing level order in the suffix multiproof.
    return [root.hex() for _, root in sorted(subtrees.items())]


def _refresh_frontier(indices, path, size, last_entry, last_path, entries, *, final_subtrees=None,
                      appended_hashes=None):
    """Update the shared sibling hashes for the same indices after an append."""
    base_subtrees = _prefix_subtrees(size, last_entry, last_path)
    old_siblings = dict(zip(_sibling_positions(indices, size), path, strict=True))
    if final_subtrees is None:
        final_subtrees = {}
    updated = []
    total = size + len(entries)
    for level, sibling in _sibling_positions(indices, total):
        position = level, sibling
        width = 1 << level
        start = sibling * width
        if start + width <= size:
            updated.append(old_siblings[position])
            continue
        if position not in final_subtrees:
            subtrees = {}
            if start < size:
                # Smaller base subtrees exactly tile the old part of this sibling.
                subtrees = {height: root for height, root in base_subtrees.items() if height < level}
            first = max(start - size, 0)
            stop = min(start + width, total) - size
            nodes = map(_leaf, entries[first:stop]) if appended_hashes is None else appended_hashes[first:stop]
            for node in nodes:
                _append_leaf_hash(subtrees, node)
            root = _subtree_root(subtrees[height] for height in sorted(subtrees))
            final_subtrees[position] = root.hex()
        updated.append(final_subtrees[position])
    return updated


def verify_multiproof(leaves, siblings, size, root, *, project_indices=None):
    """Verify the shared frontier, optionally returning sibling hashes for a subset."""
    integer(size, "Merkle tree size", 1)
    sequence(leaves, "Merkle multiproof leaves", 1, size)
    expected = bytes.fromhex(hex_digest(root, "checkpoint Merkle root"))
    active = {}
    previous = -1
    for leaf in leaves:
        fields(leaf, "index entry", "Merkle multiproof leaf")
        previous = integer(leaf["index"], "ordered Merkle leaf index", previous + 1, size - 1)
        active[previous] = _leaf(leaf["entry"])
    return _verify_multiproof_hashes(active, siblings, size, expected, project_indices=project_indices)


def _verify_multiproof_hashes(active, siblings, size, expected, *, project_indices=None):
    """Verify a frontier of locally computed leaf hashes against expected root bytes."""
    sequence(siblings, "Merkle multiproof siblings", 0, len(active) * (size - 1).bit_length())
    projected = None
    if project_indices is not None:
        requested = sequence(project_indices, "projected Merkle leaf indices", 1, size)
        selected = {integer(index, "projected Merkle leaf index", 0, size - 1) for index in requested}
        if len(selected) != len(requested) or not selected.issubset(active):
            raise LabError("Projection requires distinct leaves proved by the source batch")
        projected = []
    consumed = 0
    while size > 1:
        for index in _missing_siblings(active, size):
            if consumed == len(siblings):
                raise LabError("Merkle multiproof is missing a sibling")
            active[index] = bytes.fromhex(hex_digest(siblings[consumed], "Merkle sibling"))
            consumed += 1
        if projected is not None:
            # After filling the source frontier, every sibling of a selected
            # node is either an active source node or was just supplied.
            projected.extend(active[index].hex() for index in _missing_siblings(selected, size))
            selected = {index // 2 for index in selected}
        active = {index // 2: _pair(value, active[index + 1]) if index + 1 < size else value
                  for index, value in active.items() if index % 2 == 0}
        size = (size + 1) // 2
    if consumed != len(siblings) or active[0] != expected:
        raise LabError("Merkle multiproof does not match the trusted checkpoint")
    return projected
