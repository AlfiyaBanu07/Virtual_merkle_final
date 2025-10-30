# tree.py
"""
Merkle tree utilities:
- sha256: compute sha256 hash of a string
- build_merkle_tree: construct tree levels bottom-up
- get_proof: generate Merkle proof for a leaf
- verify_proof: verify proof against a root
"""

import hashlib
from typing import List, Dict, Tuple

def sha256(x: str) -> str:
    """Return SHA-256 hash of a string."""
    return hashlib.sha256(x.encode('utf-8')).hexdigest()

def build_merkle_tree(leaves: List[str]) -> List[List[str]]:
    """
    Build Merkle tree levels from leaves to root.
    Returns:
      levels[0] -> leaf hashes
      levels[-1][0] -> Merkle root
    """
    if not leaves:
        return [[]]

    level = [sha256(str(l)) for l in leaves]
    tree = [level]

    while len(level) > 1:
        new_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else left  # duplicate if odd
            new_level.append(sha256(left + right))
        level = new_level
        tree.append(level)
    return tree

def get_proof(leaves: List[str], index: int) -> Tuple[List[Dict], str]:
    """Generate proof for leaves[index]. Returns proof steps and root."""
    tree = build_merkle_tree(leaves)
    if not tree or not tree[0]:
        return [], ""

    proof = []
    idx = index
    for lvl in range(len(tree)-1):
        layer = tree[lvl]
        is_right = idx % 2 == 1
        sibling_index = idx - 1 if is_right else idx + 1
        position = "left" if is_right else "right"

        if sibling_index < len(layer):
            proof.append({"position": position, "hash": layer[sibling_index]})
        idx //= 2

    root = tree[-1][0] if tree else ""
    return proof, root

def verify_proof(leaf: str, proof: List[Dict], root: str) -> bool:
    """Verify that leaf + proof yields the root."""
    computed = sha256(str(leaf))
    for p in proof:
        sibling = p.get("hash", "")
        if p.get("position") == "left":
            computed = sha256(sibling + computed)
        else:
            computed = sha256(computed + sibling)
    return computed == root