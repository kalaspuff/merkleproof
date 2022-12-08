import hashlib
from typing import List, Tuple, cast

import pytest

from merkleproof.tree import MerkleTree


def hash_function(pair: Tuple[str, str]) -> str:
    return f"TH({sorted(pair)[0]}, {sorted(pair)[1]})"


@pytest.mark.parametrize(
    "leaves, root",
    [
        (["a"], "a"),  # 1 leaf
        (["a", "b"], "TH(a, b)"),  # 2 leaves
        (["a", "b", "c"], "TH(TH(a, b), c)"),  # 3 leaves
        (["a", "b", "c", "d"], "TH(TH(a, b), TH(c, d))"),  # 4 leaves
        (["a", "b", "c", "d", "e"], "TH(TH(TH(a, b), TH(c, d)), e)"),  # 5 leaves
        (["a", "b", "c", "d", "e", "f"], "TH(TH(TH(a, b), TH(c, d)), TH(e, f))"),  # 6 leaves
        (["a", "b", "c", "d", "e", "f", "g"], "TH(TH(TH(a, b), TH(c, d)), TH(TH(e, f), g))"),  # 7 leaves
        (["a", "b", "c", "d", "e", "f", "g", "h"], "TH(TH(TH(a, b), TH(c, d)), TH(TH(e, f), TH(g, h)))"),  # 8 leaves
    ],
)
def test_root(leaves: List[str], root: str) -> None:
    tree = MerkleTree(leaves, hash_function=hash_function)
    assert tree.get_root() == root


def test_get_root_with_no_leaves() -> None:
    tree = MerkleTree([])
    with pytest.raises(Exception):
        tree.get_root()


@pytest.mark.parametrize(
    "leaves, leaf, proof",
    [
        (["a"], "a", []),
        (["a", "b"], "a", ["b"]),
        (["a", "b"], "b", ["a"]),
        (["a", "b", "c"], "a", ["b", "c"]),
        (["a", "b", "c"], "b", ["a", "c"]),
        (["a", "b", "c"], "c", ["TH(a, b)"]),
        (["a", "b", "c", "d"], "a", ["b", "TH(c, d)"]),
        (["a", "b", "c", "d"], "b", ["a", "TH(c, d)"]),
        (["a", "b", "c", "d"], "c", ["d", "TH(a, b)"]),
        (["a", "b", "c", "d"], "d", ["c", "TH(a, b)"]),
        (["a", "b", "c", "d", "e"], "a", ["b", "TH(c, d)", "e"]),
        (["a", "b", "c", "d", "e"], "e", ["TH(TH(a, b), TH(c, d))"]),
        (["a", "b", "c", "d", "e", "f"], "a", ["b", "TH(c, d)", "TH(e, f)"]),
        (["a", "b", "c", "d", "e", "f"], "e", ["f", "TH(TH(a, b), TH(c, d))"]),
        (["a", "b", "c", "d", "e", "f", "g"], "b", ["a", "TH(c, d)", "TH(TH(e, f), g)"]),
        (["a", "b", "c", "d", "e", "f", "g"], "f", ["e", "g", "TH(TH(a, b), TH(c, d))"]),
        (["a", "b", "c", "d", "e", "f", "g"], "g", ["TH(e, f)", "TH(TH(a, b), TH(c, d))"]),
        (["a", "b", "c", "d", "e", "f", "g", "h"], "d", ["c", "TH(a, b)", "TH(TH(e, f), TH(g, h))"]),
    ],
)
def test_proof(leaves: List[str], leaf: str, proof: List[str]) -> None:
    tree = MerkleTree(leaves, hash_function=hash_function)
    assert tree.get_proof(leaf) == proof
    assert MerkleTree.verify(leaf, proof, tree.get_root(), hash_function=hash_function)


def test_get_proof_with_no_leaves() -> None:
    tree = MerkleTree([])
    with pytest.raises(Exception):
        tree.get_proof("")


def test_get_proof_by_index_with_no_leaves() -> None:
    tree = MerkleTree([])
    with pytest.raises(Exception):
        tree.get_proof_by_index(0)


def test_get_invalid_proof() -> None:
    tree = MerkleTree(["a", "b"])
    with pytest.raises(Exception):
        tree.get_proof("c")


def test_get_invalid_proof_by_index() -> None:
    tree = MerkleTree(["a", "b"])
    with pytest.raises(Exception):
        tree.get_proof_by_index(5)


@pytest.mark.parametrize(
    "leaves",
    [
        (["a"]),
        (["a", "b"]),
        (["a", "b"]),
        (["a", "b", "c"]),
        (["a", "b", "c"]),
        (["a", "b", "c"]),
        (["a", "b", "c", "d"]),
        (["a", "b", "c", "d"]),
        (["a", "b", "c", "d"]),
        (["a", "b", "c", "d"]),
        (["a", "b", "c", "d", "e"]),
        (["a", "b", "c", "d", "e"]),
        (["a", "b", "c", "d", "e", "f"]),
        (["a", "b", "c", "d", "e", "f"]),
        (["a", "b", "c", "d", "e", "f", "g"]),
        (["a", "b", "c", "d", "e", "f", "g"]),
        (["a", "b", "c", "d", "e", "f", "g"]),
        (["a", "b", "c", "d", "e", "f", "g", "h"]),
    ],
)
def test_verify_hashed_proof(leaves: List[str]) -> None:
    hashed_leaves: List[str] = cast(List[str], map(lambda leaf: hashlib.sha256(leaf.encode()).hexdigest(), leaves))
    tree = MerkleTree(hashed_leaves)
    root = tree.get_root()
    for leaf in hashed_leaves:
        proof = tree.get_proof(leaf)
        assert MerkleTree.verify(leaf, proof, root)
