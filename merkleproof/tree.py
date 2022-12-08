import hashlib
from typing import Callable, Iterable, List, Optional, Tuple, cast


class MerkleTree:
    leaves: List[str] = []
    root: Optional[str] = None
    hash_function: Callable

    def __init__(self, leaves: List[str], hash_function: Optional[Callable] = None) -> None:
        self.leaves = sorted(leaves)
        self.root = None
        self.hash_function = hash_function or self._hash_pair

    def build(self) -> None:
        if not self.leaves:
            raise Exception("Tree has no leaves")
        self.root = self._build(self.leaves)[0]

    def _build(self, leaves: List[str]) -> List[str]:
        if len(leaves) == 1:
            return [leaves[0]]
        else:
            return self._build(self._upper_layer(leaves))

    def _upper_layer(self, leaves: List[str]) -> List[str]:
        return [self.hash_function(pair) if "" not in pair else pair[0] for pair in self._pairwise(leaves)]

    @staticmethod
    def _hash_pair(pair: Iterable[str]) -> str:
        return hashlib.sha256("".join(pair).encode()).hexdigest()

    @staticmethod
    def _pairwise(iterable: List[str]) -> Iterable[Tuple[str, str]]:
        i = iter(iterable)
        if len(iterable) % 2:
            i = iter(iterable + [""])
        return zip(i, i)

    def get_root(self) -> str:
        if not self.root:
            self.build()
        return cast(str, self.root)

    def get_proof(self, leaf: str) -> List[str]:
        if leaf not in self.leaves:
            raise Exception("Invalid leaf for proof")
        return self.get_proof_by_index(self.leaves.index(leaf))

    def get_proof_by_index(self, index: int) -> List[str]:
        if index >= len(self.leaves):
            raise Exception("Invalid index for proof")
        return self._get_proof(self.get_root(), index, self.leaves)

    def _get_proof(self, root: str, index: int, leaves: List[str]) -> List[str]:
        if root == leaves[index]:
            return []
        else:
            sindex = divmod(index, 2)[0] * 2
            pair = leaves[sindex : (sindex + 2)]
            if len(pair) == 1:
                return self._get_proof(root, sindex // 2, self._upper_layer(leaves))
            return [(set(pair) - set([leaves[index]])).pop()] + self._get_proof(
                root, sindex // 2, self._upper_layer(leaves)
            )

    @classmethod
    def verify(cls, leaf: str, proof: List[str], root: str, hash_function: Optional[Callable] = None) -> bool:
        return cls._verify(leaf, proof, root, hash_function=hash_function or cls._hash_pair)

    @classmethod
    def _verify(cls, leaf: str, proof: List[str], root: str, hash_function: Callable) -> bool:
        if len(proof) == 0:
            return root == leaf
        else:
            return cls._verify(hash_function((leaf, proof[0])), proof[1:], root, hash_function=hash_function)
