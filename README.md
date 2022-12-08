# `merkleproof`

[![Python package](https://github.com/kalaspuff/merkleproof/workflows/Python%20package/badge.svg)](https://github.com/kalaspuff/merkleproof/actions/workflows/pythonpackage.yml)
[![pypi](https://badge.fury.io/py/merkleproof.svg)](https://pypi.python.org/pypi/merkleproof/)
[![Made with Python](https://img.shields.io/pypi/pyversions/merkleproof)](https://www.python.org/)
[![MIT License](https://img.shields.io/github/license/kalaspuff/merkleproof.svg)](https://github.com/kalaspuff/merkleproof/blob/master/LICENSE)
[![Code coverage](https://codecov.io/gh/kalaspuff/merkleproof/branch/master/graph/badge.svg)](https://codecov.io/gh/kalaspuff/merkleproof/tree/master/merkleproof)

*Build merkle trees, create merkle proofs, verify that the merkle root (hash root) can be reconstructed. The typical things you would do with a merkle tree.*

### Creating merkle trees, merkle proofs and verifying their consistency

* Simple package aimed at learning to work with merkle trees, produce proofs, etc.
* Built to be able to generate proofs that can be used in tandem with Solidity contracts.
* Follows OpenZeppelin's practices regarding produced merkle trees and proof output.

```pycon
>>> tree = MerkleTree(["a", "b"])
>>> tree.root
'fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603'
```

### Work in progress

Note that this is under development and should not be used outside of a developer setting.
