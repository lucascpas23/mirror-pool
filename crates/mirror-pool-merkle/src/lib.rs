#![forbid(unsafe_code)]
//! Deterministic, domain-separated Merkle cohort construction and proof verification.

use mirror_pool_core::Digest32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard limit preventing memory-exhaustion cohorts.
pub const MAX_LEAVES: usize = 100_000;

/// Inclusion proof bound to a round and root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CohortProof {
    pub leaf_hash: Digest32,
    pub leaf_index: u32,
    pub sibling_hashes: Vec<Digest32>,
    pub merkle_root: Digest32,
    pub round_id: u64,
}

/// Deterministically sorted Merkle cohort.
#[derive(Clone, Debug)]
pub struct MerkleCohort {
    leaves: Vec<Digest32>,
    levels: Vec<Vec<Digest32>>,
}

impl MerkleCohort {
    /// Build a canonical tree after sorting leaves and rejecting duplicates.
    pub fn build(mut leaves: Vec<Digest32>) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyTree);
        }
        if leaves.len() > MAX_LEAVES {
            return Err(MerkleError::TooManyLeaves);
        }
        leaves.sort_unstable();
        if leaves.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(MerkleError::DuplicateLeaf);
        }
        let mut levels = vec![leaves.clone()];
        while levels.last().map_or(0, Vec::len) > 1 {
            let current = levels.last().ok_or(MerkleError::EmptyTree)?;
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            for pair in current.chunks(2) {
                let right = pair.get(1).copied().unwrap_or(pair[0]);
                next.push(parent(pair[0], right));
            }
            levels.push(next);
        }
        Ok(Self { leaves, levels })
    }

    /// Merkle root.
    pub fn root(&self) -> Result<Digest32, MerkleError> {
        self.levels
            .last()
            .and_then(|level| level.first())
            .copied()
            .ok_or(MerkleError::EmptyTree)
    }

    /// Generate proof for an exact leaf.
    pub fn proof(&self, leaf: Digest32, round_id: u64) -> Result<CohortProof, MerkleError> {
        let mut index = self
            .leaves
            .binary_search(&leaf)
            .map_err(|_| MerkleError::LeafNotFound)?;
        let leaf_index = u32::try_from(index).map_err(|_| MerkleError::TooManyLeaves)?;
        let mut siblings = Vec::with_capacity(self.levels.len().saturating_sub(1));
        for level in self.levels.iter().take(self.levels.len().saturating_sub(1)) {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            siblings.push(level.get(sibling_index).copied().unwrap_or(level[index]));
            index /= 2;
        }
        Ok(CohortProof {
            leaf_hash: leaf,
            leaf_index,
            sibling_hashes: siblings,
            merkle_root: self.root()?,
            round_id,
        })
    }
}

impl CohortProof {
    /// Verify leaf path, root and expected round binding.
    pub fn verify(&self, expected_root: Digest32, expected_round: u64) -> Result<(), MerkleError> {
        if self.round_id != expected_round {
            return Err(MerkleError::WrongRound);
        }
        if self.merkle_root != expected_root {
            return Err(MerkleError::WrongRoot);
        }
        let mut node = self.leaf_hash;
        let mut index = usize::try_from(self.leaf_index).map_err(|_| MerkleError::InvalidProof)?;
        for sibling in &self.sibling_hashes {
            node = if index % 2 == 0 {
                parent(node, *sibling)
            } else {
                parent(*sibling, node)
            };
            index /= 2;
        }
        if node != expected_root {
            return Err(MerkleError::InvalidProof);
        }
        Ok(())
    }
}

fn parent(left: Digest32, right: Digest32) -> Digest32 {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&left.0);
    bytes[32..].copy_from_slice(&right.0);
    Digest32::hash(b"merkle-node", &bytes)
}

/// Merkle construction and verification failures.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum MerkleError {
    #[error("cohort tree cannot be empty")]
    EmptyTree,
    #[error("cohort exceeds the bounded maximum")]
    TooManyLeaves,
    #[error("duplicate cohort leaf")]
    DuplicateLeaf,
    #[error("leaf not found")]
    LeafNotFound,
    #[error("proof is for another round")]
    WrongRound,
    #[error("proof is for another root")]
    WrongRoot,
    #[error("invalid inclusion proof")]
    InvalidProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaves(count: u8) -> Vec<Digest32> {
        (0..count)
            .map(|value| Digest32::hash(b"leaf", &[value]))
            .collect()
    }

    #[test]
    fn tree_is_order_independent_and_odd_leaf_proofs_work() {
        let mut reversed = leaves(5);
        reversed.reverse();
        let first = MerkleCohort::build(leaves(5)).unwrap_or_else(|error| panic!("{error}"));
        let second = MerkleCohort::build(reversed).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first.root(), second.root());
        for leaf in leaves(5) {
            let proof = first
                .proof(leaf, 11)
                .unwrap_or_else(|error| panic!("{error}"));
            assert_eq!(proof.verify(first.root().unwrap_or_default(), 11), Ok(()));
        }
    }

    #[test]
    fn tampered_proofs_are_rejected() {
        let tree = MerkleCohort::build(leaves(4)).unwrap_or_else(|error| panic!("{error}"));
        let root = tree.root().unwrap_or_default();
        let mut proof = tree
            .proof(leaves(4)[0], 7)
            .unwrap_or_else(|error| panic!("{error}"));
        proof.leaf_index ^= 1;
        assert_eq!(proof.verify(root, 7), Err(MerkleError::InvalidProof));
        assert_eq!(proof.verify(root, 8), Err(MerkleError::WrongRound));
    }
}
