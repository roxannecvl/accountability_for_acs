"use strict";

function poseidonHash(poseidon, inputs) {
  return poseidon(inputs);
}

function buildLeaf({ poseidon, claimName, claimValue }) {
  const nameHash = poseidonHash(poseidon, [claimName]);
  return poseidonHash(poseidon, [nameHash, claimValue]);
}

function buildMerkleRoot({ poseidon, leaves }) {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error("buildMerkleRoot: leaves must be a non-empty array");
  }
  if ((leaves.length & (leaves.length - 1)) !== 0) {
    throw new Error(`buildMerkleRoot: leaves length must be power-of-two, got ${leaves.length}`);
  }

  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(poseidonHash(poseidon, [level[i], level[i + 1]]));
    }
    level = next;
  }
  return level[0];
}

function getMerkleProof({ poseidon, leaves, index, depth }) {
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new Error("getMerkleProof: leaves must be a non-empty array");
  }
  if (!Number.isInteger(index) || index < 0 || index >= leaves.length) {
    throw new Error(`getMerkleProof: bad index ${index}`);
  }
  if (!Number.isInteger(depth) || depth <= 0) {
    throw new Error(`getMerkleProof: bad depth ${depth}`);
  }

  let idx = index;
  let level = leaves.slice();
  const pathElements = [];
  const pathIndices = [];

  for (let d = 0; d < depth; d++) {
    const isRight = (idx & 1) === 1;
    const siblingIndex = isRight ? idx - 1 : idx + 1;
    pathElements.push(level[siblingIndex]);
    pathIndices.push(isRight ? 1 : 0);

    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(poseidonHash(poseidon, [level[i], level[i + 1]]));
    }
    level = next;
    idx = Math.floor(idx / 2);
  }

  return { pathElements, pathIndices };
}

module.exports = {
  buildLeaf,
  buildMerkleRoot,
  getMerkleProof,
};

