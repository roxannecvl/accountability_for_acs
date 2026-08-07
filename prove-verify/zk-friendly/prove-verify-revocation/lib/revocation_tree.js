"use strict";

/**
 * Packed status-list Merkle trees (all-zero leaves).
 * O(depth) witness builder for uniform zero trees.
 */

function poseidonHash2(poseidon, left, right) {
  return poseidon([left, right]);
}

function nextPowerOfTwo(n) {
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

function feToString(F, x) {
  return F.toString(x);
}

function buildUniformZeroLevelHashes(poseidon, depth) {
  const F = poseidon.F;
  const levelHash = new Array(depth + 1);
  levelHash[0] = F.e(0n);
  for (let i = 0; i < depth; i++) {
    levelHash[i + 1] = poseidonHash2(poseidon, levelHash[i], levelHash[i]);
  }
  return levelHash;
}

function proofForUniformZeroTree(levelHash, index, depth) {
  const pathElements = [];
  const pathIndices = [];
  for (let i = 0; i < depth; i++) {
    pathIndices.push((index >> i) & 1);
    pathElements.push(levelHash[i]);
  }
  return { pathElements, pathIndices, leaf: levelHash[0] };
}

function buildUniformZeroTree(poseidon, leafCount) {
  if ((leafCount & (leafCount - 1)) !== 0) {
    throw new Error(`leaf count must be power of two, got ${leafCount}`);
  }
  const depth = Math.log2(leafCount);
  const levelHash = buildUniformZeroLevelHashes(poseidon, depth);
  return {
    uniformZero: true,
    levelHash,
    root: levelHash[depth],
    leafCount,
    depth,
  };
}

function buildPackedRevocationTree(poseidon, population, bitsPerLeaf) {
  const numLeaves = Math.ceil(population / bitsPerLeaf);
  const paddedLeafCount = nextPowerOfTwo(numLeaves);
  const tree = buildUniformZeroTree(poseidon, paddedLeafCount);
  return { ...tree, population, bitsPerLeaf, paddedLeafCount, numLeaves };
}

function indexToPackedPosition(credentialIndex, bitsPerLeaf) {
  const leafIndex = Math.floor(credentialIndex / bitsPerLeaf);
  const bitIndex = credentialIndex % bitsPerLeaf;
  return { leafIndex, bitIndex };
}

function proofForPacked({ poseidon, tree, credentialIndex }) {
  const { leafIndex, bitIndex } = indexToPackedPosition(credentialIndex, tree.bitsPerLeaf);
  if (!tree.uniformZero) {
    throw new Error("proofForPacked requires uniform-zero tree");
  }
  const proof = proofForUniformZeroTree(tree.levelHash, leafIndex, tree.depth);
  const F = poseidon.F;
  return {
    credentialIndex: credentialIndex.toString(),
    leafIndex: leafIndex.toString(),
    bitIndex: bitIndex.toString(),
    leafValue: "0",
    pathElements: proof.pathElements.map((x) => feToString(F, x)),
    pathIndices: proof.pathIndices.map((x) => x.toString()),
    revocationRoot: feToString(F, tree.root),
  };
}

module.exports = {
  buildPackedRevocationTree,
  proofForPacked,
};