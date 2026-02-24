# Concepts: Non-Membership Proofs

To claim an airdrop, a claimant must show their note existed at the snapshot and was unspent at the snapshot height. For shielded pools, "spent" is represented by a pool-specific nullifier set. We prove unspentness with a **gap-based Merkle non-membership proof**: prove the claimant’s (private) nullifier lies strictly between two consecutive spent nullifiers from the organizer’s snapshot.

## Setup: spent-nullifier set and gaps

Let $S = \{x_1,\dots,x_n\}$ be the spent nullifiers observed on-chain up to the snapshot height (inclusive), sorted and de-duplicated by their canonical pool-specific ordering.

$$
\mathsf{MIN} < x_1 < \dots < x_n < \mathsf{MAX}.
$$

Here $\mathsf{MIN}$ and $\mathsf{MAX}$ are fixed sentinel bounds for the pool’s nullifier domain (Sapling uses $0$ and $\textsf{U256::MAX}$; Orchard uses $0$ and the maximum valid field element $p-1$).

Define the open-interval gaps:

$$
G_0=(\mathsf{MIN},x_1),\quad
G_i=(x_i,x_{i+1}),\ \text{for } 0<i<n,\quad
G_n=(x_n,\mathsf{MAX}).
$$

Here $y \in (a,b)$ if and only if $a < y < b$.

## Merkle commitment to gaps

The gap tree commits to each adjacent pair $(a,b)$ by hashing a Merkle leaf using a
pool-specific leaf hash with explicit domain separation (via a fixed "leaf level" distinct from
internal-node levels).

$$
L_i := H_{\mathsf{gap}}(a,b).
$$

The Merkle root $r_{\mathsf{gap}}$ of these leaves is published as the snapshot’s **gap-root** (one per pool).

In the current implementation, domain separation is provided by the hash personalization/level:

- **Sapling**: $H_{\mathsf{gap}}(a,b)$ is the Sapling Pedersen hash of the 512-bit string `a || b` (concatenation of two 32-byte nullifiers) using Merkle personalization level 62.
- **Orchard**: $H_{\mathsf{gap}}(a,b)$ is computed as a level-62 Orchard Merkle combine of the two canonical Orchard nullifier nodes corresponding to `a` and `b`.

## Non-membership proof statement

Given the claimant’s private nullifier $y$, the proof shows:

1. **Gap inclusion**: $L_i$ opens to the published root $r_{\mathsf{gap}}$ via a standard Merkle authentication path.
2. **Strict interval**: for the corresponding bounds $(a,b)$, the circuit enforces $a < y < b$.

Together this implies $y \notin S$: if $y$ were equal to any spent nullifier in $S$, it could not satisfy a strict inequality with the adjacent bounds.

## Security notes

- **Edge cases**: Since the outer gaps use fixed values $\mathsf{MIN}$ and $\mathsf{MAX}$, nullifiers equal to either value cannot be used by this construction. We decided to accept this edge case given nullifiers are random and accepting them would imply further circuit constraints.
- **Field validity (Orchard)**: In addition to the gap argument, Orchard nullifiers must be checked to be valid encodings of field elements (e.g. $y < p$) separately from above.
