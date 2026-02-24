# Introduction

ZAIR offers privacy-preserving tools for Zcash airdrops by allowing users to prove they own eligible
notes on Zcash while preserving the privacy of the notes owned and the amounts claimed.

## Security

ZAIR is a zero-knowledge proof that proves a user knows the spend-authorizing key for an eligible Sapling/Orchard note that existed and was unspent at a published snapshot height, and binds the claim to a specific (target-chain) intent message. ZAIR prevents double-claims by exposing an airdrop-specific nullifier while keeping note details and the standard Zcash nullifier private.

ZAIR does not ensure snapshot correctness: Claim soundness assumes the organizer's `config.json` (roots, parameters, and height) was computed from the intended Zcash chain state and published honestly. Verification soundness assumes verifiers implement strict decoding and all required checks; malformed inputs must be rejected.

**This project has not been audited. See [Security](./security.md) for security details.**

## How it works

ZAIR is a proof system between an airdrop organizer (who publishes a snapshot) and claimants (who
generate claims from their wallet data). The system allows an organizer to receive signed messages
that prove ownership of an eligible note at a snapshot, and a commitment to the value for binding.

1. **Trusted setup**: if supporting proofs for Sapling (Groth16), a custom circuit is used requiring a trusted setup by the organizer, for example using multi-party computation. For Orchard,
   only a transparent setup is needed; either pre-computed or generated on-the-fly during proving.
2. **Organizer publishes a snapshot config**: at a chosen snapshot height, the organizer builds and
   publishes `config.json` containing the Sapling/Orchard note commitment roots and spent-nullifier
   non-membership roots, plus per-pool parameters (e.g. `target_id` and value-commitment scheme).
   The organizer can also publish the snapshot nullifier lists (`snapshot-*.bin`) and optional
   prebuilt gap trees (`gaptree-*.bin`) derived from those lists.
3. **Claimant prepares claim inputs**: using only a Unified Full Viewing Key (UFVK),
   the claimant scans for notes up to the snapshot height and constructs, for each eligible note,
   the private witness material needed for proving (note opening, membership path, and a gap-based
   non-membership witness against the snapshot’s spent-nullifier root). This produces a
   `claim-prepared.json` file and does **not** require spending keys.
4. **Claimant generates one ZK-proof per note**: the proving step uses local spending key material
   (derived from a seed) to generate a Sapling or Orchard claim proof per eligible note. Each proof
   binds to the published snapshot roots, keeps the standard Zcash nullifier private, and exposes a
   domain-separated **airdrop nullifier** for double-claim prevention.
5. **Claimant signs a submission message**: each proof is signed with a spend-authorizing
   signature over a digest that binds together the proof fields, the configured `target_id`, and a
   hash of an external message (the target-chain claim intent). This proves the claimant
   controls the spend-authorizing key and binds the proof claim to the intended message ("destination").
6. **Organizer / verifiers check and de-duplicate**: verification consists of (1) checking the
   ZK proofs against `config.json` and (2) checking the spend-authorizing signatures and message
   binding. The verifier enforces one-time use by rejecting duplicate airdrop nullifiers.

## Concepts overview

The system is built around key concepts:

- **roles & keys**: organizer, claimant, and verifier roles, and the key material each requires.
- **snapshots**: snapshot the chain at given height as source-of-truth for note balances.
- **non-membership proofs**: to prove that a given note was not already spent.
- **airdrop nullifiers**: to guard against double-claims by tracking notes already claimed.
- **value commitments**: to bind the value in the note to the airdrop claim.

See [Concepts](./concepts/overview.md) for more details.

## Airdrop proofs

The system provides concrete ZK-proofs using above concepts that integrate into Zcash. The proofs are for Groth16 (Sapling) and Halo2 (Orchard) respectively, that include design choices such as airdrop nullifier and gap-tree definitions, see [Airdrop Proofs](./airdrop-proofs/index.md) for more details.

## Pipeline and CLI tool

The CLI is organized into these command groups:

1. **`key`**: Derive seeds and viewing keys from a mnemonic.
2. **`setup`**: Generate proving/verifying parameters (organizer/developer).
3. **`config`**: Build and export snapshot configuration and artifacts.
4. **`claim`**: Prepare, prove, and sign claims for eligible notes.
5. **`verify`**: Verify claim proofs and their spend-authorizing signatures.

See [CLI Reference](./cli/index.md) for more details.

## Integrations

ZAIR is designed to integrate with target chains that consume the signed claim submissions. The target chain verifies proofs and signatures, de-duplicates, and binds value commitments.

See [Namada](./integration/namada.md) as example integration.
