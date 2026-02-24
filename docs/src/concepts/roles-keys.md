# Roles & Keys

This page describes the roles and key considerations.

## Roles

### Organizer

The organizer sets up the airdrop by choosing a Zcash snapshot height, then fetch the on-chain nullifier sets, and build the airdrop configuration (`config.json`). This is the source-of-truth to be published, together with the verification key for custom Groth16 circuit if Sapling pools are enabled.

To avoid claimers needing to fetch nullifiers (e.g. via external services), the organizer will typically publish the configuration along with the nullifier snapshot. For further optimization, the organizer may also include the gap-tree hashes that will speed up by avoiding hashing the full non-membership tree when claiming. Finally, an organizer may also include (transparent) halo2 parameters to avoid the halo2 parameter generation when claiming.

The organizer does **not** need access to any user key material.

### Claimant

The claimant is a Zcash user wanting to claim an airdrop by proving they own shielded unspent notes at the snapshot height. The claim pipeline involves three steps with different key requirements:

1. **Prepare** (viewing key only): scans the chain for eligible notes at a given lightwalletd node.
2. **Prove** (spending key): generates ZK proofs demonstrating note ownership.
3. **Sign** (spending key): signs the proofs with a message binding the claim to an intent.

A claimer must trust that `config.json` does not have target ID `Zcash_nf` for Sapling and `z.cash:Orchard` for Orchard, otherwise the airdrop nullifier equals the standard note nullifier. More generally, a claimer should trust any software he provides his private spending key to.

### Verifier

The verifier checks that submitted claims are valid. This requires the published `config.json`, verifying keys, and the signed submission. The verifier checks the signature and checks against double-claims by rejecting claims with airdrop nullifiers seen previously. The verifier then checks the eligible ownership proof, and finally verifies any external requirements on the message. For airdrops, a message would typically contain an external zero-knowledge proof binding the (commitment of the) value claimed to the eligible amount, that needs to to be verified successfully as well.

## Keys

This project uses a hexadecimal seed-file as the root key to derive everything from. We offer tools to derive this from the standard mnemonic that most wallets can export. For the note preparation and scanning, only the unified viewing key `ufvk` is needed, that one can also derive via the CLI tool.

### Key derivation CLI

The `zair key` commands help derive the keys needed for the claim pipeline:

```bash
# Derive seed from mnemonic
zair key derive-seed --mnemonic-file mnemonic.txt

# Derive UFVK from seed (for claim prepare)
zair key derive-ufvk --seed seed.txt --network testnet
```

See [CLI Reference: key](../cli/key.md) for details.

## Security considerations

- The **seed** and **mnemonic** are the root secrets. Anyone with access to them can spend all funds in the wallet. Never share them.
- The **UFVK** allows viewing all transactions but cannot authorize spends. It is safe to use on a machine with network access (e.g. for scanning via lightwalletd).
- The **prove** and **sign** steps require the seed. In a security-conscious setup, these should run on an isolated trusted machine producing and passing only the claim submission outside.
- Intermediate files like `claim-prepared.json` and `claim-proofs-secrets.json` contain sensitive witness material. Treat them accordingly.
