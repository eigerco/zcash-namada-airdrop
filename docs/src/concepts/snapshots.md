# Concepts: Snapshots

An airdrop snapshot freezes eligibility to a Zcash block height on a network (e.g. mainnet).

## Snapshot and roots

The snapshot is taken at a Zcash `height` (inclusive), and binds proofs to published roots:

- **Note commitment tree root**: Used to prove the note exists.
- **Nullifier non-membership root**: Used to prove the note was unspent.

## Published artifacts

The organizer publishes:

- `config.json`: the airdrop configuration including airdrop identifier and roots.
- `snapshot-{sapling,orchard}.bin`: the sorted nullifier lists up to the snapshot height.
- `gaptree-{sapling,orchard}.bin`: precomputed non-membership hash tree (optional).

```admonish note
Claimants should treat `config.json` as the source-of-truth for the roots their proofs must verify against, and treat the `.bin` artifacts as untrusted until they reproduce configured roots.
```

## Example

Below is an example `config.json`:

```json
{
  "network": "testnet",
  "snapshot_height": 3839800,
  "sapling": {
    "note_commitment_root": "419a5213c91492aa4b14c5a976bc677088c8ce0b757573832b96b94ac3e08916",
    "nullifier_gap_root": "dcbc0747e877f57a4538bbd31bb0a523db7da5575b10a082b61c5d1c761eb53a",
    "target_id": "ZAIRTEST",
    "value_commitment_scheme": "sha256"
  },
  "orchard": {
    "note_commitment_root": "c426461167a9722175609ae899ae3c2a8a6edcb5c9b7f917622604c3813fd026",
    "nullifier_gap_root": "62c6c660493c1bb9cd541c8d66d45fca391dabf24afaf64506032227f4e61b08",
    "target_id": "ZAIRTEST:O",
    "value_commitment_scheme": "native"
  }
}
```
