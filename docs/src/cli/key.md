# `zair key`

Key derivation utilities for the airdrop proving pipeline.

## `zair key derive-seed`

Derives a 64-byte BIP-39 seed from a mnemonic and writes it as 128 hex characters to a file.

```bash
zair key derive-seed --mnemonic-file mnemonic.txt --no-passphrase --output seed.txt
```

## `zair key derive-ufvk`

Derives a Unified Full Viewing Key (UFVK) from a seed file or mnemonic. The UFVK is mostly useful for `claim prepare` to scan for eligible notes without requiring spending authority. This would allow a user to outsource the claim preparation to a party who only holds the viewing key, not spend-keys.

```bash
zair key derive-ufvk --seed seed.txt --network testnet --output ufvk.txt
```

Exactly one of `--seed`, `--mnemonic-file`, or `--mnemonic-stdin` must be provided.

```admonish note
The `--account` index must match the account used later in `claim prove` and `claim sign`.
```
