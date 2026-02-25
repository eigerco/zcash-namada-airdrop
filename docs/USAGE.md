# Usage Guide

> **Work in Progress**: This project is under active development. Not all features described in this guide are fully implemented yet, and some details may change.

This guide walks you through the complete workflow for:

1. **Airdrop organizers**: Building an airdrop snapshot configuration from Zcash blockchain data
2. **Users**: Claiming an airdrop using privacy-preserving non-membership proofs

## Overview

**As a Zcash user** with shielded funds (Sapling or Orchard notes) who wants to participate in the Namada airdrop, **you need to prove** that you held unspent funds at a specific blockchain height **without revealing your actual nullifiers** (which would compromise your privacy).

### The Problem

Zcash's shielded pools use nullifiers to track spent notes. When you spend a note, its nullifier gets published to the blockchain. To prove you had unspent funds at the airdrop snapshot, you'd normally need to show your nullifier isn't in the set of spent nullifiers - but revealing your nullifier would link your note to your identity.

### The Solution

This toolkit combines **non-membership proofs** with a custom **Groth16 ZK circuit**:

**Non-membership proofs** use Merkle trees built from sorted nullifiers. To prove your nullifier isn't in the set, you show it falls in a "gap" between two adjacent nullifiers in the tree, along with a Merkle proof that this gap exists.

The **ZK circuit** then proves three things simultaneously:

1. **Note ownership**: Your note commitment exists in the Zcash commitment tree
2. **Unspent status**: Your nullifier falls within a valid gap in the non-membership tree (the note wasn't spent)
3. **Hiding nullifier**: A "hiding nullifier" is correctly derived from your actual nullifier

The **hiding nullifier** is a privacy-preserving transformation of your real nullifier, used on-chain for double-claim prevention. It cannot be reversed to reveal your actual nullifier or link to your Zcash transaction history.

The ZK proof convinces the verifier of all three facts without revealing your actual nullifier, note value, or any other private data.

## Feature Flags

The `zair-cli` and `zair-sdk` crates use the `prove` feature to control proving support.

- **Without `prove`**: lighter verification-focused build.
- **With `prove`** (default): includes proof generation and local parameter setup.

In the CLI, `setup sapling`, `setup orchard`, `claim prove`, and `claim run` are only available when `prove` is enabled.

## Workflow

### Step 1: Build the Airdrop Snapshot

Run `config build` to:

1. Fetch all nullifiers from the blockchain up to the snapshot height
2. Build Merkle trees for Sapling and Orchard pools
3. Export snapshot files and a configuration JSON with Merkle roots

```bash
zair config build \
  --height 3743871 \
  --network testnet \
  --pool both \
  --lightwalletd https://testnet.zec.rocks:443 \
  --target-sapling ZAIRTEST \
  --scheme-sapling native \
  --target-orchard ZAIRTEST:O \
  --scheme-orchard native \
  --config-out config.json \
  --snapshot-out-sapling snapshot-sapling.bin \
  --snapshot-out-orchard snapshot-orchard.bin \
  --gap-tree-out-sapling gaptree-sapling.bin \
  --gap-tree-out-orchard gaptree-orchard.bin
```

This produces:

- `config.json` - Contains Merkle roots for verification
- `snapshot-sapling.bin` - Sapling pool snapshot nullifiers
- `snapshot-orchard.bin` - Orchard pool snapshot nullifiers
- `gaptree-sapling.bin` - Sapling pool precomputed gap-tree nodes
- `gaptree-orchard.bin` - Orchard pool precomputed gap-tree nodes

**Parameters of `config build` explained:**

| Parameter                | Description                                                                                                                     |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------- |
| `--network`              | Network to use (`mainnet` or `testnet`). Default: `mainnet`                                                                     |
| `--height`               | Snapshot block height (inclusive)                                                                                               |
| `--pool`                 | Pool selection: `sapling`, `orchard`, or `both` (default)                                                                       |
| `--lightwalletd`         | (Optional) URL of a lightwalletd server. Defaults: `https://zec.rocks:443` (mainnet), `https://testnet.zec.rocks:443` (testnet) |
| `--target-sapling`       | Sapling target id for hiding nullifier derivation (must be exactly 8 bytes)                                                     |
| `--scheme-sapling`       | Sapling value commitment scheme (`native` or `sha256`)                                                                          |
| `--target-orchard`       | Orchard target id for hiding nullifier derivation (must be <= 32 bytes)                                                         |
| `--scheme-orchard`       | Orchard value commitment scheme (`native` or `sha256`)                                                                          |
| `--config-out`           | Output path for the airdrop configuration JSON. Default: `config.json`                                                          |
| `--snapshot-out-sapling` | Output path for Sapling nullifiers file. Default: `snapshot-sapling.bin`                                                        |
| `--snapshot-out-orchard` | Output path for Orchard nullifiers file. Default: `snapshot-orchard.bin`                                                        |
| `--gap-tree-out-sapling` | Output path for Sapling gap-tree file. Default: `gaptree-sapling.bin`                                                           |
| `--gap-tree-out-orchard` | Output path for Orchard gap-tree file. Default: `gaptree-orchard.bin`                                                           |
| `--no-gap-tree`          | Skip writing gap-tree files during `config build`                                                                               |

> **Important (target_id domain separation)**: Sapling and Orchard `target_id` values are domain separators for airdrop nullifier derivation in claim preparation. Sapling proving currently hardcodes its domain separator in-circuit (`ZAIRTEST`), so proving parameters/proofs must match it. Orchard proving/verification is available in this milestone with `native`/`sha256` value commitment modes and Sinsemilla gap-tree hashing.
> **For organizers**: Run this to generate the official Merkle roots and publish them along with the snapshot files.
>
> **For users**: Run this yourself to fetch the nullifiers, or download the snapshot files published by the airdrop organizers.

#### Snapshot File Format

The `.bin` snapshot files use a simple binary format:

- Each nullifier is **32 bytes** (raw binary)
- Nullifiers are concatenated sequentially with no header, delimiter, or padding
- Nullifiers must be **sorted in ascending lexicographic order**
- File size must be a multiple of 32 bytes

```console
┌──────────────────┬──────────────────┬─────┬──────────────────┐
│  Nullifier 0     │  Nullifier 1     │ ... │  Nullifier N     │
│    (32 bytes)    │    (32 bytes)    │     │    (32 bytes)    │
└──────────────────┴──────────────────┴─────┴──────────────────┘
```

### Step 2: Obtain Your Viewing Keys

To scan for your notes, you need your Unified Full Viewing Key (UFVK). If you already have your viewing key, you can skip to Step 3.

#### Viewing Key Format

The `zair` CLI expects a **Unified Full Viewing Key** in Bech32 format:

- **Mainnet**: starts with `uview1...`
- **Testnet**: starts with `uviewtest1...`

#### Helper Utility: `zair key`

If you don't have your viewing key, `zair` can derive it from your wallet's mnemonic seed phrase and write it to files:

```bash
zair key derive-seed --output seed.txt
zair key derive-ufvk --network mainnet --seed seed.txt --output ufvk.txt
```

The commands will securely prompt for:

- Your 24-word mnemonic.
- Optional passphrase (press Enter if none).

> **Security Note**: Treat `seed.txt` like a spending key (it can derive spend authority). `ufvk.txt` cannot spend funds but can reveal transaction history.

### Step 3: Users Generate Their Claims

Download the snapshot files published by the airdrop organizer, then run `claim prepare` with your viewing keys:

```bash
zair claim prepare \
  --config config.json \
  --lightwalletd https://testnet.zec.rocks:443 \
  --snapshot-sapling snapshot-sapling.bin \
  --snapshot-orchard snapshot-orchard.bin \
  --gap-tree-sapling gaptree-sapling.bin \
  --gap-tree-orchard gaptree-orchard.bin \
  --ufvk ufvk.txt \
  --birthday 3663119 \
  --claims-out claim-prepared.json
```

This command will:

1. Verify the snapshot Merkle roots match the airdrop configuration (if provided)
2. Scan the blockchain for notes belonging to your viewing keys
3. For each unspent note found, generate a non-membership proof
4. Output the prepared claim inputs to `claim-prepared.json`

**Parameters of `claim prepare` explained:**

| Parameter            | Description                                                                                                                                              |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--config`           | Airdrop configuration JSON used for expected roots and network                                                                                           |
| `--lightwalletd`     | (Optional) URL of a lightwalletd server. Defaults by config network (`mainnet` => `https://zec.rocks:443`, `testnet` => `https://testnet.zec.rocks:443`) |
| `--snapshot-sapling` | (Optional) Path to the Sapling nullifiers snapshot file. Defaults to `snapshot-sapling.bin` if Sapling is enabled in config                              |
| `--snapshot-orchard` | (Optional) Path to the Orchard nullifiers snapshot file. Defaults to `snapshot-orchard.bin` if Orchard is enabled in config                              |
| `--gap-tree-sapling` | (Optional) Path to Sapling gap-tree file. Used in `--gap-tree-mode none`/`rebuild`; ignored in `sparse` (and rejected if provided)                       |
| `--gap-tree-orchard` | (Optional) Path to Orchard gap-tree file. Used in `--gap-tree-mode none`/`rebuild`; ignored in `sparse` (and rejected if provided)                       |
| `--gap-tree-mode`    | (Optional) `none` (default, require gap-tree files), `rebuild` (recompute + rewrite from snapshots), or `sparse` (build in-memory from snapshots only)   |
| `--ufvk`             | Path to a file containing your Unified Full Viewing Key (Bech32)                                                                                         |
| `--birthday`         | Required scan start height for note discovery                                                                                                            |
| `--claims-out`       | Output file for your claim inputs                                                                                                                        |

> **Recommended**: Provide the official `--config` from the airdrop to verify your snapshot files match expected Merkle roots. This ensures generated proofs will be valid.

### Step 4: Recommended Claim Flow (`claim run`)

For most users, the recommended command is:

```bash
zair claim run \
  --config config.json \
  --seed seed.txt \
  --message claim-message.bin \
  --snapshot-sapling snapshot-sapling.bin \
  --gap-tree-sapling gaptree-sapling.bin \
  --birthday 3663119 \
  --pk setup-sapling-native-pk.params \
  --account 0 \
  --lightwalletd https://testnet.zec.rocks:443
```

`claim run` executes: `claim prepare -> claim prove -> claim sign`.

> **Important**: Download the official proving and verifying keys published by the airdrop organizer. Do not generate your own - proofs made with different keys will be rejected.
>
> **Security Note**: The seed is required to derive spending authorization. Keep it secure - it can spend your funds.

### Step 5: Advanced/Granular Claim Commands

If you need custom orchestration, run commands individually:

1. `zair claim prepare ...`
2. `zair claim prove ...`
3. `zair claim sign ...`

`claim sign` computes per-claim signatures. For each claim entry it computes:

- a per-claim proof hash (`proof_hash`)
- a per-claim message hash (`message_hash`)
- a signature digest `ZAIR_SIG_V1(version, pool, target_id_from_config, proof_hash, message_hash)`

and signs that digest with the claim's randomized spend-auth key.

You must provide message bytes for signing/verification in one of two ways:

- `--message <file>`: one shared message fallback for all claims.
- `--messages <json>`: per-claim message file assignments.

Per-claim assignments JSON format:

```json
{
  "sapling": [
    {
      "airdrop_nullifier": "<hex nullifier>",
      "message_file": "messages/sapling-1.bin"
    }
  ],
  "orchard": [
    {
      "airdrop_nullifier": "<hex nullifier>",
      "message_file": "messages/orchard-1.bin"
    }
  ]
}
```

> **Security Note**: The `secrets` file contains local proving/signing material (including `alpha` and value-commitment randomness). Keep it local and do not publish it.

### Step 6: Recommended Verification Flow (`verify run`)

For end-to-end verification:

```bash
zair verify run \
  --config config.json \
  --vk setup-sapling-native-vk.params \
  --submission-in claim-submission.json \
  --message claim-message.bin
```

`verify run` executes: `verify proof -> verify signature`.

### Step 7: Advanced/Granular Verification Commands

For separate verification stages:

1. `zair verify proof ...`
2. `zair verify signature ...`

## Privacy Properties

| Property                                         | Guaranteed |
| ------------------------------------------------ | ---------- |
| Proves you held unspent funds at snapshot height | Yes        |
| Reveals your actual nullifiers                   | No         |
| Reveals which specific notes you own             | No         |
| Requires spending or moving your funds           | No         |

## Utilities

### Generate Claim Circuit Parameters (Organizers Only)

The airdrop organizer must generate and publish the Groth16 proving and verifying keys:

```bash
zair setup sapling \
  --scheme native \
  --pk-out setup-sapling-native-pk.params \
  --vk-out setup-sapling-native-vk.params

zair setup orchard \
  --scheme native \
  --params-out setup-orchard-params.bin
```

> **Important**: Users must download and use the official keys published by the organizer. Regenerating keys locally will produce different keys that won't be accepted by the verifier.

## Environment Variables

Instead of passing arguments on the command line, you can use environment variables or a `.env` file:

| Variable                   | Description                                                                                                           |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `CONFIG_FILE`              | Airdrop configuration JSON path used by `claim` and `verify` commands                                                 |
| `CLAIMS_IN`                | Path for prepared claims JSON input                                                                                   |
| `CLAIMS_OUT`               | Path for prepared claims JSON output                                                                                  |
| `BIRTHDAY`                 | Required scan start height for claim preparation                                                                      |
| `SECRETS_IN`               | Path for local-only secrets JSON input                                                                                |
| `SECRETS_OUT`              | Path for local-only secrets JSON output                                                                               |
| `MESSAGE_FILE`             | Shared message payload fallback file used by `claim sign`/`verify signature` (required unless `MESSAGES_FILE` is set) |
| `MESSAGES_FILE`            | Per-claim message assignments JSON used by `claim sign`/`verify signature` (required unless `MESSAGE_FILE` is set)    |
| `PROOFS_IN`                | Path for proofs JSON input                                                                                            |
| `PROOFS_OUT`               | Path for proofs JSON output                                                                                           |
| `SUBMISSION_IN`            | Path for signed submission bundle JSON input                                                                          |
| `SUBMISSION_OUT`           | Path for signed submission bundle JSON output                                                                         |
| `CONFIG_OUT`               | Output path for airdrop configuration JSON                                                                            |
| `LIGHTWALLETD_URL`         | Optional lightwalletd gRPC endpoint URL override                                                                      |
| `NETWORK`                  | Network to use (`mainnet` or `testnet`)                                                                               |
| `SNAPSHOT_ORCHARD_FILE`    | Optional path to Orchard nullifiers file (defaults by enabled pool)                                                   |
| `GAP_TREE_ORCHARD_FILE`    | Optional path to Orchard gap-tree file (defaults by enabled pool)                                                     |
| `PROVING_KEY_FILE`         | Path to the Groth16 proving key file                                                                                  |
| `SNAPSHOT_SAPLING_FILE`    | Optional path to Sapling nullifiers file (defaults by enabled pool)                                                   |
| `GAP_TREE_SAPLING_FILE`    | Optional path to Sapling gap-tree file (defaults by enabled pool)                                                     |
| `SEED_FILE`                | Path to file containing 64-byte wallet seed as hex                                                                    |
| `SNAPSHOT_HEIGHT`          | Snapshot block height (inclusive)                                                                                     |
| `NO_GAP_TREE`              | If set for `config build`, skip writing `gaptree-*.bin`                                                               |
| `GAP_TREE_MODE`            | For claim prepare/run: `none` (default), `rebuild`, or `sparse`                                                       |
| `POOL`                     | Pool selection for `config build` (`sapling`, `orchard`, `both`)                                                      |
| `ACCOUNT_ID`               | ZIP-32 account index for seed-derived spend-auth keys in `claim run`/`claim prove`/`claim sign` (default: `0`)        |
| `SCHEME_SAPLING`           | Sapling value commitment scheme (`native` or `sha256`) for `config build`                                             |
| `SCHEME_ORCHARD`           | Orchard value commitment scheme (`native` or `sha256`) for `config build`                                             |
| `SNAPSHOT_OUT_SAPLING`     | Output path for Sapling snapshot nullifiers from `config build`                                                       |
| `SNAPSHOT_OUT_ORCHARD`     | Output path for Orchard snapshot nullifiers from `config build`                                                       |
| `GAP_TREE_OUT_SAPLING`     | Output path for Sapling gap-tree from `config build`                                                                  |
| `GAP_TREE_OUT_ORCHARD`     | Output path for Orchard gap-tree from `config build`                                                                  |
| `UFVK_FILE`                | Path to file containing UFVK (Bech32) for `claim prepare`                                                             |
| `ORCHARD_PARAMS_FILE`      | Path to Orchard Halo2 params file for `claim`/`verify` proof commands                                                 |
| `ORCHARD_PARAMS_MODE`      | Orchard params handling mode: `auto` or `require`                                                                     |
| `SETUP_SCHEME`             | Setup scheme for `setup sapling` / `setup orchard` (`native` or `sha256`)                                             |
| `SETUP_PK_OUT`             | Output path for proving key generated by `setup sapling`                                                              |
| `SETUP_VK_OUT`             | Output path for verifying key generated by `setup sapling`                                                            |
| `SETUP_ORCHARD_PARAMS_OUT` | Output path for params generated by `setup orchard`                                                                   |
| `TARGET_SAPLING`           | Sapling target id (must be exactly 8 bytes)                                                                           |
| `TARGET_ORCHARD`           | Orchard target id (must be at most 32 bytes)                                                                          |
| `VERIFYING_KEY_FILE`       | Path to the Groth16 verifying key file                                                                                |

## Troubleshooting

### No notes found

- Regenerate your UFVK using `zair key derive-ufvk` and confirm `--network` matches
- Ensure your `--birthday` is at or before when you first received funds
- Check that you're connected to the correct network (`mainnet` vs `testnet`)

### Pool not active at snapshot height

Ensure your snapshot height is at or after the pool activation height:

| Pool    | Network | Activation Height |
| ------- | ------- | ----------------- |
| Sapling | Mainnet | 419,200           |
| Sapling | Testnet | 280,000           |
| Orchard | Mainnet | 1,687,104         |
| Orchard | Testnet | 1,842,420         |

For example, to include Orchard notes on mainnet, your snapshot height must be at or after block 1,687,104.
