# Usage Guide

> **Work in Progress**: This project is under active development. Not all features described in this guide are fully implemented yet, and some details may change.

This guide walks you through the complete workflow for:

1. **Airdrop organizers**: Building an airdrop snapshot configuration from Zcash blockchain data
2. **Users**: Claiming an airdrop using privacy-preserving non-membership proofs

## Overview

**As a Zcash user** with shielded funds (Sapling or Orchard notes) who wants to participate in the Namada airdrop, **you need to prove** that you held unspent funds at a specific blockchain height **without revealing your actual nullifiers** (which would compromise your privacy).

### The Problem

Zcash's shielded pools use nullifiers to track spent notes. When you spend a note, its nullifier gets published to the blockchain. To prove you had unspent funds at the airdrop snapshot, you'd normally need to show your nullifier isn't in the set of spent nullifiers—but revealing your nullifier would link your note to your identity.

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

In the CLI, `prove` and `setup-local` are only available when `prove` is enabled.

## Workflow

### Step 1: Build the Airdrop Snapshot

Run `build-config` to:

1. Fetch all nullifiers from the blockchain up to the snapshot height
2. Build Merkle trees for Sapling and Orchard pools
3. Export snapshot files and a configuration JSON with Merkle roots

```bash
zair build-config \
  --snapshot-height 3743871 \
  --network testnet \
  --pool both \
  --lightwalletd-url https://testnet.zec.rocks:443 \
  --sapling-target-id ZAIRTEST \
  --orchard-target-id ZAIRTEST:Orchard \
  --configuration-output-file airdrop_configuration.json \
  --sapling-snapshot-nullifiers sapling-nullifiers-testnet.bin \
  --orchard-snapshot-nullifiers orchard-nullifiers-testnet.bin
```

This produces:

- `airdrop_configuration.json` — Contains Merkle roots for verification
- `sapling-nullifiers-testnet.bin` — Sapling pool snapshot nullifiers
- `orchard-nullifiers-testnet.bin` — Orchard pool snapshot nullifiers

**Parameters of `build-config` explained:**

| Parameter                       | Description                                                                                                                     |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `--network`                     | Network to use (`mainnet` or `testnet`). Default: `mainnet`                                                                     |
| `--snapshot-height`             | Snapshot block height (inclusive)                                                                                               |
| `--pool`                        | Pool selection: `sapling`, `orchard`, or `both` (default)                                                                       |
| `--lightwalletd-url`            | (Optional) URL of a lightwalletd server. Defaults: `https://zec.rocks:443` (mainnet), `https://testnet.zec.rocks:443` (testnet) |
| `--sapling-target-id`           | Sapling target id for hiding nullifier derivation (must be exactly 8 bytes)                                                     |
| `--orchard-target-id`           | Orchard target id for hiding nullifier derivation (must be <= 32 bytes)                                                         |
| `--configuration-output-file`   | Output path for the airdrop configuration JSON. Default: `airdrop_configuration.json`                                           |
| `--sapling-snapshot-nullifiers` | Output path for Sapling nullifiers file. Default: `sapling-snapshot-nullifiers.bin`                                             |
| `--orchard-snapshot-nullifiers` | Output path for Orchard nullifiers file. Default: `orchard-snapshot-nullifiers.bin`                                             |

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

#### Helper Utility: `mnemonic-to-fvks`

If you don't have your viewing key, the `mnemonic-to-fvks` utility can derive it from your wallet's mnemonic seed phrase:

```bash
mnemonic-to-fvks --network mainnet
```

**Parameters of `mnemonic-to-fvks` explained:**

| Parameter   | Description                                                 |
| ----------- | ----------------------------------------------------------- |
| `--network` | Network to use (`mainnet` or `testnet`). Default: `mainnet` |

The tool will securely prompt for:

- Your 24-word mnemonic
- Optional passphrase (press Enter if none)
- Account index (default: 0)

It outputs:

1. **Unified Full Viewing Key** — Human-readable Bech32 format (use this with `--unified-full-viewing-key`)
2. **Individual keys** — Hex-encoded Orchard and Sapling FVKs (for debugging/advanced use)

> **Security Note**: Keep your mnemonic secure. The viewing keys cannot spend funds but can reveal your transaction history.

### Step 3: Users Generate Their Claims

Download the snapshot files published by the airdrop organizer, then run `claim-prepare` with your viewing keys:

```bash
zair claim-prepare \
  --lightwalletd-url https://testnet.zec.rocks:443 \
  --sapling-snapshot-nullifiers sapling-nullifiers-testnet.bin \
  --orchard-snapshot-nullifiers orchard-nullifiers-testnet.bin \
  --unified-full-viewing-key  uviewtest1kfhkx5fphx2ahhnpsme4sqsvx04nzuryd6vhd79rs2uv7x23gvtzlfvjq0r705kucmqcl9yf50nglmsn60c0chd8x94lnfa6s46fhdpvlv9lc33l76j32t62ucl0l70yxh2r77nqunawcxexjcg8gldmepqc9nufnn386ftas9xjalcrl3y8jycgtq6xq8lrvqm47hhrsqjcrm8e8pv7u595ma8dzdnps83fwspsvadz4dztsw8e9lwsvphzfglx0zxy32jyl7xcxhxnzw0lp5kzcpzjvwwwh3l80g9vdn7gfaj6927sg8m57gpafvj0wgu3upjdj63mxvxwd8qezcnvzlsd938dfaujm0usgz93gkk4cm60ejrj8zfckse2w7gaf8cj0n6k5 \
  --birthday-height 3663119 \
  --airdrop-claims-output-file airdrop_claims.json \
  --airdrop-configuration-file airdrop_configuration.json
```

This command will:

1. Verify the snapshot Merkle roots match the airdrop configuration (if provided)
2. Scan the blockchain for notes belonging to your viewing keys
3. For each unspent note found, generate a non-membership proof
4. Output the proofs to `airdrop_claims.json`

**Parameters of `claim-prepare` explained:**

| Parameter                       | Description                                                                                                                                              |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--lightwalletd-url`            | (Optional) URL of a lightwalletd server. Defaults by config network (`mainnet` => `https://zec.rocks:443`, `testnet` => `https://testnet.zec.rocks:443`) |
| `--sapling-snapshot-nullifiers` | Path to the Sapling nullifiers snapshot file                                                                                                             |
| `--orchard-snapshot-nullifiers` | Path to the Orchard nullifiers snapshot file                                                                                                             |
| `--unified-full-viewing-key`    | Your Unified Full Viewing Key in Bech32 format                                                                                                           |
| `--birthday-height`             | The block height when your wallet was created (optimization)                                                                                             |
| `--airdrop-claims-output-file`  | Output file for your claim inputs                                                                                                                        |
| `--airdrop-configuration-file`  | (Optional) Airdrop configuration JSON to verify Merkle roots                                                                                             |

> **Recommended**: Provide the `--airdrop-configuration-file` from the official airdrop to verify your snapshot files match the expected Merkle roots. This ensures your generated proofs will be valid.

### Step 4: Generate Claim Proofs

The `claim-prepare` command outputs claim inputs (note data + non-membership proofs). To create the final ZK proofs that can be submitted on-chain, use `prove`:

```bash
zair prove \
  --claim-inputs-file airdrop_claims.json \
  --proofs-output-file airdrop_claim_proofs.json \
  --seed-file seed.txt \
  --network testnet \
  --proving-key-file claim_proving_key.params
```

The seed file should contain your 64-byte wallet seed as hex.

This command will:

1. Load the claim inputs from the previous step
2. Derive Sapling spending keys from your seed
3. Generate Groth16 ZK proofs for each claim (in parallel)
4. Verify each proof before including it in the output
5. Output the proofs to `airdrop_claim_proofs.json`

**Parameters of `prove` explained:**

| Parameter              | Description                                                            |
| ---------------------- | ---------------------------------------------------------------------- |
| `--claim-inputs-file`  | Path to claim inputs JSON (output of `claim-prepare`)                  |
| `--proofs-output-file` | Output path for generated proofs. Default: `airdrop_claim_proofs.json` |
| `--seed-file`          | Path to file containing your 64-byte wallet seed as hex                |
| `--network`            | Network to use (`mainnet` or `testnet`). Default: `mainnet`            |
| `--proving-key-file`   | Path to proving key. Default: `claim_proving_key.params`               |

> **Important**: Download the official proving and verifying keys published by the airdrop organizer. Do not generate your own—proofs made with different keys will be rejected.
>
> **Security Note**: The seed is required to derive spending authorization. Keep it secure—it can spend your funds.

### Step 5: Verify Proofs (Optional)

To independently verify generated proofs:

```bash
zair verify \
  --proofs-file airdrop_claim_proofs.json \
  --verifying-key-file claim_verifying_key.params
```

This is a sanity check to ensure the generated proofs are valid before submission.

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
zair setup-local \
  --proving-key-file claim_proving_key.params \
  --verifying-key-file claim_verifying_key.params
```

> **Important**: Users must download and use the official keys published by the organizer. Regenerating keys locally will produce different keys that won't be accepted by the verifier.

### View Configuration Schema

To view the JSON schema for the airdrop configuration file:

```bash
zair config-schema
```

This prints the JSON schema describing the structure of the airdrop configuration file that is produced from `build-config` subcommand.

## Environment Variables

Instead of passing arguments on the command line, you can use environment variables or a `.env` file:

| Variable                      | Description                                                        |
| ----------------------------- | ------------------------------------------------------------------ |
| `AIRDROP_CLAIMS_FILE`         | Path for claims JSON (output of `claim-prepare`, input to `prove`) |
| `BIRTHDAY_HEIGHT`             | Birthday height for the provided viewing keys                      |
| `CLAIM_PROOFS_FILE`           | Path for proofs JSON (output of `prove`, input to `verify`)        |
| `CONFIGURATION_OUTPUT_FILE`   | Output path for airdrop configuration JSON                         |
| `LIGHTWALLETD_URL`            | Optional lightwalletd gRPC endpoint URL override                   |
| `NETWORK`                     | Network to use (`mainnet` or `testnet`)                            |
| `ORCHARD_SNAPSHOT_NULLIFIERS` | Path to Orchard nullifiers file                                    |
| `PROVING_KEY_FILE`            | Path to the Groth16 proving key file                               |
| `SAPLING_SNAPSHOT_NULLIFIERS` | Path to Sapling nullifiers file                                    |
| `SEED_FILE`                   | Path to file containing 64-byte wallet seed as hex                 |
| `SNAPSHOT_HEIGHT`             | Snapshot block height (inclusive)                                  |
| `POOL`                        | Pool selection for build-config (`sapling`, `orchard`, `both`)     |
| `SAPLING_TARGET_ID`           | Sapling target id (must be exactly 8 bytes)                        |
| `ORCHARD_TARGET_ID`           | Orchard target id (must be at most 32 bytes)                       |
| `VERIFYING_KEY_FILE`          | Path to the Groth16 verifying key file                             |

## Troubleshooting

### No notes found

- Verify your FVKs are correct using `mnemonic-to-fvks`
- Ensure your `--birthday-height` is at or before when you first received funds
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
