# CLI Reference

The `zair` CLI is organized into five command groups that mirror the airdrop pipeline:

| Command group           | Role      | Purpose                                      |
| ----------------------- | --------- | -------------------------------------------- |
| [`key`](./key.md)       | Anyone    | Derive seed and viewing keys from a mnemonic |
| [`setup`](./setup.md)   | Organizer | Generate proving/verifying parameters        |
| [`config`](./config.md) | Organizer | Build snapshot configuration from chain data |
| [`claim`](./claim.md)   | Prover    | Prepare, prove, and sign airdrop claims      |
| [`verify`](./verify.md) | Verifier  | Verify proofs and signatures                 |

## Step-by-step Guide

Below is a step-by-step guide for the full workflow:

### 0. Prerequisites

You need to have [built the CLI tool](../getting-started/index.md), and a Zcash testnet wallet with shielded funds confirmed before or at the snapshot height. Use any Zcash wallet (e.g. `zcash-cli` or `zingo-cli`) to:

1. Generate a new testnet account and export the mnemonic and birthday height.
2. Obtain test notes from a faucet, for example [testnet.zecfaucet.com](https://testnet.zecfaucet.com).
3. Obtain a few shielded Sapling or Orchard notes (or both).
4. Wait for confirmation and note the confirmation height.

The tools will need the wallet `birthday` and the wallet `mnemonic` (with optional passphrase). For generating a snapshot, you need a snapshot `height` after the confirmed note height e.g. current.

### 1. Derive keys

Extract the seed from your mnemonic (**sensitive!**):

```bash
zair key derive-seed --mnemonic-file mnemonic.txt --no-passphrase
```

### 2. Generate parameters

Generate the trusted Sapling setup (required once per scheme):

```bash
zair setup sapling
```

Orchard setup is generated automatically during proving, but you may precompute it:

```bash
zair setup orchard
```

### 3. Build configuration

Build the airdrop snapshot configuration against a testnet height:

```bash
zair config build \
  --network testnet \
  --height <SNAPSHOT_HEIGHT>
```

This produces `config.json`, snapshot files, and gap-tree files.

### 4. Claim

Run the full claim pipeline (prepare, prove, sign) in one step:

```bash
zair claim run \
  --config config.json \
  --seed seed.txt \
  --birthday <WALLET_BIRTHDAY> \
  --message claim-message.bin
```

This produces:

- `claim-prepared.json`: prepared proof inputs (**sensitive!**)
- `claim-proofs.json`: generated proofs and public outputs
- `claim-proofs-secrets.json`: local-only secrets (**sensitive!**)
- `claim-submission.json`: signed submission for the target chain

### 5. Verify

Run the full verification pipeline to verify the submission (proofs + signatures):

```bash
zair verify run \
  --config config.json \
  --message claim-message.bin
```

The individual steps (`claim prepare`, `claim prove`, `claim sign`, `verify proof`, `verify signature`) can also be run separately. See their respective reference pages for details.
