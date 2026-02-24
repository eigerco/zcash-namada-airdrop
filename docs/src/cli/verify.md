# `zair verify`

Commands to verify a `proof` or `signature`; or `run` the verification for both.

## `zair verify run`

End-to-end verification: verify proofs and signatures.

```bash
zair verify run \
  --config config.json \
  --submission-in claim-submission.json \
  --message claim-message.bin
```

```admonish note
Verification does not require the `prove` feature and is lighter for target-chain integration.
```

## `zair verify proof`

Verifies the ZK proofs in a proofs file against the airdrop configuration.

```bash
zair verify proof \
  --config config.json \
  --proofs-in claim-proofs.json
```

## `zair verify signature`

Verifies spend-authorizing signatures in a signed claim submission.

```bash
zair verify signature \
  --config config.json \
  --submission-in claim-submission.json \
  --message claim-message.bin
```
