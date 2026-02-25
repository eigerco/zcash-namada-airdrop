# `zair claim`

Commands to `prepare`, `prove`, and `sign` airdrop claims; or `run` the full pipeline.

## `zair claim run`

End-to-end claim pipeline: prepare, prove and sign.

```bash
zair claim run \
  --config config.json \
  --seed seed.txt \
  --birthday 3663119 \
  --message claim-message.bin
```

## `zair claim prepare`

Scans the chain with a UFVK, finds eligible notes, and constructs the private witness material needed for proving. Does **not** require spending keys and can be outsourced to anyone with the viewing key.

```bash
zair claim prepare \
  --config config.json \
  --ufvk ufvk.txt \
  --birthday 3663119
```

## `zair claim prove`

Generates one ZK proof per eligible note using the seed to derive spending keys.

```bash
zair claim prove \
  --config config.json \
  --seed seed.txt
```

```admonish note
The `--account` index must match the one used to derive the UFVK in `zair key derive-ufvk`.
```

## `zair claim sign`

Signs the generated proofs with spend-authorizing keys, binding each claim to a message payload.

```bash
zair claim sign \
  --config config.json \
  --seed seed.txt \
  --message claim-message.bin
```

```admonish note
The `prove` and `run` subcommands require the `prove` feature (enabled by default). The `prepare` and `sign` subcommands are always available.
```
