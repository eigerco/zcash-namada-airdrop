# `zair setup`

Generate proving and verifying parameters.

## `zair setup sapling`

Generates Sapling Groth16 proving and verifying keys for the claim circuit.

```bash
zair setup sapling --scheme native
```

This outputs `setup-sapling-pk.params` and `setup-sapling-vk.params`.

```admonish note
The circuit scheme must match config scheme used by `config build --scheme-sapling xxx`). Mismatched schemes will cause proof verification to fail.
```

## `zair setup orchard`

Generates Orchard Halo2 parameters for proving and verification.

```bash
zair setup orchard --scheme native
```

This outputs `setup-orchard-params.bin`, as above, circuit scheme must match config.

```admonish note
Orchard parameters can also be generated automatically during proving when `--orchard-params-mode auto` is set (default). Pre-generating can be useful for sharing or save computation.
```
