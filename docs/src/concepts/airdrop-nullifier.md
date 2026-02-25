# Concepts: Airdrop Nullifiers

To guard against airdrop _double-claims_ while keeping claims unlinkable to later Zcash shielded spends, we publish an **airdrop nullifier**: a public, deterministic, airdrop-scoped identifier derived from the note’s nullifier key material via **domain separation**.

An airdrop configuration fixes two public domain parameters:

- **targetS**: Sapling domain parameter (BLAKE2s personalization, exactly 8 bytes).
- **targetO**: Orchard domain parameter used as the _hash-to-curve domain string_ (at most 32 bytes,
  and must be valid UTF-8).

These parameters must be chosen so they do **not** coincide with the protocol domains for standard nullifiers: `Zcash_nf` (Sapling) and `z.cash:Orchard` (Orchard). See the cited specifications below.

```admonish warning
If `targetS = "Zcash_nf"` (Sapling) or `targetO = "z.cash:Orchard"` (Orchard), then the airdrop construction collapses to the standard Zcash nullifier domain for that pool, meaning the published airdrop nullifiers will match Zcash nullifiers for the same notes and **remove privacy**.
```

```admonish note
The codebase uses `targetS = "ZAIRTEST"` and `targetO = "ZAIRTEST:O"` as defaults.

- Sapling: `targetS` is compiled into the Groth16 circuit; changing it requires a new trusted setup
  and verifying key, which is required for every target deployment supporting Sapling.
- Orchard: `targetO` is baked into the circuit. Keys are re-derived deterministically per `targetO`
  at runtime (transparent setup, no ceremony).
```

## Sapling

Sapling specifies the standard nullifier PRF ([Sapling Protocol Specification](https://zips.z.cash/protocol/sapling.pdf), §5.4.2):

$$
\mathsf{PRF^{nfSapling}_{nk^\star}}(\rho^\star) =
\mathrm{BLAKE2s\text{-}256}\Big(
\texttt{"Zcash\_nf"},
\ \mathsf{LEBS2OSP_{256}}(nk^\star)\ \Vert\ \mathsf{LEBS2OSP_{256}}(\rho^\star)
\Big).
$$

The **Sapling airdrop nullifier** uses the same construction, but replaces the personalization string with the public airdrop parameter **targetS**:

$$
\mathsf{PRF^{nfSaplingAirdrop}_{nk^\star}}(\rho^\star) =
\mathrm{BLAKE2s\text{-}256}\Big(
\text{targetS},
\ \mathsf{LEBS2OSP_{256}}(nk^\star)\ \Vert\ \mathsf{LEBS2OSP_{256}}(\rho^\star)
\Big).
$$

## Orchard

Orchard specifies nullifier derivation ([Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf), §4.16):

$$
\mathsf{DeriveNullifier}_{\textsf{nk}}(\rho,\psi,\textsf{cm}) =
\mathrm{Extract}_{\mathbb{P}}\left(
\left[
\left(\mathsf{PRF^{nfOrchard}_{nk}}(\rho) + \psi\right) \bmod q_{\mathbb{P}}
\right]\cdot \mathcal{K}^{\mathrm{Orchard}} + \textsf{cm}
\right).
$$

with generator:

$$
\mathcal{K}^{\mathrm{Orchard}} := \textsf{GroupHash}^{\mathbb{P}}(\texttt{"z.cash:Orchard"},\ \texttt{K}).
$$

The **Orchard airdrop nullifier** is derived by using an airdrop-specific generator:

$$
\mathcal{K}^{\mathrm{OrchardAirdrop}} := \textsf{GroupHash}^{\mathbb{P}}(\text{targetO},\ \texttt{K}),
$$

and then computing $\mathsf{DeriveNullifier}$ as specified, but replacing $\mathcal{K}^{\mathrm{Orchard}}$ with $\mathcal{K}^{\mathrm{OrchardAirdrop}}$.
