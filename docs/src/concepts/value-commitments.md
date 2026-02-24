# Concepts: Value Commitments

This page gives the formal definitions used by ZAIR value commitments.

## Native scheme

When the configured value-commitment scheme is `native`, each pool exposes its native Zcash value commitment, see the [references](../appendix/references.md) and Zcash specification for details:

- **Sapling**:
  $
  \mathsf{cv}_{\mathsf{Sapling}} := \mathsf{ValueCommit}^{\mathsf{Sapling}}_{\mathsf{rcv}}(value).
  $
- **Orchard**:
  $
  \mathsf{cv}_{\mathsf{Orchard}} := \mathsf{ValueCommit}^{\mathsf{Orchard}}_{\mathsf{rcv}}(value).
  $

Here `rcv` is the randomness used by the pool-native commitment scheme.

## SHA-256 scheme

When the configured value-commitment scheme is `sha256`, both Sapling and Orchard use:

$$
\mathsf{cv\_sha256} :=
\mathrm{SHA256}\big(\texttt{"Zair"} \ \Vert\ \mathsf{LE64}(v)\ \Vert\ \mathsf{rcv\_sha256}\big).
$$

Here `rcv_sha256` is the randomness used by the SHA-256 commitment scheme, and $\mathsf{LE64}(v)$ is the value as 8 little endian bytes, and the prefix `"Zair"` is a fixed 4-byte ASCII domain-separation tag.
