# Airdrop nullifiers

Airdrop nullifiers are described [here](https://forum.zcashcommunity.com/t/status-update-rfc-zec-nam-shielded-airdrop-protocol/49144#p-220713-airdrop-nullifier-7)

## Sapling

In forumn is written as LESBS2OP, but the correct is LEBS2OSP
Reference: Zcash protocol.pdf section 5.4.1.5

$$
\mathsf{PRF^{nfSAir}\_{nk^\star}}(\rho^\star) =
\mathrm{BLAKE2s\text{-}256}(\text{"MASP\\\_alt"}, \mathsf{LEBS2OSP\_{256}(nk^\star)} \Vert
\mathsf{LEBS2OSP\_{256}(\rho^\star)})$$ $$\mathsf{nf\_{Air}^{Sapling}} =
\mathsf{PRF^{nfSAir}\_{nk^\star}}(\rho^\star)$$ $$ = \mathsf{DeriveAirdropNullifier^{Sapling}\
_{nk}}(\rho)
$$

## Orchard

$$
\mathcal{K}^{\mathrm{Airdrop}} := \mathrm{GroupHash}^{\mathbb{P}}(\text{"MASP:Airdrop"},
\text{"K"})
$$

$$\mathsf{PRF^{nfOAir}\_{nk}}(\rho) = \mathrm{PoseidonHash}(nk, \rho)$$

$$
\mathsf{nf\_{Air}^{Orchard}} =
\mathrm{Extract}\_{\mathbb{P}}\left(\big([\mathsf{PRF^{nfOAir}\_{nk}}(\rho) + \psi] \bmod q\big)
\cdot \mathbb{P} \Vert (\mathcal{K}^{\mathrm{Airdrop}} + cm)\right)
$$

$$= \mathsf{DeriveAirdropNullifier^{Orchard}\_{nk}}(\rho, \psi, cm)$$
