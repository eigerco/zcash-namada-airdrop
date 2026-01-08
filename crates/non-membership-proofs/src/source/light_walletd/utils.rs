use tracing::warn;
use zcash_client_backend::proto::compact_formats::CompactTx;
use zcash_protocol::TxId;

pub mod retry;
pub mod sapling_positions;

/// Extracts txid from a block's transaction list, falling back to NULL if index is invalid.
pub fn get_txid_or_null(vtx: &[CompactTx], tx_index: usize) -> TxId {
    vtx.get(tx_index).map_or_else(
        || {
            warn!(tx_index, "tx_index out of bounds, using NULL txid");
            TxId::NULL
        },
        CompactTx::txid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_indices() {
        let vtx = vec![
            CompactTx {
                hash: vec![1_u8; 32],
                ..Default::default()
            },
            CompactTx {
                hash: vec![2_u8; 32],
                ..Default::default()
            },
            CompactTx {
                hash: vec![3_u8; 32],
                ..Default::default()
            },
        ];

        for i in 0..vtx.len() {
            assert_ne!(get_txid_or_null(&vtx, i), TxId::NULL);
        }
    }

    #[test]
    fn invalid_indices_return_null() {
        let vtx = vec![CompactTx {
            hash: vec![1_u8; 32],
            ..Default::default()
        }];

        assert_eq!(get_txid_or_null(&vtx, 5), TxId::NULL);
        assert_eq!(get_txid_or_null(&[], 0), TxId::NULL);
    }
}
