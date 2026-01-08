use crate::source::light_walletd::error::LightWalletdError;

/// Information about Sapling output positions within a block
pub struct SaplingPositionInfo {
    /// Starting position index for each transaction's Sapling outputs.
    /// `tx_start_positions[i]` is the cumulative count of outputs in transactions 0..i
    pub tx_start_positions: Vec<u32>,
    /// The Sapling commitment tree size at the start of the block
    pub tree_size_start: u32,
}

/// Calculates Sapling output position information for a block.
///
/// # Arguments
/// * `block_height` - The height of the block (used for error messages)
/// * `sapling_tree_size_end` - The Sapling tree size at the end of the block (from chain metadata)
/// * `output_counts` - Number of Sapling outputs in each transaction
///
/// # Returns
/// Position information needed to calculate global tree positions for each output
///
/// # Errors
/// - `MissingChainMetadata` if there are outputs but no tree size provided
/// - `OverflowError` if cumulative counts overflow u32
pub fn calculate_sapling_positions(
    block_height: u64,
    sapling_tree_size_end: Option<u32>,
    output_counts: &[usize],
) -> Result<SaplingPositionInfo, LightWalletdError> {
    let mut tx_start_positions = Vec::with_capacity(output_counts.len());
    let mut cumulative = 0_u32;

    for &count in output_counts {
        tx_start_positions.push(cumulative);
        cumulative = cumulative
            .checked_add(u32::try_from(count)?)
            .ok_or(LightWalletdError::OverflowError)?;
    }

    let tree_size_start = if cumulative > 0 {
        let tree_size_end = sapling_tree_size_end
            .ok_or(LightWalletdError::MissingChainMetadata { block_height })?;

        tree_size_end
            .checked_sub(cumulative)
            .ok_or(LightWalletdError::OverflowError)?
    } else {
        0
    };

    Ok(SaplingPositionInfo {
        tx_start_positions,
        tree_size_start,
    })
}

/// Calculates the global position for a Sapling note in the commitment tree.
pub fn calculate_note_position(
    sapling_info: &SaplingPositionInfo,
    tx_index: usize,
    output_index: usize,
) -> Result<u64, LightWalletdError> {
    let tx_start =
        sapling_info
            .tx_start_positions
            .get(tx_index)
            .ok_or(LightWalletdError::IndexError {
                index: tx_index,
                length: sapling_info.tx_start_positions.len(),
            })?;

    let position = sapling_info
        .tree_size_start
        .checked_add(*tx_start)
        .and_then(|v| v.checked_add(u32::try_from(output_index).ok()?))
        .ok_or(LightWalletdError::OverflowError)?;

    Ok(u64::from(position))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "Tests")]

    use super::*;

    #[test]
    fn empty_block() {
        let result = calculate_sapling_positions(100, None, &[]).unwrap();
        assert!(result.tx_start_positions.is_empty());
        assert_eq!(result.tree_size_start, 0);
    }

    #[test]
    fn no_outputs_no_metadata() {
        let result = calculate_sapling_positions(100, None, &[0, 0, 0]).unwrap();
        assert_eq!(result.tx_start_positions, vec![0, 0, 0]);
        assert_eq!(result.tree_size_start, 0);
    }

    #[test]
    fn with_outputs_and_metadata() {
        // 3 txs with 2, 3, 1 outputs = 6 total
        // tree_size_end = 1000, so tree_size_start = 1000 - 6 = 994
        let result = calculate_sapling_positions(100, Some(1000), &[2, 3, 1]).unwrap();
        assert_eq!(result.tx_start_positions, vec![0, 2, 5]);
        assert_eq!(result.tree_size_start, 994);
    }

    #[test]
    fn missing_metadata_with_outputs() {
        let result = calculate_sapling_positions(100, None, &[1, 2]);
        assert!(matches!(
            result,
            Err(LightWalletdError::MissingChainMetadata { block_height: 100 })
        ));
    }

    #[test]
    fn overflow_errors() {
        // tree_size_end = 5, but we have 10 outputs (underflow)
        assert!(matches!(
            calculate_sapling_positions(100, Some(5), &[10]),
            Err(LightWalletdError::OverflowError)
        ));

        // Cumulative overflow
        assert!(calculate_sapling_positions(100, Some(u32::MAX), &[usize::MAX, 1]).is_err());

        // tree_size_end exactly equals cumulative (edge case - should work)
        let result = calculate_sapling_positions(100, Some(10), &[5, 5]).unwrap();
        assert_eq!(result.tree_size_start, 0);
    }

    #[test]
    fn valid_positions() {
        // Single tx
        let result = calculate_sapling_positions(100, Some(50), &[10]).unwrap();
        assert_eq!(result.tx_start_positions, vec![0]);
        assert_eq!(result.tree_size_start, 40);

        // Many txs: 1+2+3+...+10 = 55 total
        let counts: Vec<usize> = (1..=10).collect();
        let result = calculate_sapling_positions(100, Some(1000), &counts).unwrap();
        assert_eq!(result.tx_start_positions.len(), 10);
        assert_eq!(result.tx_start_positions[0], 0);
        assert_eq!(result.tx_start_positions[1], 1);
        assert_eq!(result.tx_start_positions[2], 3);
        assert_eq!(result.tree_size_start, 945);
    }

    mod calculate_note_position_tests {
        use super::*;

        #[test]
        fn position_calculations() {
            let info = SaplingPositionInfo {
                tx_start_positions: vec![0, 5, 8],
                tree_size_start: 1000,
            };

            // tx 0, output 0: 1000 + 0 + 0 = 1000
            assert_eq!(calculate_note_position(&info, 0, 0).unwrap(), 1000);
            // tx 0, output 2: 1000 + 0 + 2 = 1002
            assert_eq!(calculate_note_position(&info, 0, 2).unwrap(), 1002);
            // tx 1, output 0: 1000 + 5 + 0 = 1005
            assert_eq!(calculate_note_position(&info, 1, 0).unwrap(), 1005);
            // tx 1, output 1: 1000 + 5 + 1 = 1006
            assert_eq!(calculate_note_position(&info, 1, 1).unwrap(), 1006);
            // tx 2, output 2: 1000 + 8 + 2 = 1010
            assert_eq!(calculate_note_position(&info, 2, 2).unwrap(), 1010);
        }

        #[test]
        fn zero_tree_size() {
            let info = SaplingPositionInfo {
                tx_start_positions: vec![0, 5],
                tree_size_start: 0,
            };
            assert_eq!(calculate_note_position(&info, 1, 3).unwrap(), 8);
        }

        #[test]
        fn errors() {
            // Index out of bounds
            let info = SaplingPositionInfo {
                tx_start_positions: vec![0, 5],
                tree_size_start: 1000,
            };
            assert!(matches!(
                calculate_note_position(&info, 5, 0),
                Err(LightWalletdError::IndexError {
                    index: 5,
                    length: 2
                })
            ));

            // Empty tx_start_positions
            let info = SaplingPositionInfo {
                tx_start_positions: vec![],
                tree_size_start: 1000,
            };
            assert!(matches!(
                calculate_note_position(&info, 0, 0),
                Err(LightWalletdError::IndexError {
                    index: 0,
                    length: 0
                })
            ));

            // Overflow from output_index
            let info = SaplingPositionInfo {
                tx_start_positions: vec![0],
                tree_size_start: u32::MAX,
            };
            assert!(matches!(
                calculate_note_position(&info, 0, 1),
                Err(LightWalletdError::OverflowError)
            ));

            // Overflow from tx_start + tree_size
            let info = SaplingPositionInfo {
                tx_start_positions: vec![u32::MAX - 1],
                tree_size_start: 2,
            };
            assert!(matches!(
                calculate_note_position(&info, 0, 0),
                Err(LightWalletdError::OverflowError)
            ));

            // Large output_index conversion fails (64-bit only)
            #[cfg(target_pointer_width = "64")]
            {
                let info = SaplingPositionInfo {
                    tx_start_positions: vec![0],
                    tree_size_start: 0,
                };
                assert!(matches!(
                    calculate_note_position(&info, 0, usize::MAX),
                    Err(LightWalletdError::OverflowError)
                ));
            }
        }
    }
}
