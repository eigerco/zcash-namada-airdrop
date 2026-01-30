//! Circuit gadgets for the Claim circuit.
//!
//! This module contains reusable gadgets for common circuit operations.

// ZK proof code requires patterns that trigger these lints.

use bellman::gadgets::boolean::Boolean;
use bellman::{ConstraintSystem, SynthesisError};

/// Computes the OR of two booleans: `a OR b = NOT(NOT(a) AND NOT(b))`
///
/// Since bellman doesn't provide `Boolean::or`, we implement it using De Morgan's law.
fn boolean_or<CS: ConstraintSystem<bls12_381::Scalar>>(
    cs: CS,
    a: &Boolean,
    b: &Boolean,
) -> Result<Boolean, SynthesisError> {
    // a OR b = NOT(NOT(a) AND NOT(b))
    let not_a_and_not_b = Boolean::and(cs, &a.not(), &b.not())?;
    Ok(not_a_and_not_b.not())
}

/// Enforces that `a < b` using lexicographic (big-endian byte) ordering.
///
/// This gadget computes a "less than" comparison by iterating through bytes
/// from byte 0 (most significant) to byte 31 (least significant), comparing
/// the MSB of each byte first.
///
/// # Algorithm
/// For each byte from 0 to 31, for each bit from 7 (MSB) to 0 (LSB):
/// - If `a[i] = 0` and `b[i] = 1` and all higher bits were equal, then `a < b`
/// - If `a[i] = 1` and `b[i] = 0` and all higher bits were equal, then `a > b`
/// - If bits are equal, continue to next bit
///
/// This matches the byte-by-byte comparison used by sorted data structures.
///
/// # Arguments
/// * `cs` - The constraint system
/// * `a_bits` - Little-endian bit representation of `a` (256 bits, byte 0 at bits[0..8])
/// * `b_bits` - Little-endian bit representation of `b` (256 bits, byte 0 at bits[0..8])
///
/// # Panics
/// Panics if the bit arrays are not exactly 256 bits.
///
/// # Errors
/// Returns `SynthesisError` if constraint synthesis fails.
#[allow(clippy::indexing_slicing, reason = "asserts ensure exactly 256 bits")]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "byte_idx in 0..32, bit_in_byte in 0..8, max index 255"
)]
pub fn enforce_less_than<CS: ConstraintSystem<bls12_381::Scalar>>(
    mut cs: CS,
    a_bits: &[Boolean],
    b_bits: &[Boolean],
) -> Result<(), SynthesisError> {
    assert_eq!(a_bits.len(), 256, "a_bits must be 256 bits");
    assert_eq!(b_bits.len(), 256, "b_bits must be 256 bits");

    // We iterate in lexicographic order:
    // - Byte 0 is most significant (compared first)
    // - Within each byte, bit 7 is MSB (compared first)
    // lt tracks: have we determined a < b?
    // eq tracks: are all bits from start to current position equal?

    // Start with lt = 0 (not yet determined less than)
    // Start with eq = 1 (trivially equal at position beyond start)
    let mut lt = Boolean::constant(false);
    let mut eq = Boolean::constant(true);

    for byte_idx in 0..32 {
        for bit_in_byte in (0..8).rev() {
            let i = byte_idx * 8 + bit_in_byte;
            let mut cs = cs.namespace(|| format!("bit {i}"));

            let a = &a_bits[i];
            let b = &b_bits[i];

            // a == b  <=>  !(a xor b)
            let a_xor_b = Boolean::xor(cs.namespace(|| "a_xor_b"), a, b)?;
            let a_eq_b = a_xor_b.not();

            // a < b at this bit  <=>  (!a) & b
            let nota_and_b = Boolean::and(cs.namespace(|| "nota_and_b"), &a.not(), b)?;

            // eq_and_lt = eq & ((!a) & b)
            let eq_and_lt = Boolean::and(cs.namespace(|| "eq_and_lt"), &eq, &nota_and_b)?;

            // lt = lt | eq_and_lt
            lt = boolean_or(cs.namespace(|| "lt_or"), &lt, &eq_and_lt)?;

            // eq = eq & (a == b)
            eq = Boolean::and(cs.namespace(|| "eq_and"), &eq, &a_eq_b)?;
        }
    }

    // let mut constraint_idx = 0;

    // After processing all bits:
    // - If lt = 1, then a < b
    // - If lt = 0 and eq = 1, then a = b
    // - If lt = 0 and eq = 0, then a > b
    //
    // We want to enforce a < b, so we constrain lt = 1
    Boolean::enforce_equal(
        cs.namespace(|| "enforce a < b"),
        &lt,
        &Boolean::constant(true),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::arithmetic_side_effects,
        reason = "unit-test"
    )]

    use bellman::gadgets::boolean::AllocatedBit;
    use bellman::gadgets::test::TestConstraintSystem;

    use super::*;

    /// Helper to allocate a 256-bit value as little-endian boolean array
    fn alloc_bits<CS: ConstraintSystem<bls12_381::Scalar>>(
        mut cs: CS,
        value: &[u8; 32],
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let mut bits = Vec::with_capacity(256);
        for (byte_idx, byte) in value.iter().enumerate() {
            for bit_idx in 0..8 {
                let bit = Boolean::from(AllocatedBit::alloc(
                    cs.namespace(|| format!("bit {}", byte_idx * 8 + bit_idx)),
                    Some((byte >> bit_idx) & 1 == 1),
                )?);
                bits.push(bit);
            }
        }
        Ok(bits)
    }

    #[test]
    fn test_less_than_simple() {
        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

        // a = 5, b = 10 (a < b should succeed)
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 5;
        b_bytes[0] = 10;

        let a_bits = alloc_bits(cs.namespace(|| "a"), &a_bytes).unwrap();
        let b_bits = alloc_bits(cs.namespace(|| "b"), &b_bytes).unwrap();

        enforce_less_than(cs.namespace(|| "a < b"), &a_bits, &b_bits).unwrap();

        assert!(cs.is_satisfied(), "5 < 10 should be satisfied");
    }

    #[test]
    fn test_less_than_fails_when_equal() {
        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

        // a = 42, b = 42 (a < b should fail)
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 42;
        b_bytes[0] = 42;

        let a_bits = alloc_bits(cs.namespace(|| "a"), &a_bytes).unwrap();
        let b_bits = alloc_bits(cs.namespace(|| "b"), &b_bytes).unwrap();

        enforce_less_than(cs.namespace(|| "a < b"), &a_bits, &b_bits).unwrap();

        assert!(!cs.is_satisfied(), "42 < 42 should NOT be satisfied");
    }

    #[test]
    fn test_less_than_fails_when_greater() {
        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

        // a = 100, b = 50 (a < b should fail)
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 100;
        b_bytes[0] = 50;

        let a_bits = alloc_bits(cs.namespace(|| "a"), &a_bytes).unwrap();
        let b_bits = alloc_bits(cs.namespace(|| "b"), &b_bytes).unwrap();

        enforce_less_than(cs.namespace(|| "a < b"), &a_bits, &b_bits).unwrap();

        assert!(!cs.is_satisfied(), "100 < 50 should NOT be satisfied");
    }

    #[test]
    fn test_less_than_lexicographic_byte0_decides() {
        // Test that byte 0 (most significant in lexicographic order) determines the result
        // even when byte 31 would give the opposite result in little-endian integer order
        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

        // a: byte 0 = 0x01, byte 31 = 0xFF
        // b: byte 0 = 0xFF, byte 31 = 0x00
        // Lexicographic: a < b (0x01 < 0xFF at byte 0)
        // Little-endian integer: a > b (byte 31 is MSB, 0xFF > 0x00)
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 0x01;
        a_bytes[31] = 0xFF;
        b_bytes[0] = 0xFF;
        b_bytes[31] = 0x00;

        let a_bits = alloc_bits(cs.namespace(|| "a"), &a_bytes).unwrap();
        let b_bits = alloc_bits(cs.namespace(|| "b"), &b_bytes).unwrap();

        enforce_less_than(cs.namespace(|| "a < b"), &a_bits, &b_bits).unwrap();

        assert!(
            cs.is_satisfied(),
            "lexicographic: 0x01... < 0xFF... should be satisfied"
        );
    }

    #[test]
    fn test_less_than_lexicographic_byte0_greater() {
        // Test that byte 0 being greater makes a > b lexicographically
        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

        // a: byte 0 = 0xFF, byte 31 = 0x00
        // b: byte 0 = 0x01, byte 31 = 0xFF
        // Lexicographic: a > b (0xFF > 0x01 at byte 0)
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[0] = 0xFF;
        a_bytes[31] = 0x00;
        b_bytes[0] = 0x01;
        b_bytes[31] = 0xFF;

        let a_bits = alloc_bits(cs.namespace(|| "a"), &a_bytes).unwrap();
        let b_bits = alloc_bits(cs.namespace(|| "b"), &b_bytes).unwrap();

        enforce_less_than(cs.namespace(|| "a < b"), &a_bits, &b_bits).unwrap();

        assert!(
            !cs.is_satisfied(),
            "lexicographic: 0xFF... < 0x01... should NOT be satisfied"
        );
    }

    #[test]
    fn test_less_than_last_byte_difference() {
        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

        // When all bytes are equal except byte 31 (least significant in lexicographic)
        // a: byte 31 = 0x7F
        // b: byte 31 = 0x80
        // Lexicographic: a < b (0x7F < 0x80 at byte 31)
        let mut a_bytes = [0u8; 32];
        let mut b_bytes = [0u8; 32];
        a_bytes[31] = 0x7F;
        b_bytes[31] = 0x80;

        let a_bits = alloc_bits(cs.namespace(|| "a"), &a_bytes).unwrap();
        let b_bits = alloc_bits(cs.namespace(|| "b"), &b_bytes).unwrap();

        enforce_less_than(cs.namespace(|| "a < b"), &a_bits, &b_bits).unwrap();

        assert!(cs.is_satisfied(), "0x...7F < 0x...80 should be satisfied");
    }

    #[test]
    fn test_less_than_adjacent_values() {
        let mut cs = TestConstraintSystem::<bls12_381::Scalar>::new();

        // a = 0xFF...FE, b = 0xFF...FF (max - 1 < max)
        let a_bytes = [
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];
        let b_bytes = [0xFF; 32];

        let a_bits = alloc_bits(cs.namespace(|| "a"), &a_bytes).unwrap();
        let b_bits = alloc_bits(cs.namespace(|| "b"), &b_bytes).unwrap();

        enforce_less_than(cs.namespace(|| "a < b"), &a_bits, &b_bits).unwrap();

        assert!(cs.is_satisfied(), "max-1 < max should be satisfied");
    }
}
