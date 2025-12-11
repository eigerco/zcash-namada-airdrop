//! This module defines the `ChainNullifiers` trait and its implementations.
//! `ChainNullifiers` provides a streaming interface to read nullifiers from various sources.

use std::ops::RangeInclusive;

use futures_core::Stream;

use crate::{Nullifier, Pool};

/// A nullifier tagged with its pool
#[derive(Debug, Clone)]
pub struct PoolNullifier {
    /// The pool the nullifier belongs to
    pub pool: Pool,
    /// The nullifier itself
    pub nullifier: Nullifier,
}

/// This trait defines how to read nullifiers
///
/// The streaming interface is used to be inline with the lightwalletd gRPC interface.
pub trait ChainNullifiers: Sized {
    /// The error type for this source
    type Error: std::error::Error + Send + 'static;

    /// The concrete stream type returned by this source
    type Stream: Stream<Item = Result<PoolNullifier, Self::Error>> + Send;

    /// Return a stream of all nullifiers (both Sapling and Orchard) in the given range.
    ///
    /// # Cancellation
    ///
    /// Dropping the stream cancels the operation. See individual implementations
    /// for details on cleanup behavior.
    fn nullifiers_stream(&self, range: &RangeInclusive<u64>) -> Self::Stream;
}
