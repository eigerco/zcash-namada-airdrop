use crate::scanner::ScanVisitor;
use crate::{Nullifier, SanitiseNullifiers};

/// Chain nullifier visitor
#[derive(Default)]
pub struct ChainNullifiersVisitor {
    sapling_nullifiers: Vec<Nullifier>,
    orchard_nullifiers: Vec<Nullifier>,
}

impl ChainNullifiersVisitor {
    /// Get collected Sapling nullifiers
    #[must_use]
    pub fn sanitise_nullifiers(self) -> (SanitiseNullifiers, SanitiseNullifiers) {
        let sapling = SanitiseNullifiers::new(self.sapling_nullifiers);
        let orchard = SanitiseNullifiers::new(self.orchard_nullifiers);
        (sapling, orchard)
    }
}

impl ScanVisitor for ChainNullifiersVisitor {
    fn on_sapling_nullifier(&mut self, nullifier: &[u8; 32]) {
        self.sapling_nullifiers.push(Nullifier::from(nullifier));
    }

    fn on_orchard_nullifier(&mut self, nullifier: &[u8; 32]) {
        self.orchard_nullifiers.push(Nullifier::from(nullifier));
    }
}
