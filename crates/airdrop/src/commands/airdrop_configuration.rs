use std::ops::RangeInclusive;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use eyre::{Context as _, ContextCompat as _};
use http::Uri;
use non_membership_proofs::light_walletd::LightWalletd;
use non_membership_proofs::scanner::ChainNullifiersVisitor;
use non_membership_proofs::utils::ReversedHex;
use non_membership_proofs::{NonMembershipTree, SanitiseNullifiers, write_nullifiers};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::hex::Hex;
use serde_with::serde_as;
use tokio::fs::File;
use tokio::io::BufWriter;
use tracing::{info, instrument, warn};
use zcash_protocol::consensus::BlockHeight;

use crate::BUF_SIZE;
use crate::cli::CommonArgs;

/// Configuration for an airdrop, including snapshot range and Merkle roots and the hiding factors
/// for each Zcash pool.
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct AirdropConfiguration {
    /// The inclusive range of block heights for the snapshot.
    pub snapshot_range: RangeInclusive<u64>,
    /// The non-membership tree roots for Sapling and Orchard nullifiers.
    pub non_membership_tree_anchors: NonMembershipTreeAnchors,
    /// The commitment tree anchors for Sapling and Orchard pools at snapshot height.
    pub note_commitment_tree_anchors: CommitmentTreeAnchors,
    /// Hiding factor for nullifiers
    #[serde(default)]
    pub hiding_factor: HidingFactor,
}

/// Commitment tree anchors for Sapling and Orchard pools.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct CommitmentTreeAnchors {
    /// Sapling commitment tree anchor
    #[serde_as(as = "ReversedHex")]
    #[schemars(with = "String")]
    pub sapling: [u8; 32],
    /// Orchard commitment tree anchor
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub orchard: [u8; 32],
}

/// Non-membership tree roots for Sapling and Orchard nullifiers.
#[serde_as]
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Clone)]
pub struct NonMembershipTreeAnchors {
    /// Sapling non-membership tree root
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub sapling: [u8; 32],
    /// Orchard non-membership tree root
    #[serde_as(as = "Hex")]
    #[schemars(with = "String")]
    pub orchard: [u8; 32],
}

impl From<non_membership_proofs::light_walletd::CommitmentTreeAnchors> for CommitmentTreeAnchors {
    fn from(anchors: non_membership_proofs::light_walletd::CommitmentTreeAnchors) -> Self {
        Self {
            sapling: anchors.sapling,
            orchard: anchors.orchard,
        }
    }
}

impl From<CommitmentTreeAnchors> for non_membership_proofs::light_walletd::CommitmentTreeAnchors {
    fn from(anchors: CommitmentTreeAnchors) -> Self {
        Self {
            sapling: anchors.sapling,
            orchard: anchors.orchard,
        }
    }
}

/// Hiding factor for hiding-nullifier derivation
#[derive(Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default)]
pub struct HidingFactor {
    /// Hiding factor for Sapling hiding-nullifiers
    pub sapling: SaplingHidingFactor,
    /// Hiding factor for Orchard hiding-nullifiers
    pub orchard: OrchardHidingFactor,
}

/// Sapling hiding factor
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default, clap::Args)]
pub struct SaplingHidingFactor {
    /// Personalization bytes, are used to derive the hiding sapling nullifier
    #[arg(long)]
    pub personalization: String,
}

/// Orchard hiding factor
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq, Default, clap::Args)]
pub struct OrchardHidingFactor {
    /// Domain separator for the hiding orchard nullifier
    #[arg(long)]
    pub domain: String,
    /// Tag bytes, are used to derive the hiding orchard nullifier
    #[arg(long)]
    pub tag: String,
}

impl<'a> From<&'a SaplingHidingFactor>
    for non_membership_proofs::user_nullifiers::SaplingHidingFactor<'a>
{
    fn from(owned: &'a SaplingHidingFactor) -> Self {
        Self {
            personalization: owned.personalization.as_bytes(),
        }
    }
}

impl<'a> From<&'a OrchardHidingFactor>
    for non_membership_proofs::user_nullifiers::OrchardHidingFactor<'a>
{
    fn from(owned: &'a OrchardHidingFactor) -> Self {
        Self {
            domain: &owned.domain,
            tag: owned.tag.as_bytes(),
        }
    }
}

impl AirdropConfiguration {
    /// Create a new airdrop configuration.
    #[must_use]
    pub const fn new(
        snapshot_range: RangeInclusive<u64>,
        non_membership_tree_anchors: NonMembershipTreeAnchors,
        note_commitment_tree_anchors: CommitmentTreeAnchors,
        hiding_factor: HidingFactor,
    ) -> Self {
        Self {
            snapshot_range,
            non_membership_tree_anchors,
            note_commitment_tree_anchors,
            hiding_factor,
        }
    }

    /// Export the airdrop configuration to a JSON file.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub async fn export_config(&self, destination: impl AsRef<Path>) -> eyre::Result<()> {
        let config_json = serde_json::to_string_pretty(self)?;
        tokio::fs::write(destination, config_json).await?;
        Ok(())
    }
}

/// Build the airdrop configuration by fetching nullifiers from lightwalletd
/// and computing the non-membership merkle-tree
///
/// # Errors
/// Returns an error if fetching nullifiers or writing files fails
#[instrument(skip_all, fields(
    snapshot = %format!("{}..={}", config.snapshot.start(), config.snapshot.end())
))]
pub async fn build_airdrop_configuration(
    config: CommonArgs,
    configuration_output_file: PathBuf,
    sapling_snapshot_nullifiers: PathBuf,
    orchard_snapshot_nullifiers: PathBuf,
    hiding_factor: HidingFactor,
) -> eyre::Result<()> {
    info!("Fetching nullifiers");
    let lightwalletd_url =
        Uri::from_str(&config.lightwalletd_url).context("lightwalletd URL is required")?;
    let lightwalletd = LightWalletd::connect(lightwalletd_url).await?;

    let mut visitor = ChainNullifiersVisitor::default();
    lightwalletd
        .scan_nullifiers(&mut visitor, &config.snapshot)
        .await?;
    let (sapling_nullifiers, orchard_nullifiers) = visitor.sanitise_nullifiers();

    let sapling_handle = tokio::spawn(process_pool(
        "sapling",
        sapling_nullifiers,
        sapling_snapshot_nullifiers,
    ));
    let orchard_handle = tokio::spawn(process_pool(
        "orchard",
        orchard_nullifiers,
        orchard_snapshot_nullifiers,
    ));

    let (sapling_nf_root, orchard_nf_root) = tokio::try_join!(sapling_handle, orchard_handle)?;
    let non_membership_tree_anchors = NonMembershipTreeAnchors {
        sapling: sapling_nf_root?.unwrap_or_default(),
        orchard: orchard_nf_root?.unwrap_or_default(),
    };
    info!("Computed non-membership tree anchors");

    // These are the note commitment tree roots needed for proving note existence
    let upper_limit: u32 = (*config.snapshot.end())
        .try_into()
        .context("Snapshot end height too large")?;
    let upper_limit = upper_limit
        .checked_add(1)
        .context("Snapshot end height overflowed when adding 1")?;

    let note_commitment_tree_anchors = lightwalletd
        .commitment_tree_anchors(BlockHeight::from_u32(upper_limit))
        .await
        .context("Failed to fetch commitment tree anchors from lightwalletd")?;

    AirdropConfiguration::new(
        config.snapshot,
        non_membership_tree_anchors,
        note_commitment_tree_anchors.into(),
        hiding_factor,
    )
    .export_config(&configuration_output_file)
    .await?;

    info!(file = ?configuration_output_file, "Exported configuration");
    Ok(())
}

#[instrument(skip_all, fields(pool = %pool, store = %store.display()))]
async fn process_pool(
    pool: &str,
    nullifiers: SanitiseNullifiers,
    store: PathBuf,
) -> eyre::Result<Option<[u8; 32]>> {
    if nullifiers.is_empty() {
        warn!(pool, "No nullifiers collected");
        return Ok(None);
    }

    info!(count = nullifiers.len(), "Collected nullifiers");

    let file = File::create(&store).await?;
    let mut writer = BufWriter::with_capacity(BUF_SIZE, file);
    write_nullifiers(&nullifiers, &mut writer).await?;
    info!(file = ?store, pool, "Saved nullifiers");

    let merkle_tree =
        tokio::task::spawn_blocking(move || NonMembershipTree::from_nullifiers(&nullifiers))
            .await??;

    let merkle_root = merkle_tree.root().to_bytes();

    Ok(Some(merkle_root))
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;
    use tokio::fs::File;
    use tokio::io::AsyncReadExt;

    use super::*;

    #[test]
    fn deserialize_json_format() {
        // Documents the expected JSON format for consumers
        let json = r#"{
          "snapshot_range": { "start": 100, "end": 200 },
          "non_membership_tree_anchors": {
            "sapling": "0505050505050505050505050505050505050505050505050505050505050505",
            "orchard": "0606060606060606060606060606060606060606060606060606060606060606"
          },
          "note_commitment_tree_anchors": {
            "sapling": "0101010101010101010101010101010101010101010101010101010101010101",
            "orchard": "0202020202020202020202020202020202020202020202020202020202020202"
          }
        }"#;

        let json_config: AirdropConfiguration =
            serde_json::from_str(json).expect("Failed to deserialize JSON");

        let expected_config = AirdropConfiguration::new(
            100..=200,
            NonMembershipTreeAnchors {
                sapling: [5_u8; 32_usize],
                orchard: [6_u8; 32_usize],
            },
            CommitmentTreeAnchors {
                sapling: [1_u8; 32_usize],
                orchard: [2_u8; 32_usize],
            },
            HidingFactor::default(),
        );
        assert_eq!(json_config.snapshot_range, expected_config.snapshot_range);
    }

    #[tokio::test]
    async fn export_config() {
        let config = AirdropConfiguration::new(
            100..=200,
            NonMembershipTreeAnchors {
                sapling: [5_u8; 32_usize],
                orchard: [6_u8; 32_usize],
            },
            CommitmentTreeAnchors {
                sapling: [1_u8; 32_usize],
                orchard: [2_u8; 32_usize],
            },
            HidingFactor::default(),
        );
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let path = temp_file.path();

        config
            .export_config(path)
            .await
            .expect("Failed to export config");

        let mut file = File::open(path)
            .await
            .expect("Failed to open exported config");
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .await
            .expect("Failed to read exported config");

        let loaded: AirdropConfiguration =
            serde_json::from_str(&contents).expect("Failed to deserialize exported config");
        assert_eq!(config, loaded);
    }

    #[test]
    fn sanity_check_conversions() {
        let sapling_hiding = SaplingHidingFactor {
            personalization: String::from_str("123").expect("Failed to create string"),
        };
        let orchard_hiding = OrchardHidingFactor {
            domain: "domain".to_string(),
            tag: String::from_str("456").expect("Failed to create string"),
        };

        let sapling_converted: non_membership_proofs::user_nullifiers::SaplingHidingFactor =
            (&sapling_hiding).into();
        assert_eq!(sapling_converted.personalization, b"123");

        let orchard_converted: non_membership_proofs::user_nullifiers::OrchardHidingFactor =
            (&orchard_hiding).into();
        assert_eq!(orchard_converted.domain, "domain");
        assert_eq!(orchard_converted.tag, b"456");
    }
}
