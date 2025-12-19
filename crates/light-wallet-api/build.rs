//! Build script to compile protobuf definitions for the Zcash light wallet API.

use std::path::{Path, PathBuf};

fn find_workspace_dir(
    manifest_dir: impl AsRef<Path>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut manifest_dir = manifest_dir.as_ref();
    while let Some(parent) = manifest_dir.parent() {
        if parent.join("Cargo.toml").exists() && parent.join("Cargo.lock").exists() {
            return Ok(parent.to_path_buf());
        }
        manifest_dir = parent;
    }

    Err("Failed to find workspace directory".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = find_workspace_dir(&manifest_dir)?;

    let proto_dir = workspace_dir.join("proto/lightwallet-protocol/walletrpc");
    let compact_formats = proto_dir.join("compact_formats.proto");
    let service = proto_dir.join("service.proto");

    // Validate that proto files exist
    let missing_files: Vec<_> = [&compact_formats, &service]
        .iter()
        .filter_map(|path| (!path.exists()).then_some(path.display().to_string()))
        .collect();

    if !missing_files.is_empty() {
        return Err(format!(
            "The build script could not find the required proto file(s): {}. Has 'git submodule update --init' been run?",
            missing_files.join(", ")
        ).into());
    }

    // Tell Cargo to rerun if proto files change
    println!("cargo:rerun-if-changed={}", compact_formats.display());
    println!("cargo:rerun-if-changed={}", service.display());
    println!("cargo:rerun-if-changed=build.rs");

    // Also rerun if the proto directory structure changes
    println!("cargo:rerun-if-changed={}", proto_dir.display());

    tonic_prost_build::configure()
        .build_server(false)
        .compile_protos(
            &[
                compact_formats.to_str().ok_or_else(|| {
                    format!("Invalid UTF-8 in path: {}", compact_formats.display())
                })?,
                service
                    .to_str()
                    .ok_or_else(|| format!("Invalid UTF-8 in path: {}", service.display()))?,
            ],
            &[proto_dir
                .to_str()
                .ok_or_else(|| format!("Invalid UTF-8 in path: {}", proto_dir.display()))?],
        )
        .map_err(|e| format!("Failed to compile protobuf definitions: {e}"))?;

    Ok(())
}
