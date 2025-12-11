//! Build script to compile protobuf definitions for the Zcash light wallet API.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .ok_or_else(|| {
            format!(
                "Failed to find workspace directory from manifest dir: {}",
                manifest_dir.display()
            )
        })?;

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
