{ inputs, ... }:
{
  perSystem =
    { pkgs, ... }:
    let
      # Stable Rust: used for development (devshell)
      rustToolchainStable = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;

      # Nightly Rust: used for pre-commit hooks (clippy, cargo-check, etc.)
      rust-toolchain = fromTOML (builtins.readFile ../rust-toolchain.toml);
      rust-toolchain-nightly = rust-toolchain // {
        toolchain = rust-toolchain.toolchain // {
          channel = "nightly";
        };
      };
      rustToolchainNightly = pkgs.rust-bin.fromRustupToolchain rust-toolchain-nightly.toolchain;

      # Patch orchard
      patchedOrchard = pkgs.runCommand "orchard-patched" { } ''
        cp -r ${inputs.orchard} $out
        chmod -R +w $out
        patch -p1 -d $out < ${./airdrop-orchard-nullifier.patch}
      '';

      # Patch halo2_gadgets
      patchedHalo2Gadgets = pkgs.runCommand "halo2-gadgets-patched" { } ''
        cp -r ${inputs.halo2-gadgets-crate} $out
        chmod -R +w $out
        patch -p1 -d $out < ${./airdrop-halo2-gadgets-sha256.patch}
      '';

      # Patch sapling
      patchedSapling = pkgs.runCommand "sapling-patched" { } ''
        cp -r ${inputs.sapling-crypto} $out
        chmod -R +w $out
        patch -p1 -d $out < ${./airdrop-sapling-nullifier.patch}
      '';
    in
    {
      _module.args = {
        inherit
          rustToolchainStable
          rustToolchainNightly
          patchedOrchard
          patchedHalo2Gadgets
          patchedSapling
          ;
      };
    };
}
