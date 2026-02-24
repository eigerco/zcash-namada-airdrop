_: {
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
    in
    {
      _module.args = {
        inherit
          rustToolchainStable
          rustToolchainNightly
          ;
      };
    };
}
