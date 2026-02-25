{
  description = "Rust development template";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    git-hooks-nix.url = "github:cachix/git-hooks.nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    treefmt-nix.url = "github:numtide/treefmt-nix";

    # Pin to specific versions matching Cargo.toml
    sapling-crypto = {
      url = "github:zcash/sapling-crypto/v0.5.0";
      flake = false;
    };

    orchard = {
      url = "github:zcash/orchard/v0.11.0";
      flake = false;
    };

    halo2 = {
      # Commit used by crates.io `halo2_gadgets` 0.3.1 (`path_in_vcs = halo2_gadgets`).
      url = "github:zcash/halo2/3bb6f5ccbcdc3d285babcea09925a741a4452281";
      flake = false;
    };
  };

  outputs =
    inputs@{
      flake-parts,
      rust-overlay,
      nixpkgs,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "x86_64-darwin"
      ];

      imports = [
        ./nix/pkgs
        ./nix/lib.nix
        ./nix/devshell.nix
        ./nix/formatting.nix
        ./nix/git-hooks.nix
      ];

      perSystem =
        { system, ... }:
        {
          # Per-system attributes can be defined here. The self' and inputs'
          # module parameters provide easy access to attributes of the same
          # system.
          _module.args.pkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
        };
    };
}
