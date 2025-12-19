{ inputs, ... }:

{
  imports = [ inputs.git-hooks-nix.flakeModule ];

  perSystem =
    { system, ... }:
    let
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ (import inputs.rust-overlay) ];
      };

      rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
    in
    {
      # To configure git hooks after you change this file, run:
      # $ nix develop -c pre-commit run -a
      pre-commit = {
        check.enable = true;
        settings.hooks = {
          # markdown
          markdownlint = {
            enable = true;
            args = [
              "--disable"
              "MD013"
            ];
          };

          # shell
          shellcheck.enable = true;

          # nix
          nixfmt-rfc-style.enable = true;
          flake-checker.enable = true;
          statix = {
            enable = true;
            settings = {
              ignore = [ ".direnv" ];
            };
          };

          # Rust
          cargo-check = {
            package = rustToolchain;
            enable = false; # Disabled due to offline mode issues with new dependencies
          };

          cargo-test = {
            enable = false; # Disabled due to offline mode issues with new dependencies
            name = "cargo test";
            entry = "${rustToolchain}/bin/cargo test";
            pass_filenames = false;
          };

          # Check for security vulnerabilities
          cargo-audit = {
            enable = false; # Disabled due to offline mode issues with new dependencies
            name = "cargo-audit";
            entry = "${pkgs.cargo-audit}/bin/cargo-audit audit";
            pass_filenames = false;
          };

          # Check for unused dependencies
          cargo-machete = {
            enable = true;
            name = "cargo-machete";
            entry = "${pkgs.cargo-machete}/bin/cargo-machete";
            pass_filenames = false;
          };

          # Rust linter
          clippy = {
            package = rustToolchain;
            enable = false; # Disabled due to offline mode issues with new dependencies
          };

          # secret detection
          ripsecrets.enable = true;
          trufflehog.enable = true;

          # spell checker
          typos = {
            enable = true;
            settings.config = {
              # Ignore words matching long alphanumeric patterns (hashes, addresses)
              # This regex matches strings with 16+ alphanumeric chars (adjust as needed)
              # See: https://github.com/crate-ci/typos#configuration
              default.extend-ignore-re = [ "([a-zA-Z0-9]{16,})" ];
              default.extend-words = {
                groth = "groth";
                Groth = "Groth";
              };
            };
          };

          # toml
          taplo.enable = true;

          # yaml
          yamllint.enable = true;
        };
      };
    };
}
