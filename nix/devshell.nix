{ inputs, ... }:
{
  perSystem =
    { config, system, ... }:
    let
      # Apply rust overlay to nixpkgs
      pkgs = import inputs.nixpkgs {
        inherit system;
        overlays = [ (import inputs.rust-overlay) ];
      };

      # Patch orchard
      patchedOrchard = pkgs.runCommand "orchard-patched" { } ''
        cp -r ${inputs.orchard} $out
        chmod -R +w $out

        # Apply a patch file
        patch -p1 -d $out < ${./airdrop-orchard-nullifier.patch}
      '';

      # Patch sapling
      patchedSapling = pkgs.runCommand "sapling-patched" { } ''
        cp -r ${inputs.sapling-crypto} $out
        chmod -R +w $out

        # Apply a patch file
        patch -p1 -d $out < ${./airdrop-sapling-nullifier.patch}
      '';

      # Define Rust toolchain - you can customize this
      rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;

      # Define additional development tools
      devTools = with pkgs; [
        # Rust tools
        cargo-watch # Auto-rebuild on file changes
        cargo-edit # cargo add, cargo rm commands
        cargo-audit # Security audit
        cargo-outdated # Check for outdated dependencies
        cargo-expand # Expand macros in code
        cargo-hack
        cargo-machete # Check for unused dependencies

        # General development tools
        git
        protobuf
        typos
        tokio-console

        pre-commit
      ];

      # Environment variables required for each toolchain
      envs = {
        rust = {
          RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc; # Required for rust-analyzer

          # Force system OpenSSL instead of vendored version
          # Reference: https://docs.rs/openssl/latest/openssl/#manual
          OPENSSL_NO_VENDOR = 1;
          OPENSSL_LIB_DIR = "${pkgs.lib.getLib pkgs.openssl}/lib";
          OPENSSL_DIR = "${pkgs.lib.getDev pkgs.openssl}";
        };

        clang = {
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      };

      # PATH extensions for package managers
      pathExtensions = {
        cargo = ''export PATH="$PATH:~/.cargo/bin"'';
        npm = ''export PATH="$PATH:~/.npm-global/bin/"'';
      };

      rustToolchainContents = builtins.readFile ../rust-toolchain.toml;

      # Diagnostic information shown when shell starts
      devInfo = ''
        echo "🦀 Rust development environment loaded!"
        echo "Rust version: $(rustc --version)"
        echo "Cargo version: $(cargo --version)"
        echo "Build directory: $PWD"
        echo "Source directory: $src"
        echo ""
        echo "Available commands:"
        echo "  cargo build    - Build the project"
        echo "  cargo run      - Run the project"
        echo "  cargo test     - Run tests"
        echo "  cargo watch -x run - Auto-rebuild on changes"
        echo "  nix fmt        - Format code with nixformmater"
        echo "  nix check      - Code formatting and other linters checks"
        echo ""
        echo "Project initialized with ./rust-toolchain.toml"
        echo "rust-toolchain.toml contents 📦 🔧 🛠️:"
        echo '${rustToolchainContents}'
        echo ""
      '';
    in
    {
      # Development shell
      devShells.default = pkgs.mkShell {
        buildInputs = [ rustToolchain ] ++ devTools;

        inherit (envs.rust)
          RUST_SRC_PATH
          OPENSSL_NO_VENDOR
          OPENSSL_LIB_DIR
          OPENSSL_DIR
          ;
        inherit (envs.clang) LIBCLANG_PATH;

        # Environment variables
        env = {
          RUST_BACKTRACE = "1";
        };

        shellHook = ''
          ${config.pre-commit.installationScript}
          ${pathExtensions.cargo}

          # Create symlink to patched orchard for Cargo
          ln -sfn ${patchedOrchard} ./.patched-orchard

          # Create symlink to patched sapling for Cargo
          ln -sfn ${patchedSapling} ./.patched-sapling-crypto

          ${devInfo}
        '';
      };
    };
}
