# Getting Started

This section covers building `zair` and running a quick sanity check. Afterwards, you can follow the step-by-step guide on how to configure, prove and verify an airdrop claim in the [CLI Reference](../cli/index.md).

## Build options

### With Nix

Use the repo’s Nix flake to enter a development environment:

```bash
nix develop
```

Common commands:

```bash
cargo build --release
```

### Without Nix

Prerequisites:

- Rust 1.91+ (uses Rust 2024 edition)
- Protobuf compiler `protoc` (for lightwalletd gRPC bindings)

This workspace uses patched Zcash dependencies.

- `.patched-sapling-crypto`
- `.patched-orchard`
- `.patched-halo2-gadgets`

See `README.md` for detailed steps on cloning and patching.

## Building and Sanity check

Build the binary using

```bash
cargo build --release
```

You should be able to verify the CLI is available:

```bash
./target/release/zair --help
```

and inspect the command groups:

```bash
./target/release/zair key --help
./target/release/zair setup --help
./target/release/zair config --help
./target/release/zair claim --help
./target/release/zair verify --help
```

## Feature flags

The proving pipeline is gated behind the `prove` feature for some crates/binaries, enabled by default.

If you only need verification, you may build without proving support for a lighter dependency.
