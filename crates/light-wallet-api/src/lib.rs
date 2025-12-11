//! Light Wallet API for interacting with Zcash light wallets.
mod rpc {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::restriction,
        missing_docs,
        reason = "Relax lints for generated code"
    )]

    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

pub use rpc::*;
