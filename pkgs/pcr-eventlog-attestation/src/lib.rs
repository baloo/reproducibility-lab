pub mod attestor;
pub mod client;
pub mod error;
pub mod server;
pub mod tpm;
pub(crate) mod utils;
pub mod verifier;

pub(crate) mod pea {
    tonic::include_proto!("grpc.pea");
}

pub const VERSION: &str = "0.0.0";
