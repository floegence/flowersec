#![deny(clippy::all)]

//! Thin N-API lifecycle bridge for Flowersec native transports.

mod raw_quic;

pub use raw_quic::{bind_raw_quic, connect_raw_quic};

#[napi_derive::napi(js_name = "contractVersion")]
pub fn contract_version() -> u32 {
    1
}
