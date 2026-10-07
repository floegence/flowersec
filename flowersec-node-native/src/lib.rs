#![deny(clippy::all)]

//! N-API transport lifecycle bridge and fixed SQLite admission extension.

mod raw_quic;
mod sqlite_admission;
mod web_transport;

pub use raw_quic::{bind_raw_quic, connect_raw_quic};
pub use web_transport::{bind_web_transport, connect_web_transport};

#[napi_derive::napi(js_name = "contractVersion")]
pub fn contract_version() -> u32 {
    4
}
