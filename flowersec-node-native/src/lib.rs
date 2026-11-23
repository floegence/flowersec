#![deny(clippy::all)]

//! Thin N-API lifecycle bridge for Flowersec native transports.

mod raw_quic;
mod webtransport;

pub use raw_quic::{bind_raw_quic, connect_raw_quic};
pub use webtransport::{bind as bind_webtransport, connect as connect_webtransport};

fn is_remote_session_close(close: Option<flowersec_native_transport::ApplicationClose>) -> bool {
    close.is_some_and(|close| close.code == 1 && close.reason == "session closed")
}

#[napi_derive::napi(js_name = "contractVersion")]
pub fn contract_version() -> u32 {
    5
}

#[cfg(test)]
mod tests {
    use super::is_remote_session_close;
    use flowersec_native_transport::ApplicationClose;

    #[test]
    fn only_the_exact_peer_close_is_normal() {
        assert!(!is_remote_session_close(None));
        for (code, reason, expected) in [
            (1, "session closed", true),
            (0, "session closed", false),
            (1, "Session closed", false),
            (1, "session closed\0", false),
            (1, "", false),
        ] {
            assert_eq!(
                is_remote_session_close(Some(ApplicationClose {
                    code,
                    reason: reason.to_owned(),
                })),
                expected
            );
        }
    }
}
