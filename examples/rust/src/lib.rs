//! Current Rust client integration surface.
//!
//! The deployment adapter constructs the trusted [`TransportEnvironment`] and
//! [`ConnectionMaterialSource`] from its verified namespace bootstrap, identity,
//! provider policy, and durable spend store. This crate deliberately accepts
//! those opaque owners instead of inventing credentials or persistence policy.

use flowersec::{
    ConnectionError, ConnectionMaterialSource, ConnectionRequest, ConnectionRequirements, Session,
    TransportEnvironment,
};
use tokio_util::sync::CancellationToken;

/// Acquire one current session through the configured SDK-owned source.
///
/// The source captures one identity, provider, credential generation, and
/// durable spend owner. A cancellation or uncertain authorization outcome is
/// returned by the SDK without silently acquiring or spending another record.
pub async fn connect_current(
    environment: &TransportEnvironment,
    source: &ConnectionMaterialSource,
    requirements: ConnectionRequirements,
    cancellation: CancellationToken,
) -> Result<Session, ConnectionError> {
    environment
        .connect(
            source,
            ConnectionRequest {
                requirements,
                handlers: None,
            },
            cancellation,
        )
        .await
}
