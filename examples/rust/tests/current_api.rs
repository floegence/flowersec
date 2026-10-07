use flowersec::{
    ConnectionError, ConnectionMaterialSource, ConnectionRequirements, Session,
    TransportEnvironment,
};
use flowersec_rust_client_example::connect_current;
use std::future::Future;
use tokio_util::sync::CancellationToken;

fn current_entrypoint(
    environment: &TransportEnvironment,
    source: &ConnectionMaterialSource,
    requirements: ConnectionRequirements,
    cancellation: CancellationToken,
) -> impl Future<Output = Result<Session, ConnectionError>> {
    connect_current(environment, source, requirements, cancellation)
}

#[test]
fn exposes_the_current_material_source_entrypoint() {
    let _ = current_entrypoint;
}
