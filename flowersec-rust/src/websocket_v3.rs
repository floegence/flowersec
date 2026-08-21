//! Strict Flowersec v3 WebSocket carrier profile.

use std::{fmt, io, net::SocketAddr, sync::Arc};

use crate::{transport_v3::CarrierSessionV3, websocket_transport};

pub(crate) use websocket_transport::WebSocketError;

pub(crate) const SUBPROTOCOL_DIRECT_V3: &str = "flowersec.direct.v3";
pub(crate) const SUBPROTOCOL_TUNNEL_V3: &str = "flowersec.tunnel.v3";
pub(crate) const DIRECT_PATH_V3: &str = "/flowersec/v3/direct";
pub(crate) const TUNNEL_PATH_V3: &str = "/flowersec/v3/tunnel";

pub(crate) struct WebSocketListener(websocket_transport::WebSocketListener);

impl fmt::Debug for WebSocketListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebSocketListener { <opaque> }")
    }
}

impl WebSocketListener {
    pub(crate) fn bind_direct(
        address: SocketAddr,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        allowed_origins: Vec<String>,
        capacity: u32,
    ) -> Result<Self, WebSocketError> {
        Self::bind(
            address,
            certificate_chain_der,
            private_key_der,
            allowed_origins,
            capacity,
            DIRECT_PATH_V3,
            SUBPROTOCOL_DIRECT_V3,
        )
    }

    pub(crate) fn bind_tunnel(
        address: SocketAddr,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        allowed_origins: Vec<String>,
        capacity: u32,
    ) -> Result<Self, WebSocketError> {
        Self::bind(
            address,
            certificate_chain_der,
            private_key_der,
            allowed_origins,
            capacity,
            TUNNEL_PATH_V3,
            SUBPROTOCOL_TUNNEL_V3,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn bind(
        address: SocketAddr,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        allowed_origins: Vec<String>,
        capacity: u32,
        path: &'static str,
        subprotocol: &'static str,
    ) -> Result<Self, WebSocketError> {
        websocket_transport::WebSocketListener::bind(
            address,
            certificate_chain_der,
            private_key_der,
            allowed_origins,
            capacity,
            path,
            subprotocol,
            true,
            true,
        )
        .map(Self)
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    pub(crate) async fn accept(&self) -> Result<Arc<dyn CarrierSessionV3>, WebSocketError> {
        self.accept_with_peer().await.map(|(carrier, _)| carrier)
    }

    pub(crate) async fn accept_with_peer(
        &self,
    ) -> Result<(Arc<dyn CarrierSessionV3>, SocketAddr), WebSocketError> {
        self.0
            .accept_with_peer()
            .await
            .map(|(carrier, peer)| (carrier as Arc<dyn CarrierSessionV3>, peer))
    }
}

pub(crate) async fn dial(
    url: &str,
    subprotocol: &'static str,
    origin: &str,
    tls_config: Arc<rustls::ClientConfig>,
    capacity: u32,
) -> Result<Arc<dyn CarrierSessionV3>, WebSocketError> {
    let expected_path = match subprotocol {
        SUBPROTOCOL_DIRECT_V3 => DIRECT_PATH_V3,
        SUBPROTOCOL_TUNNEL_V3 => TUNNEL_PATH_V3,
        _ => return Err(WebSocketError::InvalidConfiguration),
    };
    websocket_transport::dial_strict_tls(
        url,
        expected_path,
        subprotocol,
        origin,
        tls_config,
        capacity,
    )
    .await
    .map(|carrier| carrier as Arc<dyn CarrierSessionV3>)
}
