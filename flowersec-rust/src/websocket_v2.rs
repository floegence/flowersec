//! Flowersec v2 WebSocket carrier profile.

use std::{fmt, io, net::SocketAddr, sync::Arc};

use crate::{transport_v2::CarrierSessionV2, websocket_transport};

pub(crate) use websocket_transport::WebSocketError;

pub(crate) const SUBPROTOCOL_DIRECT: &str = "flowersec.direct.v2";
pub(crate) const SUBPROTOCOL_TUNNEL: &str = "flowersec.tunnel.v2";
const DIRECT_PATH: &str = "/flowersec/v2/direct";
const TUNNEL_PATH: &str = "/flowersec/v2/tunnel";

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
        websocket_transport::WebSocketListener::bind(
            address,
            certificate_chain_der,
            private_key_der,
            allowed_origins,
            capacity,
            DIRECT_PATH,
            SUBPROTOCOL_DIRECT,
            false,
            false,
        )
        .map(Self)
    }

    pub(crate) fn bind_tunnel(
        address: SocketAddr,
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
        allowed_origins: Vec<String>,
        capacity: u32,
    ) -> Result<Self, WebSocketError> {
        websocket_transport::WebSocketListener::bind(
            address,
            certificate_chain_der,
            private_key_der,
            allowed_origins,
            capacity,
            TUNNEL_PATH,
            SUBPROTOCOL_TUNNEL,
            true,
            false,
        )
        .map(Self)
    }

    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    pub(crate) async fn accept(&self) -> Result<Arc<dyn CarrierSessionV2>, WebSocketError> {
        self.accept_with_peer().await.map(|(carrier, _)| carrier)
    }

    pub(crate) async fn accept_with_peer(
        &self,
    ) -> Result<(Arc<dyn CarrierSessionV2>, SocketAddr), WebSocketError> {
        self.0
            .accept_with_peer()
            .await
            .map(|(carrier, peer)| (carrier as Arc<dyn CarrierSessionV2>, peer))
    }
}

pub(crate) async fn dial(
    url: &str,
    subprotocol: &'static str,
    origin: &str,
    trust_roots_der: Vec<Vec<u8>>,
    capacity: u32,
) -> Result<Arc<dyn CarrierSessionV2>, WebSocketError> {
    websocket_transport::dial_with_trust_roots(url, subprotocol, origin, trust_roots_der, capacity)
        .await
        .map(|carrier| carrier as Arc<dyn CarrierSessionV2>)
}

pub(crate) fn client_tls(
    trust_roots_der: Vec<Vec<u8>>,
) -> Result<Arc<rustls::ClientConfig>, WebSocketError> {
    websocket_transport::client_tls(trust_roots_der)
}
