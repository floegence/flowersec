// Function bodies in this module are regularly cfg'd out
#![allow(unused_variables)]

#[cfg(any())]
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(any())]
use qlog::{
    events::{
        Event, EventData,
        quic::{
            PacketHeader, PacketLost, PacketLostTrigger, PacketReceived, PacketSent, PacketType,
        },
    },
    streamer::QlogStreamer,
};
#[cfg(any())]
use tracing::warn;

use crate::quic_proto::{
    ConnectionId, Instant,
    connection::{PathData, SentPacket},
    packet::SpaceId,
};

/// Shareable handle to a single qlog output stream
#[cfg(any())]
#[derive(Clone)]
pub(crate) struct QlogStream(pub(crate) Arc<Mutex<QlogStreamer>>);

#[cfg(any())]
impl QlogStream {
    fn emit_event(&self, orig_rem_cid: ConnectionId, event: EventData, now: Instant) {
        // Time will be overwritten by `add_event_with_instant`
        let mut event = Event::with_time(0.0, event);
        event.group_id = Some(orig_rem_cid.to_string());

        let mut qlog_streamer = self.0.lock().unwrap();
        if let Err(e) = qlog_streamer.add_event_with_instant(event, now) {
            warn!("could not emit qlog event: {e}");
        }
    }
}

/// A [`QlogStream`] that may be either dynamically disabled or compiled out entirely
#[derive(Clone, Default)]
pub(crate) struct QlogSink {
    #[cfg(any())]
    stream: Option<QlogStream>,
}

impl QlogSink {
    pub(crate) fn is_enabled(&self) -> bool {
        #[cfg(any())]
        {
            self.stream.is_some()
        }
        #[cfg(not(any()))]
        {
            false
        }
    }

    pub(super) fn emit_recovery_metrics(
        &self,
        pto_count: u32,
        path: &mut PathData,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(any())]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let Some(metrics) = path.qlog_recovery_metrics(pto_count) else {
                return;
            };

            stream.emit_event(orig_rem_cid, EventData::MetricsUpdated(metrics), now);
        }
    }

    pub(super) fn emit_packet_lost(
        &self,
        pn: u64,
        info: &SentPacket,
        loss_delay: Duration,
        space: SpaceId,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(any())]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = PacketLost {
                header: Some(PacketHeader {
                    packet_number: Some(pn),
                    packet_type: packet_type(space, false),
                    length: Some(info.size),
                    ..Default::default()
                }),
                frames: None,
                trigger: Some(
                    match info.time_sent.saturating_duration_since(now) >= loss_delay {
                        true => PacketLostTrigger::TimeThreshold,
                        false => PacketLostTrigger::ReorderingThreshold,
                    },
                ),
            };

            stream.emit_event(orig_rem_cid, EventData::PacketLost(event), now);
        }
    }

    pub(super) fn emit_packet_sent(
        &self,
        pn: u64,
        len: usize,
        space: SpaceId,
        is_0rtt: bool,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(any())]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = PacketSent {
                header: PacketHeader {
                    packet_number: Some(pn),
                    packet_type: packet_type(space, is_0rtt),
                    length: Some(len as u16),
                    ..Default::default()
                },
                ..Default::default()
            };

            stream.emit_event(orig_rem_cid, EventData::PacketSent(event), now);
        }
    }

    pub(super) fn emit_packet_received(
        &self,
        pn: u64,
        space: SpaceId,
        is_0rtt: bool,
        now: Instant,
        orig_rem_cid: ConnectionId,
    ) {
        #[cfg(any())]
        {
            let Some(stream) = self.stream.as_ref() else {
                return;
            };

            let event = PacketReceived {
                header: PacketHeader {
                    packet_number: Some(pn),
                    packet_type: packet_type(space, is_0rtt),
                    ..Default::default()
                },
                ..Default::default()
            };

            stream.emit_event(orig_rem_cid, EventData::PacketReceived(event), now);
        }
    }
}

#[cfg(any())]
impl From<Option<QlogStream>> for QlogSink {
    fn from(stream: Option<QlogStream>) -> Self {
        Self { stream }
    }
}

#[cfg(any())]
fn packet_type(space: SpaceId, is_0rtt: bool) -> PacketType {
    match space {
        SpaceId::Initial => PacketType::Initial,
        SpaceId::Handshake => PacketType::Handshake,
        SpaceId::Data if is_0rtt => PacketType::ZeroRtt,
        SpaceId::Data => PacketType::OneRtt,
    }
}
