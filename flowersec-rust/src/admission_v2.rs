//! Carrier-neutral candidate admission between a runtime adapter and SessionV2.

use std::{io, sync::Arc};

use subtle::ConstantTimeEq as _;
use tokio_util::sync::CancellationToken;

use crate::{
    artifact_v2::{ArtifactLease, EncodedFsb2},
    transport_v2::{CarrierSessionV2, CarrierStreamV2},
};

const FSB2_HEADER_BYTES: usize = 12;
const MAX_FSB2_PAYLOAD_BYTES: usize = 32_768;
const FSA2_HEADER_BYTES: usize = 8;
const MAX_FSA2_REASON_BYTES: usize = 64;
const FSA2_SUCCESS: &[u8; FSA2_HEADER_BYTES] = b"FSA2\x02\x00\x00\x00";

/// The single connection lifecycle shared by every Rust runtime adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConnectionPhaseV2 {
    Attempt,
    Ready,
    Winner,
    Admitted,
    Established,
    Terminated,
}

/// One runtime-owned carrier candidate before credential admission.
pub(crate) struct CandidateAttemptV2 {
    carrier: Option<Arc<dyn CarrierSessionV2>>,
    phase: ConnectionPhaseV2,
}

impl std::fmt::Debug for CandidateAttemptV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CandidateAttemptV2")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

impl CandidateAttemptV2 {
    pub(crate) fn attempt() -> Self {
        Self {
            carrier: None,
            phase: ConnectionPhaseV2::Attempt,
        }
    }

    pub(crate) fn ready(mut self, carrier: Arc<dyn CarrierSessionV2>) -> Self {
        debug_assert_eq!(self.phase, ConnectionPhaseV2::Attempt);
        self.carrier = Some(carrier);
        self.phase = ConnectionPhaseV2::Ready;
        self
    }

    pub(crate) fn select_winner(mut self) -> Self {
        debug_assert_eq!(self.phase, ConnectionPhaseV2::Ready);
        self.phase = ConnectionPhaseV2::Winner;
        self
    }
}

#[derive(Debug)]
pub(crate) enum AdmissionCommitErrorV2 {
    Spend,
    Canceled,
    Timeout,
    Rejected,
    Retryable,
    Carrier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionStatusV2 {
    Success,
    Reject,
    Retryable,
}

/// Owns durable spend and the sole client credential write for one winner.
pub(crate) struct AdmissionCommitV2<'a> {
    attempt: CandidateAttemptV2,
    lease: &'a mut ArtifactLease,
    credential: EncodedFsb2,
    max_inbound_streams: u16,
}

impl<'a> AdmissionCommitV2<'a> {
    pub(crate) fn new(
        attempt: CandidateAttemptV2,
        lease: &'a mut ArtifactLease,
        credential: EncodedFsb2,
        max_inbound_streams: u16,
    ) -> Self {
        debug_assert_eq!(attempt.phase, ConnectionPhaseV2::Winner);
        Self {
            attempt,
            lease,
            credential,
            max_inbound_streams,
        }
    }

    pub(crate) async fn commit(
        mut self,
        deadline: tokio::time::Instant,
        cancellation: &CancellationToken,
    ) -> Result<AdmittedCandidateV2, AdmissionCommitErrorV2> {
        // Once durable spend starts it completes independently of caller cancellation.
        self.lease
            .commit_spend()
            .await
            .map_err(|_| AdmissionCommitErrorV2::Spend)?;
        if cancellation.is_cancelled() {
            return Err(AdmissionCommitErrorV2::Canceled);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(AdmissionCommitErrorV2::Timeout);
        }
        let carrier = self
            .attempt
            .carrier
            .as_ref()
            .expect("winner has a carrier")
            .clone();
        let credential = &self.credential;
        let exchange = async {
            validate_capacity(&*carrier, self.max_inbound_streams)
                .map_err(|_| AdmissionCommitErrorV2::Carrier)?;
            let admission = carrier
                .open_stream()
                .await
                .map_err(|_| AdmissionCommitErrorV2::Carrier)?;
            write_all(&*admission, &credential.raw)
                .await
                .map_err(|_| AdmissionCommitErrorV2::Carrier)?;
            admission
                .close_write()
                .await
                .map_err(|_| AdmissionCommitErrorV2::Carrier)?;
            match read_client_fsa2(&*admission)
                .await
                .map_err(|_| AdmissionCommitErrorV2::Carrier)?
            {
                AdmissionStatusV2::Success => Ok(()),
                AdmissionStatusV2::Reject => Err(AdmissionCommitErrorV2::Rejected),
                AdmissionStatusV2::Retryable => Err(AdmissionCommitErrorV2::Retryable),
            }
        };
        tokio::select! {
            _ = cancellation.cancelled() => return Err(AdmissionCommitErrorV2::Canceled),
            result = tokio::time::timeout_at(deadline, exchange) => match result {
                Err(_) => return Err(AdmissionCommitErrorV2::Timeout),
                Ok(Err(error)) => return Err(error),
                Ok(Ok(())) => {}
            }
        }
        self.attempt.phase = ConnectionPhaseV2::Admitted;
        let carrier = self
            .attempt
            .carrier
            .take()
            .expect("admitted candidate has a carrier");
        Ok(AdmittedCandidateV2 {
            attempt: self.attempt,
            carrier: Some(carrier),
            binding: self.credential.binding,
        })
    }
}

/// Owns server credential validation and the sole FSA2 response write.
pub(crate) struct ServerAdmissionV2<'a> {
    attempt: CandidateAttemptV2,
    expected: &'a [EncodedFsb2],
    max_inbound_streams: u16,
}

impl<'a> ServerAdmissionV2<'a> {
    pub(crate) fn new(
        attempt: CandidateAttemptV2,
        expected: &'a [EncodedFsb2],
        max_inbound_streams: u16,
    ) -> Self {
        debug_assert_eq!(attempt.phase, ConnectionPhaseV2::Winner);
        Self {
            attempt,
            expected,
            max_inbound_streams,
        }
    }

    pub(crate) async fn commit(mut self) -> io::Result<Option<AdmittedCandidateV2>> {
        let carrier = self
            .attempt
            .carrier
            .as_ref()
            .expect("winner has a carrier")
            .clone();
        validate_capacity(&*carrier, self.max_inbound_streams)?;
        let admission = carrier.accept_stream().await?;
        let raw = match read_bounded_fsb2(&*admission).await {
            Ok(raw) => raw,
            Err(_) => {
                let _ = admission.reset().await;
                return Ok(None);
            }
        };
        let Some(credential) = self.expected.iter().find(|candidate| {
            candidate.raw.len() == raw.len()
                && bool::from(candidate.raw.as_slice().ct_eq(raw.as_slice()))
        }) else {
            let _ = admission.reset().await;
            return Ok(None);
        };
        write_all(&*admission, FSA2_SUCCESS).await?;
        admission.close_write().await?;
        self.attempt.phase = ConnectionPhaseV2::Admitted;
        let carrier = self
            .attempt
            .carrier
            .take()
            .expect("admitted candidate has a carrier");
        Ok(Some(AdmittedCandidateV2 {
            attempt: self.attempt,
            carrier: Some(carrier),
            binding: credential.binding,
        }))
    }
}

impl Drop for CandidateAttemptV2 {
    fn drop(&mut self) {
        if !matches!(
            self.phase,
            ConnectionPhaseV2::Established | ConnectionPhaseV2::Terminated
        ) {
            if let Some(carrier) = &self.carrier {
                carrier.abort();
            }
            self.phase = ConnectionPhaseV2::Terminated;
        }
    }
}

/// An admitted candidate whose carrier is ready for the session engine.
pub(crate) struct AdmittedCandidateV2 {
    attempt: CandidateAttemptV2,
    carrier: Option<Arc<dyn CarrierSessionV2>>,
    binding: [u8; 32],
}

impl AdmittedCandidateV2 {
    pub(crate) fn carrier(&self) -> Arc<dyn CarrierSessionV2> {
        self.carrier
            .as_ref()
            .expect("admitted candidate has a carrier")
            .clone()
    }

    pub(crate) const fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub(crate) fn mark_established(mut self) {
        debug_assert_eq!(self.attempt.phase, ConnectionPhaseV2::Admitted);
        self.attempt.phase = ConnectionPhaseV2::Established;
        self.carrier.take();
    }
}

impl Drop for AdmittedCandidateV2 {
    fn drop(&mut self) {
        if let Some(carrier) = self.carrier.take() {
            carrier.abort();
        }
        if self.attempt.phase != ConnectionPhaseV2::Established {
            self.attempt.phase = ConnectionPhaseV2::Terminated;
        }
    }
}

fn validate_capacity(carrier: &dyn CarrierSessionV2, max_inbound_streams: u16) -> io::Result<()> {
    let expected = crate::transport_v2::carrier_inbound_stream_limit_v2(max_inbound_streams)
        .map_err(io::Error::other)?;
    if carrier.inbound_bidirectional_stream_capacity() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "carrier stream capacity does not match the session contract",
        ));
    }
    Ok(())
}

async fn read_bounded_fsb2(stream: &dyn CarrierStreamV2) -> io::Result<Vec<u8>> {
    let mut header = [0_u8; FSB2_HEADER_BYTES];
    read_exact(stream, &mut header).await?;
    if &header[..4] != b"FSB2" || header[4] != 2 || header[6..8] != [0, 0] {
        return Err(protocol_error("invalid admission header"));
    }
    let payload_length =
        u32::from_be_bytes(header[8..12].try_into().expect("header length")) as usize;
    if payload_length == 0 || payload_length > MAX_FSB2_PAYLOAD_BYTES {
        return Err(protocol_error("invalid admission payload length"));
    }
    let mut raw = Vec::with_capacity(FSB2_HEADER_BYTES + payload_length);
    raw.extend_from_slice(&header);
    raw.resize(FSB2_HEADER_BYTES + payload_length, 0);
    read_exact(stream, &mut raw[FSB2_HEADER_BYTES..]).await?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await? != 0 {
        return Err(protocol_error("trailing admission bytes"));
    }
    Ok(raw)
}

async fn read_client_fsa2(stream: &dyn CarrierStreamV2) -> io::Result<AdmissionStatusV2> {
    let mut header = [0_u8; FSA2_HEADER_BYTES];
    read_exact(stream, &mut header).await?;
    if &header[..4] != b"FSA2" || header[4] != 2 {
        return Err(protocol_error("invalid admission response header"));
    }
    let status = match header[5] {
        0 => AdmissionStatusV2::Success,
        1 => AdmissionStatusV2::Reject,
        2 => AdmissionStatusV2::Retryable,
        _ => return Err(protocol_error("invalid admission response status")),
    };
    let reason_length = usize::from(u16::from_be_bytes([header[6], header[7]]));
    if reason_length > MAX_FSA2_REASON_BYTES {
        return Err(protocol_error("admission response reason exceeds limit"));
    }
    let mut reason = vec![0_u8; reason_length];
    read_exact(stream, &mut reason).await?;
    // Rejection reasons are deployment-owned. Clients validate only the
    // bounded wire token and never require a deployment registry.
    let valid_reason = match status {
        AdmissionStatusV2::Success => reason.is_empty(),
        AdmissionStatusV2::Reject | AdmissionStatusV2::Retryable => {
            valid_admission_reason_token(&reason)
        }
    };
    if !valid_reason {
        return Err(protocol_error("invalid admission response reason"));
    }
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await? != 0 {
        return Err(protocol_error("trailing admission response bytes"));
    }
    Ok(status)
}

fn valid_admission_reason_token(reason: &[u8]) -> bool {
    let Some((&first, rest)) = reason.split_first() else {
        return false;
    };
    first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

async fn read_exact(stream: &dyn CarrierStreamV2, mut payload: &mut [u8]) -> io::Result<()> {
    while !payload.is_empty() {
        let read = stream.read(payload).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "admission stream truncated",
            ));
        }
        payload = &mut payload[read..];
    }
    Ok(())
}

async fn write_all(stream: &dyn CarrierStreamV2, mut payload: &[u8]) -> io::Result<()> {
    while !payload.is_empty() {
        let written = stream.write(payload).await?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "admission stream accepted no bytes",
            ));
        }
        payload = &payload[written..];
    }
    Ok(())
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
