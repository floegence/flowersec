//! Bounded application headers and reliable RPC fragments. Syntax values carry
//! no service registration, caller authorization or execution capability.
use crate::{
    codec_v4::{self as codec, Limits, Value},
    service_contract::{ServiceError, ServiceFailure},
};
use serde_json::Value as Json;
pub(crate) type Result<T> = std::result::Result<T, ServiceError>;
fn protocol() -> ServiceError {
    ServiceError(ServiceFailure::Protocol)
}
fn parsed<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| protocol())
}
fn headers() -> &'static Json {
    codec::application_header_registry()
}
fn fragments() -> &'static Json {
    codec::rpc_fragment_registry()
}
fn number(value: &Json) -> Result<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse().ok())
        .ok_or_else(protocol)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HeaderScalar {
    Uint(u64),
    Bytes([u8; 32]),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ApplicationHeader {
    kind: &'static str,
    fields: [Option<HeaderScalar>; 11],
}
impl ApplicationHeader {
    pub(crate) fn decode(input: &[u8]) -> Result<Self> {
        let doc = parsed(codec::decode(
            input,
            "ApplicationHeader",
            Limits {
                bytes: 512,
                nodes: 23,
            },
            None,
        ))?;
        let code = parsed(doc.u("ApplicationHeader", "message_kind"))?;
        let (kind, variant) = headers()["kinds"]
            .as_object()
            .ok_or_else(protocol)?
            .iter()
            .find(|(_, value)| value["code"].as_u64() == Some(code))
            .ok_or_else(protocol)?;
        let expected = variant["fields"].as_array().ok_or_else(protocol)?;
        if parsed(doc.len())? != expected.len() {
            return Err(protocol());
        }
        let mut fields = [None; 11];
        let mut children = parsed(doc.children())?;
        let mut index = 0;
        while let Some(key) = children.next() {
            let id = parsed(key.and_then(Value::uint))? as usize;
            if id >= fields.len() || expected.get(index).and_then(Json::as_u64) != Some(id as u64) {
                return Err(protocol());
            }
            let field = parsed(children.next().ok_or("truncated").and_then(|value| value))?;
            fields[id] = Some(if matches!(id, 1 | 4 | 6) {
                HeaderScalar::Bytes(parsed(field.bytes())?.try_into().map_err(|_| protocol())?)
            } else {
                HeaderScalar::Uint(parsed(field.uint())?)
            });
            index += 1;
        }
        if let Some(constants) = variant["constants"].as_object() {
            for (id, expected) in constants {
                let id: usize = id.parse().map_err(|_| protocol())?;
                if fields.get(id).copied().flatten() != Some(HeaderScalar::Uint(number(expected)?))
                {
                    return Err(protocol());
                }
            }
        }
        let result = Self { kind, fields };
        if result.sdk_error() && result.payload_bytes()? > 256 {
            return Err(protocol());
        }
        Ok(result)
    }
    pub(crate) fn create(kind: &str, mut fields: [Option<HeaderScalar>; 11]) -> Result<Self> {
        let variant = headers()["kinds"].get(kind).ok_or_else(protocol)?;
        fields[0] = Some(HeaderScalar::Uint(number(&variant["code"])?));
        let expected = variant["fields"].as_array().ok_or_else(protocol)?;
        for (id, field) in fields.iter().enumerate() {
            if field.is_some()
                != expected
                    .iter()
                    .any(|value| value.as_u64() == Some(id as u64))
            {
                return Err(protocol());
            }
        }
        let mut wire = Vec::with_capacity(512);
        codec::encode_head(&mut wire, 5, expected.len() as u64);
        for (id, field) in fields.into_iter().enumerate() {
            let Some(field) = field else {
                continue;
            };
            codec::encode_head(&mut wire, 0, id as u64);
            match field {
                HeaderScalar::Uint(value) => codec::encode_head(&mut wire, 0, value),
                HeaderScalar::Bytes(value) => {
                    codec::encode_head(&mut wire, 2, 32);
                    wire.extend_from_slice(&value);
                }
            }
        }
        Self::decode(&wire)
    }
    pub(crate) fn response(
        &self,
        kind: &str,
        payload_bytes: u32,
        application_error: Option<u32>,
    ) -> Result<Self> {
        let variant = headers()["kinds"].get(kind).ok_or_else(protocol)?;
        if variant["request"].as_str() != Some(self.kind) {
            return Err(protocol());
        }
        let mut fields = [None; 11];
        for field in variant["fields"].as_array().ok_or_else(protocol)? {
            let id = number(field)? as usize;
            if id >= fields.len() {
                return Err(protocol());
            }
            fields[id] = match id {
                0 => None,
                3 => Some(HeaderScalar::Uint(u64::from(payload_bytes))),
                10 => application_error.map(|code| HeaderScalar::Uint(u64::from(code))),
                _ => self.fields[id],
            };
        }
        let result = Self::create(kind, fields)?;
        result.check_response(self)?;
        Ok(result)
    }
    pub(crate) fn encode(&self, destination: &mut [u8]) -> Result<usize> {
        let mut wire = Vec::with_capacity(512);
        codec::encode_head(&mut wire, 5, self.fields.iter().flatten().count() as u64);
        for (id, value) in self.fields.iter().enumerate() {
            let Some(value) = value else {
                continue;
            };
            codec::encode_head(&mut wire, 0, id as u64);
            match value {
                HeaderScalar::Uint(value) => codec::encode_head(&mut wire, 0, *value),
                HeaderScalar::Bytes(value) => {
                    codec::encode_head(&mut wire, 2, 32);
                    wire.extend_from_slice(value);
                }
            }
        }
        if destination.len() < wire.len() {
            return Err(ServiceError(ServiceFailure::ResourceExhausted));
        }
        destination[..wire.len()].copy_from_slice(&wire);
        Ok(wire.len())
    }
    pub(crate) fn kind(&self) -> &'static str {
        self.kind
    }
    pub(crate) fn uint(&self, id: usize) -> Result<u64> {
        match self.fields.get(id).copied().flatten() {
            Some(HeaderScalar::Uint(value)) => Ok(value),
            _ => Err(protocol()),
        }
    }
    pub(crate) fn bytes(&self, id: usize) -> Result<[u8; 32]> {
        match self.fields.get(id).copied().flatten() {
            Some(HeaderScalar::Bytes(value)) => Ok(value),
            _ => Err(protocol()),
        }
    }
    pub(crate) fn has(&self, id: usize) -> bool {
        self.fields.get(id).is_some_and(Option::is_some)
    }
    pub(crate) fn payload_bytes(&self) -> Result<usize> {
        usize::try_from(self.uint(3)?).map_err(|_| protocol())
    }
    pub(crate) fn type_id(&self) -> Result<u32> {
        u32::try_from(self.uint(2)?).map_err(|_| protocol())
    }
    pub(crate) fn is_response(&self) -> bool {
        headers()["kinds"][self.kind]["request"].is_string()
    }
    pub(crate) fn sdk_error(&self) -> bool {
        headers()["kinds"][self.kind]["sdk_error"] == true
    }
    pub(crate) fn application_error(&self) -> bool {
        headers()["kinds"][self.kind]["application_error"] == true
    }
    pub(crate) fn check_response(&self, request: &Self) -> Result<()> {
        if headers()["kinds"][self.kind]["request"].as_str() != Some(request.kind) {
            return Err(protocol());
        }
        for id in [1, 2, 4, 6, 9] {
            if self.fields[id] != request.fields[id] {
                return Err(protocol());
            }
        }
        if request.has(8) && !self.sdk_error() && self.uint(3)? > request.uint(8)? {
            return Err(protocol());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FragmentKind {
    Begin,
    Data,
    Abort,
    StopOutput,
}
impl FragmentKind {
    fn name(self) -> &'static str {
        match self {
            Self::Begin => "BEGIN",
            Self::Data => "DATA",
            Self::Abort => "ABORT",
            Self::StopOutput => "STOP_OUTPUT",
        }
    }
    fn code(self) -> Result<u8> {
        u8::try_from(number(&fragments()["kinds"][self.name()]["value"])?).map_err(|_| protocol())
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Fragment<'a> {
    pub(crate) kind: FragmentKind,
    pub(crate) serial: u64,
    pub(crate) reply_to: u64,
    pub(crate) offset: u32,
    pub(crate) bytes: &'a [u8],
}
fn read_u64(input: &[u8], offset: usize, width: usize) -> Result<u64> {
    let bytes = input.get(offset..offset + width).ok_or_else(protocol)?;
    Ok(bytes
        .iter()
        .fold(0, |value, byte| value << 8 | u64::from(*byte)))
}
impl<'a> Fragment<'a> {
    pub(crate) fn decode(input: &'a [u8]) -> Result<Self> {
        let body = read_u64(input, 0, 4)? as usize;
        if body.checked_add(4) != Some(input.len())
            || body == 0
            || body as u64 > number(&fragments()["max_body_length"])?
        {
            return Err(protocol());
        }
        let code = *input.get(4).ok_or_else(protocol)?;
        let kind = [
            FragmentKind::Begin,
            FragmentKind::Data,
            FragmentKind::Abort,
            FragmentKind::StopOutput,
        ]
        .into_iter()
        .find(|kind| kind.code().ok() == Some(code))
        .ok_or_else(protocol)?;
        let spec = &fragments()["kinds"][kind.name()];
        if body - 1 < number(&spec["body_min_bytes"])? as usize
            || body - 1 > number(&spec["body_max_bytes"])? as usize
        {
            return Err(protocol());
        }
        let serial = read_u64(input, 5, 8)?;
        if serial == 0 {
            return Err(protocol());
        }
        match kind {
            FragmentKind::Begin => {
                let length = read_u64(input, 21, 2)? as usize;
                if length == 0 || length > 512 || input.len() != 23 + length {
                    return Err(protocol());
                }
                Ok(Self {
                    kind,
                    serial,
                    reply_to: read_u64(input, 13, 8)?,
                    offset: 0,
                    bytes: &input[23..],
                })
            }
            FragmentKind::Data | FragmentKind::Abort => Ok(Self {
                kind,
                serial,
                reply_to: 0,
                offset: read_u64(input, 13, 4)? as u32,
                bytes: &input[17..],
            }),
            FragmentKind::StopOutput => Ok(Self {
                kind,
                serial,
                reply_to: 0,
                offset: 0,
                bytes: &[],
            }),
        }
    }
    pub(crate) fn encode(&self, destination: &mut [u8]) -> Result<usize> {
        if self.serial == 0 {
            return Err(protocol());
        }
        let spec = &fragments()["kinds"][self.kind.name()];
        let fixed = number(&spec["body_fixed_bytes"])? as usize;
        let total = 5usize
            .checked_add(fixed)
            .and_then(|n| n.checked_add(self.bytes.len()))
            .ok_or_else(protocol)?;
        if self.bytes.len() < number(&spec["payload_min_bytes"])? as usize
            || self.bytes.len() > number(&spec["payload_max_bytes"])? as usize
            || self.kind != FragmentKind::Begin && self.reply_to != 0
            || matches!(self.kind, FragmentKind::Begin | FragmentKind::StopOutput)
                && self.offset != 0
            || total > destination.len()
        {
            return Err(protocol());
        }
        destination[..4].copy_from_slice(&((total - 4) as u32).to_be_bytes());
        destination[4] = self.kind.code()?;
        destination[5..13].copy_from_slice(&self.serial.to_be_bytes());
        match self.kind {
            FragmentKind::Begin => {
                destination[13..21].copy_from_slice(&self.reply_to.to_be_bytes());
                destination[21..23].copy_from_slice(&(self.bytes.len() as u16).to_be_bytes());
                destination[23..total].copy_from_slice(self.bytes);
            }
            FragmentKind::Data | FragmentKind::Abort => {
                destination[13..17].copy_from_slice(&self.offset.to_be_bytes());
                destination[17..total].copy_from_slice(self.bytes);
            }
            FragmentKind::StopOutput => {}
        }
        Ok(total)
    }
}

/// One compact association slot. A full channel separately prepays each live
/// request/reply and payload; abandoned input still consumes exact offsets.
#[derive(Debug)]
pub(crate) struct MessageInput {
    pub(crate) serial: u64,
    pub(crate) reply_to: u64,
    pub(crate) header: ApplicationHeader,
    next: u32,
    aborted: bool,
}
impl MessageInput {
    pub(crate) fn begin(fragment: Fragment<'_>) -> Result<Self> {
        if fragment.kind != FragmentKind::Begin {
            return Err(protocol());
        }
        let header = ApplicationHeader::decode(fragment.bytes)?;
        if header.is_response() != (fragment.reply_to != 0) {
            return Err(protocol());
        }
        Ok(Self {
            serial: fragment.serial,
            reply_to: fragment.reply_to,
            header,
            next: 0,
            aborted: false,
        })
    }
    pub(crate) fn data(&mut self, fragment: Fragment<'_>) -> Result<()> {
        if fragment.kind != FragmentKind::Data
            || fragment.serial != self.serial
            || self.aborted
            || fragment.offset != self.next
        {
            return Err(protocol());
        }
        let end = u64::from(self.next)
            .checked_add(fragment.bytes.len() as u64)
            .ok_or_else(protocol)?;
        if end > self.header.uint(3)? {
            return Err(protocol());
        }
        self.next = end as u32;
        Ok(())
    }
    pub(crate) fn abort(&mut self, fragment: Fragment<'_>) -> Result<()> {
        if fragment.kind != FragmentKind::Abort
            || fragment.serial != self.serial
            || fragment.offset != self.next
            || self.complete()
            || self.aborted
        {
            return Err(protocol());
        }
        self.aborted = true;
        Ok(())
    }
    pub(crate) fn complete(&self) -> bool {
        !self.aborted && self.header.uint(3).ok() == Some(u64::from(self.next))
    }
}

pub(crate) fn execution_digest(
    contract: &[u8],
    header: &ApplicationHeader,
    payload: &[u8],
) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    if header.is_response() || payload.len() != header.payload_bytes()? || !header.has(1) {
        return Err(protocol());
    }
    let domain = parsed(codec::wire_domain("execution_request_digest"))?;
    if domain["operation"] != "sha256" {
        return Err(protocol());
    }
    let hex = domain["label_bytes"].as_str().ok_or_else(protocol)?;
    let mut label = [0u8; 128];
    if hex.len() % 2 != 0 || hex.len() / 2 > label.len() {
        return Err(protocol());
    }
    for (index, chunk) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let n = std::str::from_utf8(chunk).map_err(|_| protocol())?;
        label[index] = u8::from_str_radix(n, 16).map_err(|_| protocol())?;
    }
    let mut hash = Sha256::new();
    hash.update(&label[..hex.len() / 2]);
    for part in domain["input_schema"]["parts"]
        .as_array()
        .ok_or_else(protocol)?
    {
        let name = part["name"].as_str().ok_or_else(protocol)?;
        let encoding = part["encoding"].as_str().ok_or_else(protocol)?;
        match (name, encoding) {
            ("contract", "lp-map") => {
                hash.update((contract.len() as u32).to_be_bytes());
                hash.update(contract);
            }
            ("operation_id", "lp-bytes") => {
                hash.update(32u32.to_be_bytes());
                hash.update(header.bytes(1)?);
            }
            ("payload", "lp-bytes") => {
                hash.update((payload.len() as u32).to_be_bytes());
                hash.update(payload);
            }
            _ => {
                let id = match name {
                    "message_kind" => 0,
                    "type_id" => 2,
                    "deadline_at_ms" => 5,
                    "admission_mode" => 7,
                    "response_limit_bytes" => 8,
                    _ => return Err(protocol()),
                };
                let width = match encoding {
                    "u8" => 1,
                    "u32" => 4,
                    "u64" => 8,
                    _ => return Err(protocol()),
                };
                let value = header.uint(id)?;
                if width < 8 && value >= 1u64 << (width * 8) {
                    return Err(protocol());
                }
                hash.update(&value.to_be_bytes()[8 - width..]);
            }
        }
    }
    Ok(hash.finalize().into())
}
