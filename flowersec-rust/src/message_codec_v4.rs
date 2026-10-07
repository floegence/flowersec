//! SDK byte and UTF-8 implementations are concrete types. Application trait
//! implementations cannot claim the SDK's private behavior classification.
use crate::service_contract::{MessageCodec, MessageDefinition, ServiceError, ServiceFailure};
#[derive(Clone, Debug)]
pub struct BytesMessageCodec {
    definition: MessageDefinition,
}
impl BytesMessageCodec {
    pub fn new(definition: MessageDefinition) -> Self {
        Self { definition }
    }
}
impl MessageCodec<Vec<u8>> for BytesMessageCodec {
    fn definition(&self) -> &MessageDefinition {
        &self.definition
    }
    fn application_bytes(&self) -> u64 {
        1
    }
    fn encode(&self, value: &Vec<u8>, destination: &mut [u8]) -> Result<usize, ServiceError> {
        if value.len() > self.definition.max_message_bytes() as usize
            || value.len() > destination.len()
        {
            return Err(ServiceError(ServiceFailure::EncodeFailed));
        }
        destination[..value.len()].copy_from_slice(value);
        Ok(value.len())
    }
    fn decode(&self, source: &[u8]) -> Result<Vec<u8>, ServiceError> {
        if source.len() > self.definition.max_message_bytes() as usize {
            return Err(ServiceError(ServiceFailure::DecodeFailed));
        }
        Ok(source.to_vec())
    }
}
#[derive(Clone, Debug)]
pub struct UTF8MessageCodec {
    definition: MessageDefinition,
}
impl UTF8MessageCodec {
    pub fn new(definition: MessageDefinition) -> Self {
        Self { definition }
    }
}
impl MessageCodec<String> for UTF8MessageCodec {
    fn definition(&self) -> &MessageDefinition {
        &self.definition
    }
    fn application_bytes(&self) -> u64 {
        1
    }
    fn encode(&self, value: &String, destination: &mut [u8]) -> Result<usize, ServiceError> {
        if value.len() > self.definition.max_message_bytes() as usize
            || value.len() > destination.len()
        {
            return Err(ServiceError(ServiceFailure::EncodeFailed));
        }
        destination[..value.len()].copy_from_slice(value.as_bytes());
        Ok(value.len())
    }
    fn decode(&self, source: &[u8]) -> Result<String, ServiceError> {
        if source.len() > self.definition.max_message_bytes() as usize {
            return Err(ServiceError(ServiceFailure::DecodeFailed));
        }
        std::str::from_utf8(source)
            .map(str::to_owned)
            .map_err(|_| ServiceError(ServiceFailure::DecodeFailed))
    }
}
#[derive(Clone, Debug)]
pub(crate) struct ResumeResultCodec {
    definition: MessageDefinition,
}
impl ResumeResultCodec {
    pub(crate) fn new(definition: MessageDefinition) -> Self {
        Self { definition }
    }
}
impl MessageCodec<crate::ApplicationResumeResult> for ResumeResultCodec {
    fn definition(&self) -> &MessageDefinition {
        &self.definition
    }
    fn application_bytes(&self) -> u64 {
        8192
    }
    fn encode(
        &self,
        value: &crate::ApplicationResumeResult,
        destination: &mut [u8],
    ) -> Result<usize, ServiceError> {
        let encoded = value.encoded()?;
        if encoded.len() > destination.len()
            || encoded.len() > self.definition.max_message_bytes() as usize
        {
            return Err(ServiceError(ServiceFailure::EncodeFailed));
        }
        destination[..encoded.len()].copy_from_slice(&encoded);
        Ok(encoded.len())
    }
    fn decode(&self, source: &[u8]) -> Result<crate::ApplicationResumeResult, ServiceError> {
        if source.len() > self.definition.max_message_bytes() as usize {
            return Err(ServiceError(ServiceFailure::DecodeFailed));
        }
        crate::ApplicationResumeResult::capture(source)
    }
}
pub(crate) fn controlled<T: 'static>(codec: &dyn MessageCodec<T>) -> bool {
    let implementation = std::any::Any::type_id(codec);
    implementation == std::any::TypeId::of::<ResumeResultCodec>()
        || implementation == std::any::TypeId::of::<BytesMessageCodec>()
        || implementation == std::any::TypeId::of::<UTF8MessageCodec>()
}
