//! Locally installed heterogeneous error decoders. Remote error directories
//! describe bounded bytes and never install application code or schemas.
use crate::{
    ApplicationErrorDefinition, ApplicationInvocationContext, AsyncMessageCodec, MessageCodec,
    MessageCodecIdentity, ServiceError, ServiceFailure,
};
use async_trait::async_trait;
use futures_util::FutureExt;
use std::{any::Any, fmt, panic::AssertUnwindSafe, sync::Arc};
type Result<T> = std::result::Result<T, ServiceError>;
#[async_trait]
trait Decoder: Send + Sync {
    async fn decode(
        &self,
        bytes: Arc<Vec<u8>>,
        context: ApplicationInvocationContext,
    ) -> Result<DecodedApplicationError>;
}
struct SyncDecoder<T> {
    codec: Arc<dyn MessageCodec<T>>,
}
struct AsyncDecoder<T> {
    codec: Arc<dyn AsyncMessageCodec<T>>,
}
#[async_trait]
impl<T: Send + 'static> Decoder for SyncDecoder<T> {
    async fn decode(
        &self,
        bytes: Arc<Vec<u8>>,
        context: ApplicationInvocationContext,
    ) -> Result<DecodedApplicationError> {
        let codec = self.codec.clone();
        // Waiting cancellation never drops the original callback. Its native
        // task, input, invocation and result allowance survive actual exit.
        tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                codec.decode_with_context(&bytes, &context)
            }))
            .unwrap_or_else(|_| Err(ServiceError(ServiceFailure::DecodeFailed)))
            .map(|value| DecodedApplicationError {
                value: Box::new(value),
            })
        })
        .await
        .map_err(|_| ServiceError(ServiceFailure::DecodeFailed))?
    }
}
#[async_trait]
impl<T: Send + 'static> Decoder for AsyncDecoder<T> {
    async fn decode(
        &self,
        bytes: Arc<Vec<u8>>,
        context: ApplicationInvocationContext,
    ) -> Result<DecodedApplicationError> {
        AssertUnwindSafe(self.codec.decode(&bytes, context))
            .catch_unwind()
            .await
            .unwrap_or_else(|_| Err(ServiceError(ServiceFailure::DecodeFailed)))
            .map(|value| DecodedApplicationError {
                value: Box::new(value),
            })
    }
}
/// A finite trusted local codec capture for one exact business error definition.
#[derive(Clone)]
pub struct ApplicationErrorCodec {
    definition: ApplicationErrorDefinition,
    allowance: u64,
    decoder: Arc<dyn Decoder>,
}
impl fmt::Debug for ApplicationErrorCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApplicationErrorCodec")
            .field("definition", &self.definition)
            .finish_non_exhaustive()
    }
}
impl ApplicationErrorCodec {
    pub fn synchronous<T: Send + 'static>(
        definition: ApplicationErrorDefinition,
        codec: Arc<dyn MessageCodec<T>>,
    ) -> Result<Self> {
        Self::check(&definition, codec.definition(), codec.application_bytes())?;
        Ok(Self {
            allowance: codec.application_bytes(),
            definition,
            decoder: Arc::new(SyncDecoder { codec }),
        })
    }
    pub fn asynchronous<T: Send + 'static>(
        definition: ApplicationErrorDefinition,
        codec: Arc<dyn AsyncMessageCodec<T>>,
    ) -> Result<Self> {
        Self::check(&definition, codec.definition(), codec.application_bytes())?;
        Ok(Self {
            allowance: codec.application_bytes(),
            definition,
            decoder: Arc::new(AsyncDecoder { codec }),
        })
    }
    fn check(
        definition: &ApplicationErrorDefinition,
        message: &crate::MessageDefinition,
        allowance: u64,
    ) -> Result<()> {
        if definition.code == 0
            || definition.message != *message
            || definition.max_payload_bytes > message.max_message_bytes()
            || allowance == 0
            || allowance > 1 << 30
        {
            return Err(ServiceError(ServiceFailure::ConfigurationCapacity));
        }
        Ok(())
    }
    pub fn definition(&self) -> &ApplicationErrorDefinition {
        &self.definition
    }
    pub fn identity(&self) -> MessageCodecIdentity {
        MessageCodecIdentity::from(&self.definition.message)
    }
    pub(crate) fn allowance(&self) -> u64 {
        self.allowance
    }
    pub(crate) async fn decode(
        &self,
        bytes: Arc<Vec<u8>>,
        context: ApplicationInvocationContext,
    ) -> Result<DecodedApplicationError> {
        if bytes.len() > self.definition.max_payload_bytes as usize {
            return Err(ServiceError(ServiceFailure::DecodeFailed));
        }
        self.decoder.decode(bytes, context).await
    }
}
/// One known error value produced by its original local decoder invocation.
pub struct DecodedApplicationError {
    value: Box<dyn Any + Send>,
}
impl fmt::Debug for DecodedApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DecodedApplicationError { <application value> }")
    }
}
impl DecodedApplicationError {
    pub fn is<T: Any>(&self) -> bool {
        self.value.is::<T>()
    }
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.value.downcast_ref()
    }
    pub fn into_value<T: Any>(self) -> std::result::Result<T, Self> {
        match self.value.downcast::<T>() {
            Ok(value) => Ok(*value),
            Err(value) => Err(Self { value }),
        }
    }
}
