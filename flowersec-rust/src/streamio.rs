use crate::{
    defaults,
    yamux::{YamuxError, YamuxStream},
};
use serde::{Serialize, de::DeserializeOwned};

#[derive(Debug, thiserror::Error)]
pub enum StreamIoError {
    #[error("stream frame exceeds configured limit")]
    TooLarge,
    #[error("stream JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("stream failed: {0}")]
    Yamux(#[from] YamuxError),
}

pub async fn write_json<T: Serialize + ?Sized>(
    stream: &YamuxStream,
    value: &T,
) -> Result<(), StreamIoError> {
    let payload = serde_json::to_vec(value)?;
    if payload.len() > u32::MAX as usize {
        return Err(StreamIoError::TooLarge);
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    stream.write(&frame).await?;
    Ok(())
}

pub async fn read_json<T: DeserializeOwned>(
    stream: &YamuxStream,
    max_bytes: usize,
) -> Result<T, StreamIoError> {
    let max_bytes = if max_bytes == 0 {
        defaults::MAX_JSON_FRAME_BYTES
    } else {
        max_bytes
    };
    let header = stream.read_exact(4).await?;
    let length = u32::from_be_bytes(header.try_into().expect("fixed header")) as usize;
    if length > max_bytes {
        return Err(StreamIoError::TooLarge);
    }
    let payload = stream.read_exact(length).await?;
    Ok(serde_json::from_slice(&payload)?)
}

pub async fn write_chunk(stream: &YamuxStream, payload: &[u8]) -> Result<(), StreamIoError> {
    if payload.len() > u32::MAX as usize {
        return Err(StreamIoError::TooLarge);
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write(&frame).await?;
    Ok(())
}

pub async fn read_chunk(stream: &YamuxStream, max_bytes: usize) -> Result<Vec<u8>, StreamIoError> {
    let header = stream.read_exact(4).await?;
    let length = u32::from_be_bytes(header.try_into().expect("fixed header")) as usize;
    if length > max_bytes {
        return Err(StreamIoError::TooLarge);
    }
    Ok(stream.read_exact(length).await?)
}
