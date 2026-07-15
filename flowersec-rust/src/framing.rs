use crate::defaults::MAX_JSON_FRAME_BYTES;
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum FramingError {
    #[error("frame exceeds configured limit")]
    TooLarge,
    #[error("invalid JSON frame")]
    InvalidJson(#[from] serde_json::Error),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
}

pub async fn write_json_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FramingError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let payload = serde_json::to_vec(value)?;
    if payload.len() > u32::MAX as usize {
        return Err(FramingError::TooLarge);
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_json_frame<R, T>(reader: &mut R, max_bytes: usize) -> Result<T, FramingError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let max_bytes = if max_bytes == 0 {
        MAX_JSON_FRAME_BYTES
    } else {
        max_bytes
    };
    let length = reader.read_u32().await? as usize;
    if length > max_bytes {
        return Err(FramingError::TooLarge);
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

pub async fn write_chunk<W>(writer: &mut W, payload: &[u8]) -> Result<(), FramingError>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > u32::MAX as usize {
        return Err(FramingError::TooLarge);
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(payload).await?;
    Ok(())
}

pub async fn read_chunk<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, FramingError>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u32().await? as usize;
    if length > max_bytes {
        return Err(FramingError::TooLarge);
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(payload)
}
