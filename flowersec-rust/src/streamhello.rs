use crate::{
    defaults,
    generated::flowersec::rpc::v1::StreamHello,
    streamio::{self, StreamIoError},
    yamux::YamuxStream,
};

pub const VERSION: u32 = 1;
pub const RPC_KIND: &str = "rpc";

pub async fn write(stream: &YamuxStream, kind: &str) -> Result<(), StreamIoError> {
    if kind.trim().is_empty() {
        return Err(StreamIoError::Json(serde_json::Error::io(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "stream kind is empty"),
        )));
    }
    streamio::write_json(
        stream,
        &StreamHello {
            kind: kind.to_owned(),
            v: VERSION,
        },
    )
    .await
}

pub async fn read(stream: &YamuxStream, max_bytes: usize) -> Result<String, StreamIoError> {
    let hello: StreamHello = streamio::read_json(
        stream,
        if max_bytes == 0 {
            defaults::MAX_STREAM_HELLO_BYTES
        } else {
            max_bytes
        },
    )
    .await?;
    if hello.v != VERSION || hello.kind.trim().is_empty() {
        return Err(StreamIoError::Json(serde_json::Error::io(
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid stream hello"),
        )));
    }
    Ok(hello.kind)
}
