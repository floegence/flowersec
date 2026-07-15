#![no_main]

use async_trait::async_trait;
use flowersec::yamux::{ByteDuplex, Mode, YamuxError, YamuxLimits, YamuxSession};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug)]
struct FuzzDuplex {
    input: Mutex<Option<Vec<u8>>>,
}

#[async_trait]
impl ByteDuplex for FuzzDuplex {
    async fn read(&self) -> Result<Vec<u8>, YamuxError> {
        self.input
            .lock()
            .await
            .take()
            .ok_or_else(|| YamuxError::Transport("fuzz input exhausted".to_owned()))
    }

    async fn write(&self, _bytes: &[u8]) -> Result<(), YamuxError> {
        Ok(())
    }

    async fn close(&self) -> Result<(), YamuxError> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("build fuzz runtime");
    runtime.block_on(async {
        let duplex = Arc::new(FuzzDuplex {
            input: Mutex::new(Some(data.to_vec())),
        });
        if let Ok(session) = YamuxSession::new(duplex, Mode::Server, YamuxLimits::default()) {
            session.wait_closed().await;
        }
    });
});
