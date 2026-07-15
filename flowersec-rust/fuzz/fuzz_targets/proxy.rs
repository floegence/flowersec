#![no_main]

use flowersec::proxy::{
    HttpRequestMeta, HttpResponseMeta, WebSocketOp, WebSocketOpenMeta, WebSocketOpenResponse,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<HttpRequestMeta>(data);
    let _ = serde_json::from_slice::<HttpResponseMeta>(data);
    let _ = serde_json::from_slice::<WebSocketOpenMeta>(data);
    let _ = serde_json::from_slice::<WebSocketOpenResponse>(data);
    if let Some(operation) = data.first() {
        let _ = WebSocketOp::try_from(*operation);
    }
});
