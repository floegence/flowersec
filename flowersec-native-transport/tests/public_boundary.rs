use std::{fmt::Debug, future::Future, net::SocketAddr};

use flowersec_native_transport::{
    ApplicationClose, Cancellation, DatagramSendOutcome, PathProfile, RawQuicClientConfig,
    RawQuicError, RawQuicLimits, RawQuicListener, RawQuicServerConfig, RawQuicSession,
    RawQuicStream,
};

#[test]
fn public_driver_boundary_is_flowersec_owned() {
    fn debug<T: Debug>() {}
    debug::<ApplicationClose>();
    debug::<Cancellation>();
    debug::<DatagramSendOutcome>();
    debug::<PathProfile>();
    debug::<RawQuicClientConfig>();
    debug::<RawQuicError>();
    debug::<RawQuicLimits>();
    debug::<RawQuicListener>();
    debug::<RawQuicServerConfig>();
    debug::<RawQuicSession>();
    debug::<RawQuicStream>();

    let _: fn(SocketAddr, RawQuicServerConfig) -> Result<RawQuicListener, RawQuicError> =
        RawQuicListener::bind;
    let _: fn() -> Cancellation = Cancellation::new;
    let _: fn(&Cancellation) = Cancellation::cancel;
}

#[test]
fn async_public_operations_do_not_return_implementation_types() {
    fn is_future<T, F: Future<Output = T>>(_: F) {}
    let cancellation = Cancellation::new();
    let stream = None::<RawQuicStream>;
    if let Some(stream) = stream {
        is_future(stream.read(1, &cancellation));
        is_future(stream.write(vec![1], &cancellation));
        is_future(stream.close_write(&cancellation));
        is_future(stream.stop_sending());
        is_future(stream.reset());
    }
}
