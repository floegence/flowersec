use std::sync::Arc;

use flowersec::{NotificationSubscription, RpcPeer, SessionError};

fn compile_notification_contract(peer: &dyn RpcPeer) -> Result<(), SessionError> {
    let subscription = peer.subscribe_notification(7, Arc::new(|_payload| {}))?;
    subscription.cancel();
    Ok(())
}

#[test]
fn notification_subscription_public_shape_is_stable() {
    let _ = compile_notification_contract;
    let _ = std::mem::size_of::<NotificationSubscription>();
}
