use std::{
    error::Error,
    fs::File,
    io::Read,
    num::NonZeroUsize,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use flowersec::{
    Acceptor, AcceptorOptions, Artifact, ArtifactLease, ArtifactSpendError, DirectAuthorizer,
    DirectHandlers, RpcError, RpcHandler, SessionHandlerOptions, SessionHandlers,
    WebSocketAcceptorOptions,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

struct Echo;

const WIDE_DONE: &str = "wide-rpc-complete";

pub async fn serve_wide(
    session: &dyn flowersec::Session,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    super::parity::exercise_wide(session).await?;
    session
        .rpc()
        .notify(super::NOTIFICATION_TYPE_ID, json!({"value": WIDE_DONE}))
        .await?;
    Ok(())
}

pub fn echo_handlers(
    done: Option<oneshot::Sender<()>>,
    binary: Option<super::large_rpc::BinaryEcho>,
) -> Result<flowersec::RpcHandlers, flowersec::HandlerRegistrationError> {
    let mut methods = super::parity::Registrations::default();
    for id in [super::ECHO_RPC_TYPE_ID, 7003, 7005] {
        methods.call(id, Echo)?;
    }
    methods.notification(
        super::NOTIFICATION_TYPE_ID,
        EchoNotification(std::sync::Mutex::new(done)),
    )?;
    if let Some(binary) = binary {
        methods.call(super::parity::LARGE_ECHO_METHOD, binary)?;
    }
    methods.finish()
}

struct EchoNotification(std::sync::Mutex<Option<oneshot::Sender<()>>>);

#[async_trait]
impl flowersec::NotificationHandler for EchoNotification {
    async fn handle_notification(&self, _: u32, value: Value) -> Result<(), RpcError> {
        if !value.is_object() {
            return Err(RpcError::new(400, None).unwrap());
        }
        if value == json!({"value": WIDE_DONE})
            && let Some(done) = self.0.lock().unwrap().take()
        {
            let _ = done.send(());
        }
        Ok(())
    }
}

pub struct EchoStream;

#[async_trait]
impl flowersec::StreamHandler for EchoStream {
    async fn handle(
        &self,
        incoming: &flowersec::IncomingStream,
        cancellation: CancellationToken,
    ) -> Result<(), flowersec::SessionError> {
        cancellation
            .run_until_cancelled(async {
                let stream = incoming.stream();
                super::read_exact_message(stream, b"hello").await?;
                super::write_all(stream, bytes::Bytes::from_static(b"world")).await
            })
            .await
            .ok_or(flowersec::SessionError::Canceled)?
    }
}

#[async_trait]
impl RpcHandler for Echo {
    async fn call(&self, _: u32, request: Value) -> Result<Value, RpcError> {
        Ok(request)
    }
    async fn notify(&self, _: u32, _: Value) -> Result<(), RpcError> {
        Err(RpcError::new(400, Some("Echo requires a reply".into())).unwrap())
    }
}

pub(crate) struct ApprovalStore {
    pub(crate) directory: PathBuf,
    pub(crate) handlers: DirectHandlers,
    pub(crate) call_large_echo: bool,
}

pub(crate) fn read_approval(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(65_537).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[async_trait]
impl DirectAuthorizer for ApprovalStore {
    async fn lookup(&self, channel: &str) -> Option<(ArtifactLease, DirectHandlers)> {
        if channel.is_empty()
            || !channel
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.'))
        {
            return None;
        }
        let approved = self.directory.join(format!("{channel}.json"));
        let spent = self.directory.join(format!("{channel}.spent"));
        let material = tokio::task::spawn_blocking({
            let path = approved.clone();
            move || read_approval(&path)
        })
        .await
        .ok()?
        .ok()?;
        let artifact = Artifact::parse(&material).ok()?;
        let lease = ArtifactLease::new(artifact, move || async move {
            tokio::task::spawn_blocking(move || {
                // Immutable, private approvals on one filesystem. Link creation
                // claims the currently published inode without replacing a receipt.
                std::fs::hard_link(&approved, &spent)
                    .map_err(|_| ArtifactSpendError::CommitFailed)?;
                File::open(&spent)
                    .and_then(|file| file.sync_all())
                    .and_then(|()| super::sync_parent_directory(&spent))
                    .map_err(|_| ArtifactSpendError::CommitFailed)?;
                if read_approval(&spent).map_err(|_| ArtifactSpendError::CommitFailed)? != material
                {
                    return Err(ArtifactSpendError::CommitFailed);
                }
                Ok(())
            })
            .await
            .map_err(|_| ArtifactSpendError::CommitFailed)?
        });
        Some((lease, self.handlers.clone()))
    }

    async fn connected(&self, _: &str, session: Arc<dyn flowersec::Session>) {
        if super::parity::wide_workload()
            && let Err(error) = serve_wide(session.as_ref()).await
        {
            eprintln!("reverse wide RPC: {error}");
            let _ = session.close().await;
            return;
        }
        if self.call_large_echo {
            match super::large_rpc::call(session.as_ref()).await {
                Ok(()) => println!("binary_echo=verified"),
                Err(error) => eprintln!("binary echo: {error}"),
            }
            if let Err(error) = session.close().await {
                eprintln!("session close: {error}");
            }
        }
    }
}

pub async fn serve(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn Error>> {
    let bind_address = super::required_argument(args.next(), "bind address")?.parse()?;
    let certificate_chain_der = vec![std::fs::read(super::required_argument(
        args.next(),
        "certificate DER",
    )?)?];
    let private_key_der = std::fs::read(super::required_argument(args.next(), "private key DER")?)?;
    let directory = PathBuf::from(super::required_argument(args.next(), "approval directory")?)
        .canonicalize()?;
    if !directory.is_dir() || args.next().is_some() {
        return Err(super::usage().into());
    }
    let large = super::large_rpc::Role::configured(super::large_rpc::Role::Serve)?;
    let frame_limit = super::frame_limit(large.is_some())?;
    let max_inbound_streams = std::env::var("FSEC_MAX_INBOUND_STREAMS")
        .unwrap_or_else(|_| "16".into())
        .parse()?;
    let accept_timeout = Duration::from_secs(10);
    let mut acceptor = if let Ok(origin) = std::env::var("FSEC_ORIGIN") {
        Acceptor::bind_websocket(WebSocketAcceptorOptions {
            bind_address,
            certificate_chain_der,
            private_key_der,
            allowed_origins: vec![origin],
            max_inbound_streams,
            accept_timeout,
        })?
    } else {
        Acceptor::bind(AcceptorOptions {
            bind_address,
            certificate_chain_der,
            private_key_der,
            max_inbound_streams,
            accept_timeout,
        })?
    };
    if let Some(limit) = frame_limit {
        acceptor = acceptor.with_rpc_frame_limit(limit);
    }
    if let Some(limit) = super::concurrency()? {
        acceptor = acceptor.with_rpc_concurrency(limit);
    }
    let mut handlers =
        SessionHandlers::new(SessionHandlerOptions::default())?.with_rpc_handlers(echo_handlers(
            None,
            (large == Some(super::large_rpc::Role::Serve))
                .then(super::large_rpc::BinaryEcho::default),
        )?);
    handlers.handle_stream(super::ECHO_STREAM_KIND, EchoStream)?;
    let store = ApprovalStore {
        directory,
        handlers: DirectHandlers::new(handlers),
        call_large_echo: large == Some(super::large_rpc::Role::Call),
    };
    println!("listening={}", acceptor.local_address()?);
    acceptor
        .serve(
            Arc::new(store),
            NonZeroUsize::new(64).unwrap(),
            CancellationToken::new(),
        )
        .await?;
    Ok(())
}
