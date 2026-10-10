//! A bounded message adapter over the existing authenticated business Stream.
//! The immutable definition is local registration data, never admission proof.
use crate::{
    ApplicationInvocationContext,
    api_v4::{CleanupStatus, ReadStreamStatus, StreamReadPermit, WriteOperation},
    application_executor_v4::ApplicationGroup,
    codec_v4::{self as codec, Limits, Value},
    crypto_v4::{Metadata, OpenRequest, Session, Stream},
    environment_v4::{
        EnvironmentCharge, EnvironmentRoot, ResourceAccount, ResourceCharge, ResourceLimits,
    },
    message_codec_v4::controlled,
    service_contract::{MessageCodec, MessageDefinition, ServiceError, ServiceFailure},
    transport::ByteStream,
};
use async_trait::async_trait;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    marker::PhantomData,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    time::Instant,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, ServiceError>;
fn failure(code: ServiceFailure) -> ServiceError {
    ServiceError(code)
}
fn parse<T>(value: codec::Result<T>) -> Result<T> {
    value.map_err(|_| failure(ServiceFailure::ContractMismatch))
}
fn head(bytes: &mut Vec<u8>, major: u8, value: u64) {
    codec::encode_head(bytes, major, value);
}
fn blob(bytes: &mut Vec<u8>, value: &[u8]) {
    head(bytes, 2, value.len() as u64);
    bytes.extend_from_slice(value);
}
fn text(bytes: &mut Vec<u8>, value: &str) {
    head(bytes, 3, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}
struct DefinitionBody {
    kind: String,
    revision: String,
    outgoing: MessageDefinition,
    incoming: MessageDefinition,
    canonical: Vec<u8>,
    digest: [u8; 32],
    root: Arc<EnvironmentRoot>,
    _charge: EnvironmentCharge,
}
#[derive(Clone)]
pub struct MessageStreamDefinition(Arc<DefinitionBody>);
impl fmt::Debug for MessageStreamDefinition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageStreamDefinition")
            .field("kind", &self.0.kind)
            .field("revision", &self.0.revision)
            .finish()
    }
}
impl MessageStreamDefinition {
    pub fn kind(&self) -> &str {
        &self.0.kind
    }
    pub fn revision(&self) -> &str {
        &self.0.revision
    }
    pub fn digest(&self) -> [u8; 32] {
        self.0.digest
    }
    pub fn canonical(&self) -> &[u8] {
        &self.0.canonical
    }
    pub fn opener_to_acceptor(&self) -> &MessageDefinition {
        &self.0.outgoing
    }
    pub fn acceptor_to_opener(&self) -> &MessageDefinition {
        &self.0.incoming
    }
    pub(crate) fn import(root: &Arc<EnvironmentRoot>, canonical: &[u8]) -> Result<Self> {
        let charge = root.reserve_environment(ResourceLimits {
            sdk_bytes: 12288,
            items: 1,
            ..ResourceLimits::default()
        })?;
        let value = parse(codec::decode(
            canonical,
            "MessageStreamDefinition",
            Limits {
                bytes: 8192,
                nodes: 32,
            },
            None,
        ))?;
        let kind = parse(
            value
                .field("MessageStreamDefinition", "kind")
                .and_then(Value::text),
        )?
        .to_owned();
        if kind.starts_with("flowersec.")
            || kind.starts_with("flowersec/")
            || kind.trim() != kind
            || kind.is_empty()
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let revision = parse(
            value
                .field("MessageStreamDefinition", "revision")
                .and_then(Value::text),
        )?
        .to_owned();
        let direction = |name| -> Result<MessageDefinition> {
            let value = parse(value.field("MessageStreamDefinition", name))?;
            MessageDefinition::new(
                parse(value.b("MessageStreamDirection", "codec_schema_digest"))?,
                parse(
                    value
                        .field("MessageStreamDirection", "codec_revision")
                        .and_then(Value::text),
                )?
                .to_owned(),
                parse(value.u("MessageStreamDirection", "max_message_bytes"))? as u32,
            )
        };
        let outgoing = direction("opener_to_acceptor")?;
        let incoming = direction("acceptor_to_opener")?;
        let mut hash = Sha256::new();
        hash.update(b"flowersec/v4/typed-message-definition\0");
        hash.update((canonical.len() as u32).to_be_bytes());
        hash.update(canonical);
        Ok(Self(Arc::new(DefinitionBody {
            kind,
            revision,
            outgoing,
            incoming,
            canonical: canonical.to_vec(),
            digest: hash.finalize().into(),
            root: root.clone(),
            _charge: charge,
        })))
    }
    pub(crate) fn define(
        root: &Arc<EnvironmentRoot>,
        kind: &str,
        revision: &str,
        opener_to_acceptor: MessageDefinition,
        acceptor_to_opener: MessageDefinition,
    ) -> Result<Self> {
        let _workspace = root.reserve_environment(ResourceLimits {
            sdk_bytes: 8192,
            items: 1,
            ..ResourceLimits::default()
        })?;
        let mut canonical = Vec::with_capacity(8192);
        head(&mut canonical, 5, 4);
        head(&mut canonical, 0, 0);
        text(&mut canonical, kind);
        head(&mut canonical, 0, 1);
        text(&mut canonical, revision);
        for (index, direction) in [opener_to_acceptor, acceptor_to_opener]
            .into_iter()
            .enumerate()
        {
            head(&mut canonical, 0, index as u64 + 2);
            head(&mut canonical, 5, 3);
            head(&mut canonical, 0, 0);
            blob(&mut canonical, &direction.schema_digest());
            head(&mut canonical, 0, 1);
            text(&mut canonical, direction.revision());
            head(&mut canonical, 0, 2);
            head(&mut canonical, 0, direction.max_message_bytes() as u64);
        }
        Self::import(root, &canonical)
    }
    fn wrap(&self, application: &Metadata) -> Result<Metadata> {
        if application.encoded().len() > 4006 {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        let mut bytes = Vec::with_capacity(4096);
        head(&mut bytes, 5, 3);
        head(&mut bytes, 0, 0);
        text(&mut bytes, "flowersec/typed-message");
        head(&mut bytes, 0, 1);
        head(&mut bytes, 0, 1);
        head(&mut bytes, 0, 2);
        head(&mut bytes, 5, 2);
        // Deterministic CBOR text-map order compares encoded key length first.
        text(&mut bytes, "definition");
        blob(&mut bytes, &self.digest());
        text(&mut bytes, "application");
        blob(&mut bytes, application.encoded());
        Metadata::from_typed_encoded(&bytes).map_err(|_| failure(ServiceFailure::ContractMismatch))
    }
    pub fn application_metadata(&self, wrapper: &Metadata) -> Result<Metadata> {
        let value = parse(codec::decode(
            wrapper.encoded(),
            "TypedMessageMetadata",
            Limits {
                bytes: 4096,
                nodes: codec::TYPED_MESSAGE_METADATA_MAX_NODES,
            },
            None,
        ))?;
        let values = parse(value.field("TypedMessageMetadata", "values"))?;
        let mut digest = None;
        let mut application = None;
        let mut fields = parse(values.children())?;
        while let Some(key) = fields.next() {
            let key = parse(key.and_then(Value::text))?;
            let value = parse(fields.next().ok_or("truncated").and_then(|value| value))?;
            match key {
                "definition" => digest = Some(parse(value.bytes())?),
                "application" => application = Some(parse(value.bytes())?),
                _ => return Err(failure(ServiceFailure::ContractMismatch)),
            }
        }
        if digest != Some(self.0.digest.as_slice()) {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        Metadata::from_encoded(
            application.ok_or_else(|| failure(ServiceFailure::ContractMismatch))?,
        )
        .map_err(|_| failure(ServiceFailure::ContractMismatch))
    }
}
#[derive(Clone, Debug)]
pub struct MessageStreamOptions {
    pub assembly_timeout: Duration,
    pub send_timeout: Duration,
    pub cleanup_timeout: Duration,
}
impl Default for MessageStreamOptions {
    fn default() -> Self {
        Self {
            assembly_timeout: Duration::from_secs(30),
            send_timeout: Duration::from_secs(30),
            cleanup_timeout: Duration::from_secs(5),
        }
    }
}
impl MessageStreamOptions {
    fn check(&self) -> Result<()> {
        if [
            self.assembly_timeout,
            self.send_timeout,
            self.cleanup_timeout,
        ]
        .iter()
        .any(|duration| duration.is_zero() || *duration > Duration::from_secs(60))
        {
            return Err(failure(ServiceFailure::ConfigurationCapacity));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageReceiveTerminal {
    Open,
    Eof,
    Aborted,
    FramingFailed,
    DecodeFailed,
    AssemblyTimeout,
    Closed,
}
#[derive(Debug)]
pub struct EncodedMessage {
    pub payload: Option<Bytes>,
    pub definition: MessageDefinition,
    pub terminal: MessageReceiveTerminal,
}
#[derive(Debug)]
pub struct TypedMessage<T> {
    pub value: Option<T>,
    pub definition: MessageDefinition,
    pub terminal: MessageReceiveTerminal,
    _custody: Option<ResourceCharge>,
}
struct Received {
    payload: Zeroizing<Vec<u8>>,
    present: bool,
    terminal: MessageReceiveTerminal,
    _charge: Option<ResourceCharge>,
}
struct Decoded<I> {
    value: I,
    terminal: MessageReceiveTerminal,
    _charge: ResourceCharge,
}
struct InputState<I> {
    diagnostics: Option<Arc<crate::diagnostics_v4::DiagnosticActivity>>,
    ready: Option<Received>,
    typed: Option<Result<Decoded<I>>>,
    scheduled: bool,
    started: bool,
    terminal: MessageReceiveTerminal,
    demand: bool,
    waiting: bool,
}
struct SendJob<O> {
    value: Arc<O>,
    context: Option<ApplicationInvocationContext>,
    cancellation: CancellationToken,
    deadline: Instant,
    result: oneshot::Sender<Result<usize>>,
    _charge: Arc<ResourceCharge>,
    _entry: Arc<SendEntry>,
    diagnostics: Arc<crate::diagnostics_v4::DiagnosticActivity>,
}
struct Core<I, O> {
    stream: Mutex<Option<Arc<Stream>>>,
    account: ResourceAccount,
    group: ApplicationGroup,
    definition: MessageStreamDefinition,
    application: Metadata,
    inbound: Arc<dyn MessageCodec<I>>,
    outbound: Arc<dyn MessageCodec<O>>,
    incoming: MessageDefinition,
    outgoing: MessageDefinition,
    options: MessageStreamOptions,
    input: Mutex<InputState<I>>,
    #[cfg(test)]
    decode_return_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    sender: mpsc::Sender<SendJob<O>>,
    changed: Arc<Notify>,
    activated: AtomicBool,
    send_control: Mutex<SendControl>,
    send_entries: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    workers: AtomicUsize,
    handles: AtomicUsize,
    closed: AtomicBool,
    charge: Mutex<Option<Arc<ResourceCharge>>>,
    _capture_charge: Arc<ResourceCharge>,
    tail: crate::application_tails_v4::ApplicationTail,
    close_owner: fn(&Arc<Core<I, O>>),
    _types: PhantomData<I>,
}
pub struct TypedMessageStream<I, O>(Arc<Core<I, O>>);
impl<I, O> Clone for TypedMessageStream<I, O> {
    fn clone(&self) -> Self {
        self.0.handles.fetch_add(1, Ordering::AcqRel);
        Self(self.0.clone())
    }
}
impl<I, O> Drop for TypedMessageStream<I, O> {
    fn drop(&mut self) {
        if self.0.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            (self.0.close_owner)(&self.0);
        }
    }
}
impl<I, O> fmt::Debug for TypedMessageStream<I, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TypedMessageStream { <opaque> }")
    }
}
impl<I: Send + Sync + 'static, O: Send + Sync + 'static> TypedMessageStream<I, O> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Typed stream assembly takes both codecs and the original read permit, setup charge and callback tail."
    )]
    fn prepare(
        stream: Stream,
        definition: MessageStreamDefinition,
        application: Metadata,
        inbound: Arc<dyn MessageCodec<I>>,
        outbound: Arc<dyn MessageCodec<O>>,
        opener: bool,
        options: MessageStreamOptions,
        setup_charge: ResourceCharge,
    ) -> Result<Self> {
        options.check()?;
        let (incoming, outgoing) = if opener {
            (
                definition.acceptor_to_opener().clone(),
                definition.opener_to_acceptor().clone(),
            )
        } else {
            (
                definition.opener_to_acceptor().clone(),
                definition.acceptor_to_opener().clone(),
            )
        };
        if inbound.definition() != &incoming
            || outbound.definition() != &outgoing
            || inbound.application_bytes() == 0
            || outbound.application_bytes() == 0
            || inbound.application_bytes() > 1 << 30
            || outbound.application_bytes() > 1 << 30
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let account = stream.account();
        if !account.belongs_to(&definition.0.root) {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let group = account.application_group()?;
        let tail = stream
            .application_tail()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let (stream, permit) = stream
            .claim_typed()
            .map_err(|_| failure(ServiceFailure::ResultModeConflict))?;
        Ok(Self::prepared_core(
            Some(stream),
            account,
            group,
            definition,
            application,
            inbound,
            outbound,
            incoming,
            outgoing,
            options,
            setup_charge,
            permit,
            tail,
        ))
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Typed stream assembly takes both codecs and the original read permit, setup charge and callback tail."
    )]
    fn prepared_core(
        stream: Option<Stream>,
        account: ResourceAccount,
        group: ApplicationGroup,
        definition: MessageStreamDefinition,
        application: Metadata,
        inbound: Arc<dyn MessageCodec<I>>,
        outbound: Arc<dyn MessageCodec<O>>,
        incoming: MessageDefinition,
        outgoing: MessageDefinition,
        options: MessageStreamOptions,
        setup_charge: ResourceCharge,
        permit: StreamReadPermit,
        tail: crate::application_tails_v4::ApplicationTail,
    ) -> Self {
        let setup_charge = Arc::new(setup_charge);
        let (sender, receiver) = mpsc::channel(4);
        let core = Arc::new(Core {
            stream: Mutex::new(stream.map(Arc::new)),
            account,
            group,
            definition,
            application,
            inbound,
            outbound,
            incoming,
            outgoing,
            options,
            input: Mutex::new(InputState {
                diagnostics: None,
                ready: None,
                typed: None,
                scheduled: false,
                started: false,
                terminal: MessageReceiveTerminal::Open,
                demand: false,
                waiting: false,
            }),
            #[cfg(test)]
            decode_return_hook: Mutex::new(None),
            sender,
            changed: Arc::new(Notify::new()),
            send_control: Mutex::new(SendControl {
                sealed: false,
                pending: 0,
                fin_started: false,
                fin_result: None,
            }),
            send_entries: Arc::new(AtomicUsize::new(0)),
            activated: AtomicBool::new(false),
            cancellation: tail.cancellation(),
            tail,
            workers: AtomicUsize::new(2),
            handles: AtomicUsize::new(1),
            close_owner: Core::close,
            closed: AtomicBool::new(false),
            charge: Mutex::new(Some(setup_charge.clone())),
            _capture_charge: setup_charge,
            _types: PhantomData,
        });
        let reader = core.clone();
        tokio::spawn(async move {
            let _worker = Worker(reader.clone());
            reader.read_messages(permit).await;
            if reader.cancellation.is_cancelled() {
                reader.close();
            }
        });
        let writer = core.clone();
        tokio::spawn(async move {
            let _worker = Worker(writer.clone());
            writer.write_messages(receiver).await;
            if writer.cancellation.is_cancelled() {
                writer.close();
            }
        });
        Self(core)
    }
    fn activate(&self) {
        self.0.activated.store(true, Ordering::Release);
        self.0.changed.notify_waiters();
    }
    #[cfg(test)]
    pub(crate) fn set_decode_return_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .0
            .decode_return_hook
            .lock()
            .expect("decode return hook") = Some(hook);
    }
    pub fn definition(&self) -> &MessageStreamDefinition {
        &self.0.definition
    }
    pub fn application_metadata(&self) -> &Metadata {
        &self.0.application
    }
    pub async fn send(
        &self,
        value: Arc<O>,
        context: Option<ApplicationInvocationContext>,
        cancellation: &CancellationToken,
    ) -> Result<usize> {
        self.0.check()?;
        let retained = retained_bytes(value.as_ref());
        let charge = Arc::new(self.0.account.reserve(ResourceLimits {
            sdk_bytes: self.0.outbound.application_bytes()
                + self.0.outgoing.max_message_bytes() as u64 * 2
                + retained
                + 8192,
            items: 2,
            tasks: 1,
            ..ResourceLimits::default()
        })?);
        let entries =
            self.0
                .send_entries
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < 4).then_some(count + 1)
                });
        if entries.is_err() {
            return Err(failure(ServiceFailure::ResourceExhausted));
        }
        let entry = Arc::new(SendEntry {
            count: self.0.send_entries.clone(),
            changed: self.0.changed.clone(),
        });
        let deadline = Instant::now() + self.0.options.send_timeout;
        let original = cancellation.child_token();
        let observer = SendObserver(original.clone());
        let (sender, receiver) = oneshot::channel();
        let diagnostics = self
            .0
            .account
            .diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        // Rejected admission must release its charge after the security lock.
        let mut job = Some(SendJob {
            value,
            context,
            cancellation: original.clone(),
            deadline,
            result: sender,
            _charge: charge,
            _entry: entry,
            diagnostics: diagnostics.clone(),
        });
        self.0.account.with_security(|| {
            let mut control = self.0.send_control.lock().expect("typed send control");
            if control.sealed || self.0.closed.load(Ordering::Acquire) || original.is_cancelled() {
                return Err(failure(ServiceFailure::Closed));
            }
            let permit = self
                .0
                .sender
                .try_reserve()
                .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
            permit.send(job.take().expect("original typed send"));
            control.pending += 1;
            Ok(())
        })??;
        let outcome = tokio::select! { result = receiver => result.unwrap_or_else(|_| Err(failure(ServiceFailure::Closed))),
        _ = cancellation.cancelled() => Err(failure(ServiceFailure::Canceled)),
        _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)),
        _ = self.0.cancellation.cancelled() => Err(failure(ServiceFailure::Closed)) };
        drop(observer);
        // The queued job retains the original context until its physical send exits.
        // Canceling this wait does not invent a second send outcome.
        outcome
    }
    pub async fn receive_encoded(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<EncodedMessage> {
        let message = self.receive_owned(cancellation).await?;
        self.0.complete_receive_diagnostics(message.terminal, None);
        let definition = self.0.incoming.clone();
        let terminal = message.terminal;
        let bytes = if message.present {
            Some(Bytes::from_owner(MessagePayload {
                payload: message.payload,
                _charge: message._charge,
            }))
        } else {
            None
        };
        Ok(EncodedMessage {
            payload: bytes,
            definition,
            terminal,
        })
    }
    pub async fn receive(
        &self,
        context: Option<ApplicationInvocationContext>,
        cancellation: &CancellationToken,
    ) -> Result<TypedMessage<I>> {
        enum ReceiveAction<I> {
            Decoded(Result<Decoded<I>>),
            Decode,
            Terminal(MessageReceiveTerminal),
        }

        if self.0.closed.load(Ordering::Acquire) {
            if cancellation.is_cancelled() {
                return Err(failure(ServiceFailure::Canceled));
            }
            return Ok(TypedMessage {
                value: None,
                definition: self.0.incoming.clone(),
                terminal: self.0.input.lock().expect("typed input").terminal,
                _custody: None,
            });
        }
        self.0.check()?;
        {
            let mut input = self.0.input.lock().expect("typed input");
            if input.waiting {
                return Err(failure(ServiceFailure::ResultModeConflict));
            }
            input.waiting = true;
            if input.diagnostics.is_none() {
                input.diagnostics = Some(
                    self.0
                        .account
                        .diagnostic_activity(crate::DiagnosticPhase::Application, 1),
                );
            }
            input.demand = true;
        }
        let _wait = ReceiveWait(self.0.clone());
        self.0.changed.notify_waiters();
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let terminal = {
                let input = self.0.input.lock().expect("typed input");
                (input.ready.is_none()
                    && input.typed.is_none()
                    && !input.started
                    && input.terminal != MessageReceiveTerminal::Open)
                    .then_some(input.terminal)
            };
            if let Some(terminal) = terminal {
                self.0.complete_receive_diagnostics(terminal, None);
                return Ok(TypedMessage {
                    value: None,
                    definition: self.0.incoming.clone(),
                    terminal,
                    _custody: None,
                });
            }
            let action = self.0.account.with_security(|| {
                let mut input = self.0.input.lock().expect("typed input");
                if cancellation.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                if let Some(value) = input.typed.take() {
                    input.started = false;
                    input.scheduled = false;
                    input.demand = false;
                    return Ok(Some(ReceiveAction::Decoded(value)));
                }
                if input.ready.is_some() && !input.scheduled && !input.started {
                    return Ok(Some(ReceiveAction::Decode));
                }
                // EOF can arrive after the terminal fast path above. Observe
                // it under the same input lock as decoded-message selection,
                // after the original decoder has physically returned.
                if input.terminal != MessageReceiveTerminal::Open
                    && input.ready.is_none()
                    && !input.started
                {
                    return Ok(Some(ReceiveAction::Terminal(input.terminal)));
                }
                Ok(None)
            })??;
            match action {
                Some(ReceiveAction::Terminal(terminal)) => {
                    self.0.complete_receive_diagnostics(terminal, None);
                    return Ok(TypedMessage {
                        value: None,
                        definition: self.0.incoming.clone(),
                        terminal,
                        _custody: None,
                    });
                }
                Some(ReceiveAction::Decoded(value)) => {
                    if let Err(error) = &value {
                        self.0.complete_receive_diagnostics(
                            MessageReceiveTerminal::Aborted,
                            Some(*error),
                        );
                        // Concrete SDK decoders validate private wire structure.
                        // Their failure terminates this stream before another
                        // prefix can be consumed; application decoder errors
                        // remain the outcome of only their original message.
                        if controlled(self.0.inbound.as_ref()) {
                            self.0.terminal(MessageReceiveTerminal::DecodeFailed);
                            self.0.close();
                        }
                    }
                    let value = value?;
                    self.0.complete_receive_diagnostics(value.terminal, None);
                    self.0.changed.notify_waiters();
                    return Ok(TypedMessage {
                        value: Some(value.value),
                        definition: self.0.incoming.clone(),
                        terminal: value.terminal,
                        _custody: Some(value._charge),
                    });
                }
                Some(ReceiveAction::Decode) => {
                    let codec = self.0.inbound.clone();
                    let charge = self.0.account.reserve(ResourceLimits {
                        sdk_bytes: codec.application_bytes()
                            + self.0.incoming.max_message_bytes() as u64,
                        items: 1,
                        tasks: u64::from(!controlled(codec.as_ref())),
                        ..ResourceLimits::default()
                    })?;
                    if controlled(codec.as_ref()) {
                        let completion = self.0.group.completion_owner(context.as_ref())?;
                        let position = tokio::select! {
                            position = completion.position() => position?,
                            _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                            _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                        };
                        let invocation = position.enter()?;
                        let message = self.0.account.with_security(|| {
                            let mut input = self.0.input.lock().expect("typed input");
                            if cancellation.is_cancelled() || self.0.closed.load(Ordering::Acquire)
                            {
                                return Err(failure(ServiceFailure::Canceled));
                            }
                            let message = input
                                .ready
                                .take()
                                .ok_or_else(|| failure(ServiceFailure::ResultModeConflict))?;
                            input.started = true;
                            Ok(message)
                        })??;
                        let value = codec
                            .decode_with_context(&message.payload, &invocation.context())
                            .map(|value| Decoded {
                                value,
                                terminal: message.terminal,
                                _charge: charge,
                            });
                        drop(message);
                        drop(invocation);
                        drop(position);
                        drop(completion);
                        self.0.publish_decoded(value);
                        continue;
                    }
                    let completion = self.0.group.completion_owner(context.as_ref())?;
                    let position = tokio::select! {
                        position = completion.position() => position?,
                        _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                        _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                    };
                    self.0.account.with_security(|| {
                        let mut input = self.0.input.lock().expect("typed input");
                        if cancellation.is_cancelled() || input.ready.is_none() {
                            return Err(failure(ServiceFailure::Canceled));
                        }
                        input.scheduled = true;
                        Ok(())
                    })??;
                    let weak = Arc::downgrade(&self.0);
                    let account = self.0.account.clone();
                    self.0.workers.fetch_add(1, Ordering::AcqRel);
                    let lifetime = self.0.clone();
                    tokio::task::spawn_blocking(move || {
                        let _worker = Worker(lifetime);
                        let invocation = match position.enter() {
                            Ok(invocation) => invocation,
                            Err(error) => {
                                drop(charge);
                                drop(position);
                                drop(completion);
                                if let Some(owner) = weak.upgrade() {
                                    let retired = {
                                        let mut input = owner.input.lock().expect("typed input");
                                        // This original message owns the entry
                                        // failure. Keep it scheduled until that
                                        // one outcome is claimed by receive.
                                        input.started = true;
                                        input.ready.take()
                                    };
                                    drop(retired);
                                    owner.publish_decoded(Err(error.into()));
                                }
                                return;
                            }
                        };
                        let message = account.with_security(|| {
                            let owner = weak
                                .upgrade()
                                .ok_or_else(|| failure(ServiceFailure::Closed))?;
                            if owner.closed.load(Ordering::Acquire) {
                                return Err(failure(ServiceFailure::Closed));
                            }
                            let mut input = owner.input.lock().expect("typed input");
                            let message = input.ready.take();
                            if message.is_some() {
                                input.started = true;
                            } else {
                                input.scheduled = false;
                            }
                            Ok(message)
                        });
                        let message = match message {
                            Ok(Ok(Some(message))) => message,
                            _ => {
                                drop(charge);
                                drop(invocation);
                                drop(position);
                                drop(completion);
                                if let Some(owner) = weak.upgrade() {
                                    owner.input.lock().expect("typed input").scheduled = false;
                                    owner.changed.notify_waiters();
                                }
                                return;
                            }
                        };
                        let value = std::panic::catch_unwind(AssertUnwindSafe(|| {
                            codec.decode_with_context(&message.payload, &invocation.context())
                        }))
                        .unwrap_or_else(|_| Err(failure(ServiceFailure::DecodeFailed)));
                        let result = value.map(|value| Decoded {
                            value,
                            terminal: message.terminal,
                            _charge: charge,
                        });
                        #[cfg(test)]
                        if let Some(owner) = weak.upgrade() {
                            let hook = owner
                                .decode_return_hook
                                .lock()
                                .expect("decode return hook")
                                .take();
                            if let Some(hook) = hook {
                                hook();
                            }
                        }
                        // Finish the original input and executor responsibility
                        // before an observer may request the following prefix.
                        drop(message);
                        drop(invocation);
                        drop(position);
                        drop(completion);
                        if let Some(owner) = weak.upgrade() {
                            owner.publish_decoded(result);
                        }
                    });
                }
                None => {}
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)) }
        }
    }
    async fn receive_owned(&self, cancellation: &CancellationToken) -> Result<Received> {
        if self.0.closed.load(Ordering::Acquire) {
            if cancellation.is_cancelled() {
                return Err(failure(ServiceFailure::Canceled));
            }
            let terminal = self.0.input.lock().expect("typed input").terminal;
            return Ok(Received {
                payload: Zeroizing::new(Vec::new()),
                present: false,
                terminal,
                _charge: None,
            });
        }
        self.0.check()?;
        {
            let mut input = self.0.input.lock().expect("typed input");
            if input.waiting {
                return Err(failure(ServiceFailure::ResultModeConflict));
            }
            input.waiting = true;
            if input.diagnostics.is_none() {
                input.diagnostics = Some(
                    self.0
                        .account
                        .diagnostic_activity(crate::DiagnosticPhase::Application, 1),
                );
            }
            input.demand = true;
        }
        let _wait = ReceiveWait(self.0.clone());
        self.0.changed.notify_waiters();
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let result = self.0.account.with_security(|| {
                let mut input = self.0.input.lock().expect("typed input");
                if cancellation.is_cancelled() {
                    return Err(failure(ServiceFailure::Canceled));
                }
                if input.started || input.typed.is_some() {
                    return Err(failure(ServiceFailure::ResultModeConflict));
                }
                if let Some(message) = input.ready.take() {
                    input.demand = false;
                    return Ok(Some(message));
                }
                if input.terminal != MessageReceiveTerminal::Open {
                    return Ok(Some(Received {
                        payload: Zeroizing::new(Vec::new()),
                        present: false,
                        terminal: input.terminal,
                        _charge: None,
                    }));
                }
                Ok(None)
            })??;
            if let Some(message) = result {
                self.0.changed.notify_waiters();
                return Ok(message);
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
            _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)) }
        }
    }
    pub async fn close_write(&self) -> Result<()> {
        self.0.check()?;
        let start = {
            let mut control = self.0.send_control.lock().expect("typed send control");
            control.sealed = true;
            if control.fin_started {
                false
            } else {
                control.fin_started = true;
                true
            }
        };
        if start {
            self.0.workers.fetch_add(1, Ordering::AcqRel);
            let owner = self.0.clone();
            let deadline = Instant::now() + owner.options.send_timeout;
            tokio::spawn(async move {
                let _worker = Worker(owner.clone());
                let result = owner.finish_queue(deadline).await;
                owner
                    .send_control
                    .lock()
                    .expect("typed send control")
                    .fin_result = Some(result);
                owner.changed.notify_waiters();
            });
        }
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(result) = self
                .0
                .send_control
                .lock()
                .expect("typed send control")
                .fin_result
            {
                return result;
            }
            tokio::select! { _ = changed => {}, _ = self.0.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)) }
        }
    }
    pub async fn finish(&self) -> Result<()> {
        self.close_write().await?;
        self.0
            .stream()?
            .finish()
            .await
            .map_err(|_| failure(ServiceFailure::Closed))
    }
    pub fn close(&self) {
        self.0.close();
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        let workers = self.0.workers.load(Ordering::Acquire);
        CleanupStatus {
            complete: workers == 0,
            cleanup_incomplete: workers != 0,
            pending_callbacks: workers as u64,
        }
    }
    pub async fn wait_cleanup(&self) -> CleanupStatus {
        let deadline = Instant::now() + self.0.options.cleanup_timeout;
        loop {
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::select! { _ = changed => {}, _ = tokio::time::sleep_until(deadline) => return self.cleanup_status() }
        }
    }
}
struct MessagePayload {
    payload: Zeroizing<Vec<u8>>,
    _charge: Option<ResourceCharge>,
}
impl AsRef<[u8]> for MessagePayload {
    fn as_ref(&self) -> &[u8] {
        &self.payload
    }
}
struct SendObserver(CancellationToken);
impl Drop for SendObserver {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct ReceiveWait<I, O>(Arc<Core<I, O>>);
impl<I, O> Drop for ReceiveWait<I, O> {
    fn drop(&mut self) {
        self.0.input.lock().expect("typed input").waiting = false;
        self.0.changed.notify_waiters();
    }
}
struct Worker<I, O>(Arc<Core<I, O>>);
impl<I, O> Drop for Worker<I, O> {
    fn drop(&mut self) {
        if self.0.workers.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.charge.lock().expect("typed setup charge").take();
            self.0.tail.finish();
        }
        self.0.changed.notify_waiters();
    }
}
impl<I: Send + Sync + 'static, O: Send + Sync + 'static> Core<I, O> {
    fn check(&self) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(failure(ServiceFailure::Closed));
        }
        self.account.check()?;
        Ok(())
    }
    fn stream(&self) -> Result<Arc<Stream>> {
        self.stream
            .lock()
            .expect("typed Stream")
            .clone()
            .ok_or_else(|| failure(ServiceFailure::Closed))
    }
    fn close(self: &Arc<Self>) {
        // Seal, cancellation and physical-tail transfer are one live ownership
        // interval even when both I/O tasks exit on another thread immediately.
        self.workers.fetch_add(1, Ordering::AcqRel);
        let _closing = Worker(self.clone());
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.cancellation.cancel();
        self.group.close();
        let retired = {
            let mut input = self.input.lock().expect("typed input");
            let retired = (input.ready.take(), input.typed.take());
            if let Some(diagnostics) = &input.diagnostics {
                diagnostics.service_failure(failure(ServiceFailure::Closed));
            }
            if input.terminal == MessageReceiveTerminal::Open {
                input.terminal = MessageReceiveTerminal::Closed;
            }
            retired
        };
        drop(retired);
        let stream = self.stream.lock().expect("typed Stream").take();
        if let Some(stream) = stream {
            if !self.activated.load(Ordering::Acquire) {
                self.changed.notify_waiters();
                return;
            }
            self.workers.fetch_add(1, Ordering::AcqRel);
            let owner = self.clone();
            // The original Stream retains provider/transport responsibility.
            // Reset is submitted by this finite task; callback tails retain
            // only their application account and actual executor position.
            tokio::spawn(async move {
                let _worker = Worker(owner.clone());
                let _ = stream.reset().await;
                loop {
                    if stream.cleanup_status().complete {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
        }
        self.changed.notify_waiters();
    }
    fn publish_decoded(&self, result: Result<Decoded<I>>) {
        // A result that loses to close or security expiry still owns its charge.
        // Release it only after leaving both publication locks.
        let mut result = Some(result);
        let retired = self.account.with_security(|| {
            let mut input = self.input.lock().expect("typed input");
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            if let Some(Err(error)) = &result
                && let Some(diagnostics) = &input.diagnostics
            {
                diagnostics.service_failure(*error);
            }
            input
                .typed
                .replace(result.take().expect("original typed result"))
        });
        drop(retired);
        drop(result);
        self.changed.notify_waiters();
    }
    fn complete_receive_diagnostics(
        &self,
        terminal: MessageReceiveTerminal,
        error: Option<ServiceError>,
    ) {
        if let Some(diagnostics) = self.input.lock().expect("typed input").diagnostics.take() {
            if let Some(error) = error {
                diagnostics.service_failure(error);
            } else if matches!(
                terminal,
                MessageReceiveTerminal::Open | MessageReceiveTerminal::Eof
            ) {
                diagnostics.succeed();
            } else {
                diagnostics.service_failure(failure(ServiceFailure::Closed));
            }
        }
    }
    fn terminal(&self, terminal: MessageReceiveTerminal) {
        let mut input = self.input.lock().expect("typed input");
        input.terminal = terminal;
        if !matches!(
            terminal,
            MessageReceiveTerminal::Open | MessageReceiveTerminal::Eof
        ) && let Some(diagnostics) = &input.diagnostics
        {
            diagnostics.service_failure(failure(ServiceFailure::Closed));
        }
        drop(input);
        self.changed.notify_waiters();
    }
    async fn read_messages(self: &Arc<Self>, permit: StreamReadPermit) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.cancellation.is_cancelled() {
                break;
            }
            let demanded = {
                let input = self.input.lock().expect("typed input");
                self.activated.load(Ordering::Acquire)
                    && input.demand
                    && input.ready.is_none()
                    && !input.scheduled
                    && !input.started
                    && input.typed.is_none()
                    && input.terminal == MessageReceiveTerminal::Open
            };
            if !demanded {
                tokio::select! { _ = changed => {}, _ = self.cancellation.cancelled() => break };
                continue;
            }
            let received = self.read_message(&permit).await;
            match received {
                Ok(message) => {
                    let mut message = Some(message);
                    let retired = {
                        let mut input = self.input.lock().expect("typed input");
                        if self.closed.load(Ordering::Acquire) {
                            None
                        } else {
                            input
                                .ready
                                .replace(message.take().expect("original typed frame"))
                        }
                    };
                    drop(retired);
                    drop(message);
                }
                Err(terminal) => {
                    self.terminal(terminal);
                    if terminal != MessageReceiveTerminal::Eof {
                        self.close();
                    }
                    break;
                }
            }
            self.changed.notify_waiters();
        }
    }
    async fn read_message(
        &self,
        permit: &StreamReadPermit,
    ) -> std::result::Result<Received, MessageReceiveTerminal> {
        let mut prefix = [0; 4];
        let mut used = 0;
        let mut deadline = None;
        let mut prefix_terminal = ReadStreamStatus::Open;
        while used < 4 {
            let read = self.read_piece(4 - used, permit, deadline).await?;
            prefix_terminal = read.stream_status;
            if !read.data.is_empty() {
                deadline.get_or_insert(Instant::now() + self.options.assembly_timeout);
                prefix[used..used + read.data.len()].copy_from_slice(&read.data);
                used += read.data.len();
            }
            if read.stream_status != ReadStreamStatus::Open && used < 4 {
                return Err(
                    if used == 0 && read.stream_status == ReadStreamStatus::Eof {
                        MessageReceiveTerminal::Eof
                    } else {
                        MessageReceiveTerminal::FramingFailed
                    },
                );
            }
        }
        let length = u32::from_be_bytes(prefix) as usize;
        if (length != 0 && prefix_terminal != ReadStreamStatus::Open)
            || length > self.incoming.max_message_bytes() as usize
        {
            return Err(MessageReceiveTerminal::FramingFailed);
        }
        let charge = self
            .account
            .reserve(ResourceLimits {
                sdk_bytes: length as u64 + 4096,
                items: 1,
                ..ResourceLimits::default()
            })
            .map_err(|_| MessageReceiveTerminal::Aborted)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(length));
        let mut terminal = if prefix_terminal == ReadStreamStatus::Eof {
            MessageReceiveTerminal::Eof
        } else {
            MessageReceiveTerminal::Open
        };
        while payload.len() < length {
            let read = self
                .read_piece((length - payload.len()).min(16384), permit, deadline)
                .await?;
            payload.extend_from_slice(&read.data);
            if read.stream_status != ReadStreamStatus::Open {
                if payload.len() < length {
                    return Err(MessageReceiveTerminal::FramingFailed);
                }
                terminal = if read.stream_status == ReadStreamStatus::Eof {
                    MessageReceiveTerminal::Eof
                } else {
                    MessageReceiveTerminal::Aborted
                };
            }
        }
        Ok(Received {
            payload,
            present: true,
            terminal,
            _charge: Some(charge),
        })
    }
    async fn read_piece(
        &self,
        length: usize,
        permit: &StreamReadPermit,
        deadline: Option<Instant>,
    ) -> std::result::Result<crate::ReadResult, MessageReceiveTerminal> {
        let stream = self.stream().map_err(|_| MessageReceiveTerminal::Closed)?;
        let deadline = deadline.unwrap_or(Instant::now() + Duration::from_secs(86400));
        tokio::select! {
            result = stream.read_with_permit(length, permit) => result.map_err(|_| MessageReceiveTerminal::Aborted),
            _ = self.cancellation.cancelled() => Err(MessageReceiveTerminal::Closed),
            _ = tokio::time::sleep_until(deadline), if deadline < Instant::now() + Duration::from_secs(61) => Err(MessageReceiveTerminal::AssemblyTimeout),
        }
    }
    async fn write_messages(self: &Arc<Self>, mut receiver: mpsc::Receiver<SendJob<O>>) {
        loop {
            while !self.activated.load(Ordering::Acquire) {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.activated.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! { _ = changed => {}, _ = self.cancellation.cancelled() => return }
            }
            let job = tokio::select! { _ = self.cancellation.cancelled() => break,
            job = receiver.recv() => match job { Some(job) => job, None => break } };
            let outcome = self.send_one(&job).await;
            match &outcome {
                Ok(_) => job.diagnostics.succeed(),
                Err(error) => job.diagnostics.service_failure(*error),
            }
            let _ = job.result.send(outcome);
            {
                let mut control = self.send_control.lock().expect("typed send control");
                control.pending -= 1;
            }
            self.changed.notify_waiters();
        }
    }
    async fn finish_queue(&self, deadline: Instant) -> Result<()> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            self.check()?;
            if self
                .send_control
                .lock()
                .expect("typed send control")
                .pending
                == 0
            {
                break;
            }
            tokio::select! { _ = changed => {}, _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
            _ = tokio::time::sleep_until(deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)) }
        }
        let stream = self.stream()?;
        tokio::select! { result = stream.close_write() => result.map_err(|_| failure(ServiceFailure::ServiceUnavailable)),
        _ = self.cancellation.cancelled() => Err(failure(ServiceFailure::Closed)),
        _ = tokio::time::sleep_until(deadline) => Err(failure(ServiceFailure::DeadlineExceeded)) }
    }
    async fn send_one(self: &Arc<Self>, job: &SendJob<O>) -> Result<usize> {
        self.check()?;
        if job.cancellation.is_cancelled() || Instant::now() >= job.deadline {
            return Err(failure(ServiceFailure::Canceled));
        }
        let codec = self.outbound.clone();
        let value = job.value.clone();
        let maximum = self.outgoing.max_message_bytes() as usize;
        let payload = if controlled(codec.as_ref()) {
            let position = tokio::select! {
                position = self.group.ordinary(false, job.context.as_ref()) => position?,
                _ = job.cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                _ = tokio::time::sleep_until(job.deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)),
            };
            let invocation = position.enter()?;
            let mut payload = Zeroizing::new(vec![0; maximum]);
            let length = codec.encode_with_context(&value, &mut payload, &invocation.context())?;
            if length > maximum {
                return Err(failure(ServiceFailure::EncodeFailed));
            }
            payload.truncate(length);
            drop(invocation);
            drop(position);
            payload
        } else {
            let position = tokio::select! {
                position = self.group.ordinary(false, job.context.as_ref()) => position?,
                _ = job.cancellation.cancelled() => return Err(failure(ServiceFailure::Canceled)),
                _ = self.cancellation.cancelled() => return Err(failure(ServiceFailure::Closed)),
                _ = tokio::time::sleep_until(job.deadline) => return Err(failure(ServiceFailure::DeadlineExceeded)),
            };
            let invocation = position.enter()?;
            let account = self.account.clone();
            let cancellation = invocation.cancellation();
            let backing = job._charge.clone();
            let entry = job._entry.clone();
            let source_cancel = job.cancellation.clone();
            let deadline = job.deadline;
            let (sender, receiver) = oneshot::channel();
            self.workers.fetch_add(1, Ordering::AcqRel);
            let owner = self.clone();
            tokio::task::spawn_blocking(move || {
                let _worker = Worker(owner);
                let _backing = backing;
                let _entry = entry;
                let result = (|| {
                    account.check()?;
                    if source_cancel.is_cancelled() || Instant::now() >= deadline {
                        return Err(failure(ServiceFailure::Canceled));
                    }
                    let mut payload = Zeroizing::new(vec![0; maximum]);
                    let length = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        codec.encode_with_context(&value, &mut payload, &invocation.context())
                    }))
                    .unwrap_or_else(|_| Err(failure(ServiceFailure::EncodeFailed)))?;
                    if length > maximum {
                        return Err(failure(ServiceFailure::EncodeFailed));
                    }
                    payload.truncate(length);
                    account.check()?;
                    Ok(payload)
                })();
                let _ = sender.send(result);
                drop(invocation);
                drop(position);
            });
            tokio::select! {
                encoded = receiver => encoded.map_err(|_| failure(ServiceFailure::EncodeFailed))??,
                _ = job.cancellation.cancelled() => { cancellation.cancel(); return Err(failure(ServiceFailure::Canceled)); },
                _ = self.cancellation.cancelled() => { cancellation.cancel(); return Err(failure(ServiceFailure::Closed)); },
                _ = tokio::time::sleep_until(job.deadline) => { cancellation.cancel(); return Err(failure(ServiceFailure::DeadlineExceeded)); },
            }
        };
        self.check()?;
        if job.cancellation.is_cancelled() || Instant::now() >= job.deadline {
            return Err(failure(ServiceFailure::Canceled));
        }
        let length = payload.len();
        let mut wire = Vec::with_capacity(4 + length);
        wire.extend_from_slice(&(length as u32).to_be_bytes());
        wire.extend_from_slice(&payload);
        let wire = Bytes::from(wire);
        let stream: Arc<dyn ByteStream> = self.stream()?;
        let cancellation = job.cancellation.clone();
        let deadline = job.deadline;
        let operation = WriteOperation::try_prepare_guarded(
            stream,
            wire,
            Some(Arc::new(move |_| {
                if cancellation.is_cancelled() {
                    return Err(crate::SessionError::Canceled);
                }
                if Instant::now() >= deadline {
                    return Err(crate::SessionError::Timeout);
                }
                Ok(())
            })),
        )
        .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        operation
            .start()
            .await
            .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
        let mut canceled_observer = false;
        let progress = loop {
            tokio::select! {
                result = operation.wait() => break result.map_err(|_| failure(ServiceFailure::ServiceUnavailable))?,
                _ = job.cancellation.cancelled(), if !canceled_observer => {
                    canceled_observer = true;
                    operation.cancel_unsubmitted();
                },
                _ = self.cancellation.cancelled() => { operation.cancel(); break operation.wait().await.map_err(|_| failure(ServiceFailure::Closed))?; },
                _ = tokio::time::sleep_until(job.deadline) => { operation.cancel(); break operation.wait().await.map_err(|_| failure(ServiceFailure::DeadlineExceeded))?; },
            }
        };
        if progress.accepted_bytes != progress.requested_bytes
            || progress.terminal_reason.as_deref() != Some("complete")
        {
            if progress.accepted_bytes != 0 {
                self.close();
            }
            return Err(failure(
                if progress.terminal_reason.as_deref() == Some("canceled") {
                    ServiceFailure::Canceled
                } else {
                    ServiceFailure::ServiceUnavailable
                },
            ));
        }
        Ok(length)
    }
}
impl Session {
    pub async fn open_message_stream<I: Send + Sync + 'static, O: Send + Sync + 'static>(
        &self,
        definition: MessageStreamDefinition,
        application: Metadata,
        inbound: Arc<dyn MessageCodec<I>>,
        outbound: Arc<dyn MessageCodec<O>>,
        receive_window: u64,
        options: MessageStreamOptions,
    ) -> Result<TypedMessageStream<I, O>> {
        options.check()?;
        if inbound.definition() != definition.acceptor_to_opener()
            || outbound.definition() != definition.opener_to_acceptor()
            || inbound.application_bytes() == 0
            || outbound.application_bytes() == 0
            || inbound.application_bytes() > 1 << 30
            || outbound.application_bytes() > 1 << 30
        {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let account = self.application_account();
        if !account.belongs_to(&definition.0.root) {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let tail = self
            .application_tail()
            .map_err(|_| failure(ServiceFailure::Closed))?;
        let setup = account.reserve(ResourceLimits {
            sdk_bytes: 32768 + inbound.application_bytes() + outbound.application_bytes(),
            items: 12,
            tasks: 3,
            work_slots: 2,
            ..ResourceLimits::default()
        })?;
        let wrapper = definition.wrap(&application)?;
        let group = account.application_group()?;
        let mut preparation = crate::crypto_v4::StreamPreparation::new(account.clone())
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        let permit = preparation
            .claim_typed()
            .map_err(|_| failure(ServiceFailure::ResultModeConflict))?;
        let incoming = definition.acceptor_to_opener().clone();
        let outgoing = definition.opener_to_acceptor().clone();
        let typed = TypedMessageStream::prepared_core(
            None,
            account,
            group,
            definition,
            application,
            inbound,
            outbound,
            incoming,
            outgoing,
            options,
            setup,
            permit,
            tail,
        );
        let candidate = typed.0.clone();
        // Both workers, their queues, the read permit, and the callback graph
        // exist before native stream admission allocates any wire identity.
        self.open_stream_prepared(
            typed.definition().kind(),
            wrapper,
            receive_window,
            preparation,
            move |stream| {
                *candidate.stream.lock().expect("typed Stream") = Some(Arc::new(stream));
            },
        )
        .await
        .map_err(|_| failure(ServiceFailure::ServiceUnavailable))?;
        typed.activate();
        Ok(typed)
    }
}
#[async_trait]
pub trait MessageStreamHandler<I, O>: fmt::Debug + Send + Sync + 'static {
    async fn authorize(
        &self,
        authentication: crate::ApplicationBinding,
        application: Metadata,
        cancellation: CancellationToken,
        context: ApplicationInvocationContext,
    ) -> std::result::Result<crate::StreamAuthorization, crate::ServeError>;
    async fn handle(
        &self,
        stream: TypedMessageStream<I, O>,
        cancellation: CancellationToken,
        context: ApplicationInvocationContext,
    ) -> std::result::Result<(), crate::ServeError>;
    fn application_bytes(&self) -> u64 {
        65536
    }
}
struct Registered<I, O> {
    definition: MessageStreamDefinition,
    inbound: Arc<dyn MessageCodec<I>>,
    outbound: Arc<dyn MessageCodec<O>>,
    options: MessageStreamOptions,
    handler: Arc<dyn MessageStreamHandler<I, O>>,
}
impl<I, O> fmt::Debug for Registered<I, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MessageStreamRegistration { <opaque> }")
    }
}
#[async_trait]
impl<I: Send + Sync + 'static, O: Send + Sync + 'static> crate::RawStreamHandler
    for Registered<I, O>
{
    fn message_definition(&self) -> Option<[u8; 32]> {
        Some(self.definition.digest())
    }
    async fn authorize(
        &self,
        _: crate::ApplicationBinding,
        _: Metadata,
        _: CancellationToken,
    ) -> std::result::Result<crate::StreamAuthorization, crate::ServeError> {
        Err(crate::ServeError::new(crate::ServeFailure::Configuration))
    }
    async fn handle(
        &self,
        _: Stream,
        _: Metadata,
        _: CancellationToken,
    ) -> std::result::Result<(), crate::ServeError> {
        Err(crate::ServeError::new(crate::ServeFailure::Configuration))
    }
    async fn handle_open_with_context(
        &self,
        request: OpenRequest,
        authentication: crate::ApplicationBinding,
        cancellation: CancellationToken,
        context: ApplicationInvocationContext,
    ) -> std::result::Result<(), crate::ServeError> {
        let diagnostics = request
            .account()
            .diagnostic_activity(crate::DiagnosticPhase::Application, 1);
        let result = async {
            let application = self
                .definition
                .application_metadata(request.metadata())
                .map_err(|_| crate::ServeError::new(crate::ServeFailure::Rejected))?;
            let decision = self
                .handler
                .authorize(
                    authentication,
                    application.clone(),
                    cancellation.clone(),
                    context.clone(),
                )
                .await?;
            let crate::StreamAuthorization::Accept { receive_window } = decision else {
                diagnostics.fail(
                    crate::DiagnosticCode::IdentityRejected,
                    crate::DiagnosticRetryDisposition::DoNotRetry,
                );
                let _ = request.reject();
                return Ok(());
            };
            context
                .check_cancellation()
                .map_err(|_| crate::ServeError::new(crate::ServeFailure::Canceled))?;
            let candidate = request
                .prepare_stream()
                .map_err(|_| crate::ServeError::new(crate::ServeFailure::Capacity))?;
            let charge = candidate
                .account()
                .reserve(ResourceLimits {
                    sdk_bytes: 32768
                        + self.handler.application_bytes()
                        + self.inbound.application_bytes()
                        + self.outbound.application_bytes(),
                    items: 12,
                    tasks: 3,
                    work_slots: 2,
                    ..ResourceLimits::default()
                })
                .map_err(crate::ServeError::from)?;
            let typed = TypedMessageStream::prepare(
                candidate.clone(),
                self.definition.clone(),
                application,
                self.inbound.clone(),
                self.outbound.clone(),
                false,
                self.options.clone(),
                charge,
            )
            .map_err(|_| crate::ServeError::new(crate::ServeFailure::Capacity))?;
            // All adapter resources and both codec directions exist before the
            // original irreversible OPEN_ACCEPT. No raw fallback is installed.
            if request.accept_prepared(candidate, receive_window).is_err() {
                typed.close();
                return Err(crate::ServeError::new(crate::ServeFailure::Rejected));
            }
            typed.activate();
            let handled = self
                .handler
                .handle(typed.clone(), cancellation, context)
                .await;
            if handled.is_err() {
                typed.close();
            } else if let Err(error) = typed.finish().await {
                diagnostics.service_failure(error);
                typed.close();
            }
            handled
        }
        .await;
        diagnostics.serve_outcome(&result);
        result
    }
}
/// Produces an entry for the original immutable kind registration table.
/// HandlerPlan rejects raw/typed collisions using its existing kind gate.
pub fn register_message_stream<I: Send + Sync + 'static, O: Send + Sync + 'static>(
    definition: MessageStreamDefinition,
    inbound: Arc<dyn MessageCodec<I>>,
    outbound: Arc<dyn MessageCodec<O>>,
    options: MessageStreamOptions,
    handler: Arc<dyn MessageStreamHandler<I, O>>,
) -> Result<crate::RawStreamRegistration> {
    options.check()?;
    if inbound.definition() != definition.opener_to_acceptor()
        || outbound.definition() != definition.acceptor_to_opener()
        || handler.application_bytes() == 0
        || handler.application_bytes() > 1 << 30
    {
        return Err(failure(ServiceFailure::ConfigurationCapacity));
    }
    let kind = definition.kind().to_owned();
    Ok(crate::RawStreamRegistration {
        kind,
        metadata: None,
        handler: Arc::new(Registered {
            definition,
            inbound,
            outbound,
            options,
            handler,
        }),
    })
}

impl OpenRequest {
    pub fn accept_message_stream<I: Send + Sync + 'static, O: Send + Sync + 'static>(
        self,
        definition: MessageStreamDefinition,
        inbound: Arc<dyn MessageCodec<I>>,
        outbound: Arc<dyn MessageCodec<O>>,
        receive_window: u64,
        options: MessageStreamOptions,
    ) -> Result<TypedMessageStream<I, O>> {
        let application = definition.application_metadata(self.metadata())?;
        if self.kind() != definition.kind() {
            return Err(failure(ServiceFailure::ContractMismatch));
        }
        let candidate = self
            .prepare_stream()
            .map_err(|_| failure(ServiceFailure::ResourceExhausted))?;
        let charge = candidate.account().reserve(ResourceLimits {
            sdk_bytes: 32768 + inbound.application_bytes() + outbound.application_bytes(),
            items: 12,
            tasks: 3,
            work_slots: 2,
            ..ResourceLimits::default()
        })?;
        let typed = TypedMessageStream::prepare(
            candidate.clone(),
            definition,
            application,
            inbound,
            outbound,
            false,
            options,
            charge,
        )?;
        if self.accept_prepared(candidate, receive_window).is_err() {
            typed.close();
            return Err(failure(ServiceFailure::ServiceUnavailable));
        }
        typed.activate();
        Ok(typed)
    }
}

struct SendControl {
    sealed: bool,
    pending: usize,
    fin_started: bool,
    fin_result: Option<Result<()>>,
}
struct SendEntry {
    count: Arc<AtomicUsize>,
    changed: Arc<Notify>,
}
impl Drop for SendEntry {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        self.changed.notify_waiters();
    }
}
fn retained_bytes<T: 'static>(value: &T) -> u64 {
    let value = value as &dyn std::any::Any;
    if let Some(value) = value.downcast_ref::<Vec<u8>>() {
        value.capacity() as u64
    } else if let Some(value) = value.downcast_ref::<String>() {
        value.capacity() as u64
    } else {
        std::mem::size_of::<T>() as u64
    }
}
