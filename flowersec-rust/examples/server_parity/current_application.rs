use super::*;
use flowersec::{
    BytesMessageCodec, ContractAcceptance, FixedContractQuery, MessageDefinition, MethodDefinition,
    MethodDefinitionOptions, NotificationDropPolicy, NotificationPrepareOptions,
    NotificationServiceRegistration, ResponseLimitPolicy, ServiceBindingOptions, ServiceClient,
    ServiceContract, ServiceDefinition, ServiceError, ServiceFailure, ServiceMethod,
    ServiceNotificationObserver, ServiceNotificationSubscription, ServiceSemantics, ServiceShape,
    TypedUnaryValue, UnaryPrepareOptions, UnaryRequestContext, UnaryResponse, UnaryServiceHandler,
    UnaryServiceRegistration,
};
use std::sync::atomic::Ordering;
use tokio::sync::Semaphore;

#[derive(Debug)]
pub(super) struct Application {
    ledger: ExecutionLedger,
    observer_ready: std::sync::atomic::AtomicBool,
    notification_count: std::sync::atomic::AtomicU32,
    changed: Notify,
    peer_ready: Semaphore,
    notified: Semaphore,
    datagram_ready: Semaphore,
    completed: Semaphore,
    session: Mutex<Option<flowersec::Session>>,
    installed: Mutex<Option<flowersec::AcceptedServices>>,
}
impl Application {
    pub(super) fn new(ledger: ExecutionLedger) -> Arc<Self> {
        Arc::new(Self {
            ledger,
            observer_ready: std::sync::atomic::AtomicBool::new(false),
            notification_count: std::sync::atomic::AtomicU32::new(0),
            changed: Notify::new(),
            peer_ready: Semaphore::new(0),
            notified: Semaphore::new(0),
            datagram_ready: Semaphore::new(0),
            completed: Semaphore::new(0),
            session: Mutex::new(None),
            installed: Mutex::new(None),
        })
    }
    pub(super) fn published(
        &self,
        session: flowersec::Session,
        services: flowersec::AcceptedServices,
    ) {
        *self.session.lock().expect("current application Session") = Some(session);
        *self.installed.lock().expect("current application services") = Some(services);
    }
    async fn wait_observer(&self, cancellation: &CancellationToken) -> Result<(), ServiceError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.observer_ready.load(Ordering::Acquire) {
                return Ok(());
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ServiceError(ServiceFailure::Canceled)) }
        }
    }
    async fn wait_notifications(
        &self,
        cancellation: &CancellationToken,
    ) -> Result<(), ServiceError> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.notification_count.load(Ordering::Acquire) >= 2 {
                return Ok(());
            }
            tokio::select! { _ = changed => {}, _ = cancellation.cancelled() => return Err(ServiceError(ServiceFailure::Canceled)) }
        }
    }
    fn retire(&self) {
        self.session
            .lock()
            .expect("retire application Session")
            .take();
        self.installed
            .lock()
            .expect("retire application services")
            .take();
    }
}
#[derive(Debug)]
struct Handler {
    method: u32,
    application: Arc<Application>,
}
#[async_trait]
impl UnaryServiceHandler for Handler {
    async fn authorize(&self, context: UnaryRequestContext) -> Result<(), ServiceError> {
        context.invocation.check_cancellation().map_err(Into::into)
    }
    async fn handle(
        &self,
        context: UnaryRequestContext,
        request: &[u8],
    ) -> Result<UnaryResponse, ServiceError> {
        let value: Value = serde_json::from_slice(request)
            .map_err(|_| ServiceError(ServiceFailure::DecodeFailed))?;
        let observation_barrier = self.method == ECHO_RPC
            && value.get("value").and_then(Value::as_str) == Some("notifications-observed");
        let wanted = match self.method {
            ECHO_RPC if observation_barrier => "notifications-observed",
            ECHO_RPC => "ping",
            COMPLETE_RPC => "complete",
            DATAGRAM_READY_RPC => "datagram-ready",
            _ => return Err(ServiceError(ServiceFailure::Protocol)),
        };
        if value.get("value").and_then(Value::as_str) != Some(wanted) {
            return Err(ServiceError(ServiceFailure::Protocol));
        }
        match self.method {
            ECHO_RPC => {
                self.application
                    .wait_observer(&context.cancellation)
                    .await?;
                if observation_barrier {
                    // Keep the application gate open until both notifications
                    // have actually reached their original observer.
                    self.application
                        .wait_notifications(&context.cancellation)
                        .await?;
                }
                self.application.ledger.record(&["rpc"]);
                self.application.peer_ready.add_permits(1);
            }
            DATAGRAM_READY_RPC => self.application.datagram_ready.add_permits(1),
            COMPLETE_RPC => {
                let session = self
                    .application
                    .session
                    .lock()
                    .expect("completion Session")
                    .clone()
                    .ok_or(ServiceError(ServiceFailure::Closed))?;
                session
                    .rekey()
                    .await
                    .map_err(|_| ServiceError(ServiceFailure::ServiceFailed))?;
                self.application.ledger.record(&["rekey"]);
                let result = session
                    .probe_liveness(Duration::from_secs(3))
                    .await
                    .map_err(|_| ServiceError(ServiceFailure::ServiceFailed))?;
                if result.outcome != flowersec::ProbeOutcome::Responsive {
                    return Err(ServiceError(ServiceFailure::ServiceFailed));
                }
                self.application.ledger.record(&["liveness"]);
                self.application.completed.add_permits(1);
            }
            _ => unreachable!(),
        }
        Ok(UnaryResponse {
            payload: request.to_vec(),
            application_error_code: None,
        })
    }
}
#[derive(Debug)]
struct Observer(Arc<Application>);
#[async_trait]
impl ServiceNotificationObserver<Vec<u8>> for Observer {
    fn application_bytes(&self) -> u64 {
        4096
    }
    async fn observe(
        &self,
        value: Vec<u8>,
        _context: flowersec::NotificationContext,
    ) -> Result<(), ServiceError> {
        let value: Value = serde_json::from_slice(&value)
            .map_err(|_| ServiceError(ServiceFailure::DecodeFailed))?;
        if value.get("value").and_then(Value::as_str) != Some("notify") {
            return Err(ServiceError(ServiceFailure::Protocol));
        }
        self.0.ledger.record(&["notification"]);
        self.0.notified.add_permits(1);
        self.0.notification_count.fetch_add(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
        Ok(())
    }
}

// These unsigned engineering templates are the shared canonical application
// declarations. They confer no admission, execution or publication authority.
fn contract(environment: &flowersec::TransportEnvironment, type_id: u32) -> ServiceContract {
    let template = if type_id == NOTIFY_RPC {
        "ad006a61636d652f66696c6573010102020500066131076131080009000a000b19753015f4171a00100000181b80"
    } else {
        "ae006a61636d652f66696c6573010102000300066131076131080109000a1a001000000b1975300c19271015f4171a00100000181b80"
    };
    let wire = template
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    let mut cursor = 0;
    let CurrentCborValue::Map(mut fields) = current_cbor_value(&wire, &mut cursor, 0).unwrap()
    else {
        unreachable!()
    };
    for (key, value) in &mut fields {
        match key {
            CurrentCborValue::Uint(0) => *value = CurrentCborValue::Text("flowersec.parity".into()),
            CurrentCborValue::Uint(1) => *value = CurrentCborValue::Uint(u64::from(type_id)),
            CurrentCborValue::Uint(10) if type_id != NOTIFY_RPC => {
                *value = CurrentCborValue::Uint(4096)
            }
            CurrentCborValue::Uint(12) => *value = CurrentCborValue::Uint(30000),
            CurrentCborValue::Uint(23) => *value = CurrentCborValue::Uint(4096),
            _ => {}
        }
    }
    let mut encoded = Vec::new();
    current_encode_cbor(&CurrentCborValue::Map(fields), &mut encoded);
    ServiceContract::capture(environment, &encoded).expect("capture current parity contract")
}
fn method(type_id: u32) -> MethodDefinition {
    let notify = type_id == NOTIFY_RPC;
    let message = MessageDefinition::new([8; 32], "1".into(), 4096).unwrap();
    MethodDefinition::new(MethodDefinitionOptions {
        type_id,
        shape: if notify {
            ServiceShape::Notify
        } else {
            ServiceShape::Unary
        },
        semantics: if notify {
            ServiceSemantics::Observation
        } else {
            ServiceSemantics::Transient
        },
        request: message.clone(),
        response: (!notify).then_some(message),
        response_revision: "1".into(),
        request_max_bytes: 4096,
        min_response_limit_bytes: 0,
        max_response_bytes: if notify { 0 } else { 4096 },
        require_durable: false,
        checkpoint_format: None,
        restart_flush_deadline_ms: None,
        streaming: None,
        content: None,
        errors: Vec::new(),
    })
    .unwrap()
}
pub(super) fn plan(
    environment: &flowersec::TransportEnvironment,
    application: Arc<Application>,
) -> flowersec::HandlerPlan {
    let contracts = [ECHO_RPC, NOTIFY_RPC, COMPLETE_RPC, DATAGRAM_READY_RPC]
        .map(|id| contract(environment, id));
    let unary = contracts
        .iter()
        .filter(|contract| contract.type_id() != NOTIFY_RPC)
        .map(|contract| UnaryServiceRegistration {
            contract: contract.clone(),
            offer: None,
            offer_window_ms: None,
            query_allowed: true,
            resident: false,
            handler: Arc::new(Handler {
                method: contract.type_id(),
                application: application.clone(),
            }),
            execution: None,
            caller: None,
        })
        .collect();
    let notification = contracts
        .iter()
        .find(|contract| contract.type_id() == NOTIFY_RPC)
        .unwrap()
        .clone();
    let mut query_digest = [0; 32];
    query_digest[0] = 9;
    environment
        .handler_plan(flowersec::HandlerPlanOptions {
            streams: flowersec::StreamDispatch::Manual,
            application_bytes: 65536,
        })
        .unwrap()
        .with_services(flowersec::ServicePlan {
            query: FixedContractQuery {
                type_id: 7,
                contract_digest: query_digest,
            },
            unary,
            notifications: vec![NotificationServiceRegistration {
                contract: notification,
                request: method(NOTIFY_RPC).options().request.clone(),
                query_allowed: true,
                offer: None,
                execution: None,
                caller: None,
                handler: None,
            }],
            streaming: Vec::new(),
            resume: Vec::new(),
            result_read: None,
            management: None,
        })
        .expect("freeze current parity services before READY")
}
struct Binding {
    client: ServiceClient,
    methods: [MethodDefinition; 4],
    notifications: flowersec::NotificationPeer,
    subscription: ServiceNotificationSubscription<Vec<u8>>,
}
async fn bind(session: &flowersec::Session, application: &Arc<Application>) -> Binding {
    let installed = application
        .installed
        .lock()
        .expect("published current services")
        .clone()
        .or_else(|| session.configured_services())
        .expect("original pre-READY services");
    application.published(session.clone(), installed.clone());
    let peer = installed.service_peer();
    let notifications = installed
        .notifications()
        .expect("original notification peer");
    let snapshot = peer
        .query_contracts(
            &[flowersec::ContractQueryTarget {
                namespace: "flowersec.parity".into(),
                type_id: NOTIFY_RPC,
                wanted_digest: None,
                known: None,
            }],
            Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await
        .expect("query original notification contract");
    let notification = snapshot[0]
        .contract
        .clone()
        .expect("advertised notification contract");
    let subscription = notifications
        .subscribe(
            notification,
            Arc::new(BytesMessageCodec::new(
                method(NOTIFY_RPC).options().request.clone(),
            )),
            NotificationDropPolicy::DropNewest,
            Arc::new(Observer(application.clone())),
        )
        .expect("subscribe before peer echo barrier");
    application.observer_ready.store(true, Ordering::Release);
    application.changed.notify_waiters();
    let methods = [ECHO_RPC, NOTIFY_RPC, COMPLETE_RPC, DATAGRAM_READY_RPC].map(method);
    let definition = ServiceDefinition::new(
        "flowersec.parity".into(),
        methods
            .iter()
            .map(|method| ServiceMethod {
                name: format!("Method{}", method.type_id()),
                export_name: format!("method{}", method.type_id()),
                method: method.clone(),
            })
            .collect(),
    )
    .unwrap();
    let options = methods
        .iter()
        .map(|method| ServiceBindingOptions {
            method: method.clone(),
            acceptance: ContractAcceptance::exact(),
            response_limit: ResponseLimitPolicy::Fixed(if method.type_id() == NOTIFY_RPC {
                0
            } else {
                4096
            }),
            execution_reference_identity: None,
            streaming: None,
            resume: None,
        })
        .collect();
    let client = peer
        .bind(
            definition,
            options,
            Duration::from_secs(10),
            CancellationToken::new(),
        )
        .await
        .expect("bind current parity methods");
    Binding {
        client,
        methods,
        notifications,
        subscription,
    }
}
async fn call(binding: &Binding, type_id: u32, value: &str) {
    let method = binding
        .methods
        .iter()
        .find(|method| method.type_id() == type_id)
        .unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({"value":value})).unwrap();
    let operation = binding
        .client
        .prepare_unary(
            method,
            &payload,
            Arc::new(BytesMessageCodec::new(method.options().request.clone())),
            Arc::new(BytesMessageCodec::new(
                method.options().response.clone().unwrap(),
            )),
            UnaryPrepareOptions {
                timeout: Duration::from_secs(10),
                response_limit_bytes: Some(4096),
                ..UnaryPrepareOptions::default()
            },
        )
        .unwrap();
    operation.start().unwrap();
    let response = operation
        .wait_typed(CancellationToken::new())
        .await
        .unwrap();
    let TypedUnaryValue::Response(response) = response.value else {
        panic!("current RPC returned an application error")
    };
    assert_eq!(
        serde_json::from_slice::<Value>(&response).unwrap(),
        serde_json::from_slice::<Value>(&payload).unwrap()
    );
    operation.close();
    let cleanup = operation.wait_cleanup().await;
    assert!(cleanup.complete, "current RPC retained physical cleanup");
}
async fn notify(binding: &Binding) {
    let method = binding
        .methods
        .iter()
        .find(|method| method.type_id() == NOTIFY_RPC)
        .unwrap();
    let payload = Arc::new(serde_json::to_vec(&serde_json::json!({"value":"notify"})).unwrap());
    let operation = binding
        .client
        .prepare_notification(
            &binding.notifications,
            method,
            payload,
            Arc::new(BytesMessageCodec::new(method.options().request.clone())),
            NotificationPrepareOptions {
                timeout: Duration::from_secs(10),
                ..NotificationPrepareOptions::default()
            },
            CancellationToken::new(),
        )
        .await
        .unwrap();
    operation.start().unwrap();
    operation
        .wait_submission(&CancellationToken::new())
        .await
        .unwrap();
    operation.close();
    assert!(
        operation
            .wait_cleanup(Duration::from_secs(5))
            .await
            .complete,
        "current notification publication retained cleanup"
    );
}
async fn signal(semaphore: &Semaphore, label: &str) {
    tokio::time::timeout(Duration::from_secs(10), semaphore.acquire())
        .await
        .expect(label)
        .unwrap()
        .forget();
}
async fn passive_cancellation(session: &flowersec::Session, ledger: &ExecutionLedger) {
    let cancellation = CancellationToken::new();
    cancellation.cancel();
    tokio::select! { biased; _ = cancellation.cancelled() => {}, _ = session.wait_termination() => panic!("canceling a passive waiter terminated the Session") }
    ledger.record(&["cancel"]);
}
async fn retire(binding: Binding, application: &Application) {
    binding.subscription.close();
    assert!(
        binding
            .subscription
            .wait_closed(Duration::from_secs(5))
            .await
            .complete,
        "current notification observer retained cleanup"
    );
    drop(binding);
    application.retire();
}
pub(super) async fn server(
    session: &flowersec::Session,
    application: &Arc<Application>,
    path: &'static str,
    datagrams: bool,
) {
    let binding = bind(session, application).await;
    passive_cancellation(session, &application.ledger).await;
    tokio::join!(
        current_server_streams(session, path, &application.ledger),
        async {
            call(&binding, ECHO_RPC, "ping").await;
            signal(
                &application.peer_ready,
                "client observer readiness deadline",
            )
            .await;
            notify(&binding).await;
            signal(&application.notified, "client notification deadline").await;
            signal(
                &application.datagram_ready,
                "client datagram barrier deadline",
            )
            .await;
            if datagrams {
                current_datagram_exchange(session, false, &application.ledger).await;
            }
            signal(&application.completed, "verified completion deadline").await;
            signal(&application.notified, "post-rekey notification deadline").await;
        }
    );
    session.wait_termination().await;
    retire(binding, application).await;
}
pub(super) async fn client(
    session: &flowersec::Session,
    application: &Arc<Application>,
    path: &'static str,
    datagrams: bool,
) {
    let binding = bind(session, application).await;
    call(&binding, ECHO_RPC, "ping").await;
    notify(&binding).await;
    signal(&application.notified, "server notification deadline").await;
    current_client_streams(session, path, &application.ledger).await;
    passive_cancellation(session, &application.ledger).await;
    call(&binding, ECHO_RPC, "ping").await;
    call(&binding, DATAGRAM_READY_RPC, "datagram-ready").await;
    if datagrams {
        current_datagram_exchange(session, true, &application.ledger).await;
    }
    session.rekey().await.unwrap();
    application.ledger.record(&["rekey"]);
    assert_eq!(
        session
            .probe_liveness(Duration::from_secs(3))
            .await
            .unwrap()
            .outcome,
        flowersec::ProbeOutcome::Responsive
    );
    application.ledger.record(&["liveness"]);
    call(&binding, COMPLETE_RPC, "complete").await;
    notify(&binding).await;
    call(&binding, ECHO_RPC, "notifications-observed").await;
    drain(session).await;
    session.close();
    retire(binding, application).await;
}

async fn drain(session: &flowersec::Session) {
    // Successful parity proves graceful completion before idempotent Close;
    // immediate Close is allowed to abort the underlying carrier.
    let operation = session.drain(Duration::from_secs(5)).unwrap();
    assert_eq!(
        operation.wait().await.unwrap().outcome,
        flowersec::DrainOutcome::Drained,
        "current parity communication did not drain"
    );
    session.wait_termination().await;
}
