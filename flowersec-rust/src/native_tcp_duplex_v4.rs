//! A TCP endpoint created and owned entirely by the SDK.  The public facade
//! never exposes a socket/descriptor, so a caller cannot create an I/O alias.
use crate::{
    api_v4::{CleanupStatus, ReadStreamStatus, StreamReadPermit, TransportEnvironment},
    crypto_v4::Stream,
    environment_v4::{
        EnvironmentCharge, EnvironmentError, EnvironmentRoot, ResourceAccount, ResourceCharge,
        ResourceLimits,
    },
    transport::SessionError,
};
use bytes::Bytes;
use std::{
    io,
    net::{Shutdown, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpSocket, TcpStream},
    sync::Notify,
    time::{Instant, sleep_until},
};
use tokio_util::sync::CancellationToken;

/// Concrete limits for the SDK-owned native endpoint.  Socket buffer requests
/// are OS configuration, not a whole-process RSS or remote-consumption proof.
#[derive(Clone, Copy, Debug)]
pub struct NativeTcpDuplexOptions {
    pub connect_timeout: Duration,
    pub prepared_timeout: Duration,
    pub send_buffer_bytes: u32,
    pub receive_buffer_bytes: u32,
}
impl Default for NativeTcpDuplexOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            prepared_timeout: Duration::from_secs(60),
            send_buffer_bytes: 64 * 1024,
            receive_buffer_bytes: 64 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeTcpDuplexInfo {
    pub requested_send_buffer_bytes: u32,
    pub requested_receive_buffer_bytes: u32,
    pub observed_send_buffer_bytes: u32,
    pub observed_receive_buffer_bytes: u32,
    pub sdk_owned_socket: bool,
    pub half_close: bool,
    pub kernel_queue_hard_bound: bool,
    pub authenticated_send_drain: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeTcpDuplexError {
    #[error("invalid native TCP endpoint options")]
    InvalidOptions,
    #[error("native TCP endpoint resource capacity is exhausted")]
    Capacity,
    #[error("native TCP endpoint connection failed")]
    ConnectFailed,
    #[error("native TCP endpoint deadline expired")]
    Deadline,
    #[error("native TCP endpoint is closed")]
    Closed,
    #[error("native TCP endpoint owner is unavailable")]
    OwnerUnavailable,
}
enum SocketCharge {
    Root(EnvironmentCharge),
    Session { _charge: ResourceCharge },
}
struct SocketRetirement(Arc<std::sync::atomic::AtomicBool>);
impl Drop for SocketRetirement {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
struct Socket {
    io: TcpStream,
    shutdown: std::net::TcpStream,
    charge: Mutex<SocketCharge>,
    // This final field drops after both descriptors and the actual charge.
    _retirement: SocketRetirement,
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }
}
impl Socket {
    fn attach_prepaid(
        &self,
        account: &ResourceAccount,
        charge: ResourceCharge,
    ) -> Result<(), SessionError> {
        let mut current = self.charge.lock().expect("native socket charge");
        let original = match &mut *current {
            SocketCharge::Root(original) => original,
            SocketCharge::Session { .. } => return Err(SessionError::OperationFailed),
        };
        let transferred = original
            .attach_prepaid(account, charge)
            .map_err(session_resource_error)?;
        *current = SocketCharge::Session {
            _charge: transferred,
        };
        Ok(())
    }
}
struct NativeState {
    socket: Option<Arc<Socket>>,
    claimed: bool,
    closed: bool,
    write_closed: bool,
    read_eof: bool,
}
struct Core {
    root: Arc<EnvironmentRoot>,
    state: Mutex<NativeState>,
    changed: Notify,
    handles: AtomicUsize,
    monitor_done: std::sync::atomic::AtomicBool,
    physical_retired: Arc<std::sync::atomic::AtomicBool>,
    info: NativeTcpDuplexInfo,
    // Facade aliases retain metadata after the physical socket retires.
    _charge: EnvironmentCharge,
}
impl Core {
    fn close(&self) {
        let socket = {
            let mut state = self.state.lock().expect("native TCP owner");
            state.closed = true;
            state.socket.take()
        };
        if let Some(socket) = socket {
            let _ = socket.shutdown.shutdown(Shutdown::Both);
        }
        self.changed.notify_waiters();
    }
    fn expire_unclaimed(&self) {
        let socket = {
            let mut state = self.state.lock().expect("native TCP owner");
            if state.claimed {
                return;
            }
            state.closed = true;
            state.socket.take()
        };
        if let Some(socket) = socket {
            let _ = socket.shutdown.shutdown(Shutdown::Both);
        }
        self.changed.notify_waiters();
    }
    fn socket(&self) -> Result<Arc<Socket>, SessionError> {
        let state = self.state.lock().expect("native TCP owner");
        if state.closed || self.root.is_closed() {
            return Err(SessionError::Closed);
        }
        state.socket.clone().ok_or(SessionError::Closed)
    }
    fn cleanup_status(&self) -> CleanupStatus {
        let state = self.state.lock().expect("native TCP owner");
        let complete = state.closed
            && self.physical_retired.load(Ordering::Acquire)
            && self.monitor_done.load(Ordering::Acquire);
        CleanupStatus {
            complete,
            cleanup_incomplete: false,
            pending_callbacks: u64::from(!complete),
        }
    }
}

/// SDK-created TCP socket with complete original ownership and real write
/// half-close.  It accepts no external socket and exports no socket handle.
/// Clones share one owner; only one bridge may claim that owner.
pub struct NativeTcpDuplex {
    core: Arc<Core>,
}
impl std::fmt::Debug for NativeTcpDuplex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeTcpDuplex")
            .field("info", &self.info())
            .finish()
    }
}
impl Clone for NativeTcpDuplex {
    fn clone(&self) -> Self {
        self.core.handles.fetch_add(1, Ordering::AcqRel);
        Self {
            core: self.core.clone(),
        }
    }
}
impl Drop for NativeTcpDuplex {
    fn drop(&mut self) {
        if self.core.handles.fetch_sub(1, Ordering::AcqRel) == 1 {
            let close = !self.core.state.lock().expect("native TCP owner").claimed;
            if close {
                self.core.expire_unclaimed();
            }
        }
    }
}
impl NativeTcpDuplex {
    /// Create a fresh socket inside the environment's original physical budget.
    /// Numeric addresses avoid an unbounded DNS/lookup adapter responsibility.
    /// Dropping the connect future closes its privately owned partial socket.
    pub async fn connect(
        environment: &TransportEnvironment,
        address: SocketAddr,
        options: NativeTcpDuplexOptions,
    ) -> Result<Self, NativeTcpDuplexError> {
        if options.connect_timeout.is_zero()
            || options.connect_timeout > Duration::from_secs(60)
            || options.prepared_timeout.is_zero()
            || options.prepared_timeout > Duration::from_secs(24 * 60 * 60)
            || options.send_buffer_bytes == 0
            || options.receive_buffer_bytes == 0
            || options.send_buffer_bytes > 4 * 1024 * 1024
            || options.receive_buffer_bytes > 4 * 1024 * 1024
        {
            return Err(NativeTcpDuplexError::InvalidOptions);
        }
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| NativeTcpDuplexError::OwnerUnavailable)?;
        let root = environment.root().clone();
        // Runtime descriptor/registration backing is distinct from external
        // kernel queues.  The latter are explicitly reported without a hard
        // memory guarantee; no caller budget label manufactures one.
        let charge = root
            .reserve_environment(Self::bridge_resources())
            .map_err(native_resource_error)?;
        let monitor_charge = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 256,
                tasks: 1,
                timers: 1,
                items: 1,
                work_slots: 1,
                ..ResourceLimits::default()
            })
            .map_err(native_resource_error)?;
        let facade_charge = root
            .reserve_environment(ResourceLimits {
                sdk_bytes: 512,
                items: 1,
                ..ResourceLimits::default()
            })
            .map_err(native_resource_error)?;
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        }
        .map_err(|_| NativeTcpDuplexError::ConnectFailed)?;
        socket
            .set_send_buffer_size(options.send_buffer_bytes)
            .map_err(|_| NativeTcpDuplexError::ConnectFailed)?;
        socket
            .set_recv_buffer_size(options.receive_buffer_bytes)
            .map_err(|_| NativeTcpDuplexError::ConnectFailed)?;
        let observed_send_buffer_bytes = socket
            .send_buffer_size()
            .map_err(|_| NativeTcpDuplexError::ConnectFailed)?;
        let observed_receive_buffer_bytes = socket
            .recv_buffer_size()
            .map_err(|_| NativeTcpDuplexError::ConnectFailed)?;
        let deadline = Instant::now() + options.connect_timeout;
        let socket = tokio::select! {
            biased;
            _ = wait_root_closed(&root) => return Err(NativeTcpDuplexError::Closed),
            result = socket.connect(address) => result.map_err(|_| NativeTcpDuplexError::ConnectFailed)?,
            _ = sleep_until(deadline) => return Err(NativeTcpDuplexError::Deadline),
        };
        if root.is_closed() {
            return Err(NativeTcpDuplexError::Closed);
        }
        // The additional descriptor stays private and performs only OS
        // shutdown; both descriptors share the same actual socket queues.
        let shutdown = socket
            .into_std()
            .map_err(|_| NativeTcpDuplexError::ConnectFailed)?;
        let io = shutdown
            .try_clone()
            .and_then(TcpStream::from_std)
            .map_err(|_| NativeTcpDuplexError::ConnectFailed)?;
        let physical_retired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let socket = Arc::new(Socket {
            io,
            shutdown,
            charge: Mutex::new(SocketCharge::Root(charge)),
            _retirement: SocketRetirement(physical_retired.clone()),
        });
        let core = Arc::new(Core {
            root,
            state: Mutex::new(NativeState {
                socket: Some(socket),
                claimed: false,
                closed: false,
                write_closed: false,
                read_eof: false,
            }),
            changed: Notify::new(),
            handles: AtomicUsize::new(1),
            monitor_done: std::sync::atomic::AtomicBool::new(false),
            physical_retired,
            info: NativeTcpDuplexInfo {
                requested_send_buffer_bytes: options.send_buffer_bytes,
                requested_receive_buffer_bytes: options.receive_buffer_bytes,
                observed_send_buffer_bytes,
                observed_receive_buffer_bytes,
                sdk_owned_socket: true,
                half_close: true,
                kernel_queue_hard_bound: false,
                authenticated_send_drain: false,
            },
            _charge: facade_charge,
        });
        let monitor = core.clone();
        let prepared_deadline = Instant::now() + options.prepared_timeout;
        // Construct the retirement owner before spawning. Runtime shutdown
        // may drop this task before its future has ever been polled.
        let retirement = MonitorRetirement {
            core: monitor.clone(),
            charge: Some(monitor_charge),
        };
        runtime.spawn(async move {
            let _retirement = retirement;
            loop {
                let changed = monitor.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let state = monitor.state.lock().expect("native TCP owner");
                    if state.claimed || state.closed {
                        break;
                    }
                }
                if monitor.root.is_closed() || Instant::now() >= prepared_deadline {
                    monitor.expire_unclaimed();
                    break;
                }
                tokio::select! {
                    _ = changed => {},
                    _ = sleep_until(prepared_deadline) => {},
                    _ = wait_root_closed(&monitor.root) => {},
                }
            }
        });
        Ok(Self { core })
    }
    pub(crate) fn bridge_resources() -> ResourceLimits {
        ResourceLimits {
            sdk_bytes: 4096,
            provider_bytes: 32768,
            items: 1,
            native_handles: 2,
            connections: 1,
            tasks: 1,
            timers: 1,
            work_slots: 1,
            ..ResourceLimits::default()
        }
    }
    pub fn info(&self) -> NativeTcpDuplexInfo {
        self.core.info
    }
    pub fn close(&self) -> Result<(), NativeTcpDuplexError> {
        let socket = {
            let mut state = self.core.state.lock().expect("native TCP owner");
            if state.claimed {
                return Err(NativeTcpDuplexError::OwnerUnavailable);
            }
            state.closed = true;
            state.socket.take()
        };
        if let Some(socket) = socket {
            let _ = socket.shutdown.shutdown(Shutdown::Both);
        }
        self.core.changed.notify_waiters();
        Ok(())
    }
    pub async fn wait_cleanup(&self, timeout: Duration) -> CleanupStatus {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(5));
        loop {
            let mut status = self.cleanup_status();
            if status.complete {
                return status;
            }
            if Instant::now() >= deadline {
                status.cleanup_incomplete = true;
                return status;
            }
            tokio::select! {
                _ = self.core.changed.notified() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }
    pub fn cleanup_status(&self) -> CleanupStatus {
        self.core.cleanup_status()
    }
    pub(crate) fn check_bridge_owner(&self, stream: &Stream) -> Result<(), SessionError> {
        let state = self.core.state.lock().expect("native TCP owner");
        if state.claimed
            || state.closed
            || state.socket.is_none()
            || !Arc::ptr_eq(&self.core.root, stream.account().environment_root())
        {
            return Err(SessionError::OperationFailed);
        }
        Ok(())
    }
    /// Only the bridge that acquired the original owner controls I/O/close.
    pub(crate) fn claim_with_stream(
        &self,
        stream: &Stream,
        charge: ResourceCharge,
    ) -> Result<(NativeTcpClaim, Stream, StreamReadPermit), SessionError> {
        let mut state = self.core.state.lock().expect("native TCP owner");
        if state.claimed
            || state.closed
            || state.socket.is_none()
            || !Arc::ptr_eq(&self.core.root, stream.account().environment_root())
        {
            return Err(SessionError::OperationFailed);
        }
        let socket = state.socket.as_ref().ok_or(SessionError::Closed)?;
        let account = stream.account();
        let (stream, permit) =
            stream.claim_bridge_endpoint_with(|| socket.attach_prepaid(&account, charge))?;
        state.claimed = true;
        drop(state);
        self.core.changed.notify_waiters();
        Ok((
            NativeTcpClaim {
                core: self.core.clone(),
            },
            stream,
            permit,
        ))
    }
}

// The notification is installed before checking closed, so shutdown between
// the check and await cannot strand a private in-progress connect or monitor.
async fn wait_root_closed(root: &EnvironmentRoot) {
    loop {
        let changed = root.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if root.is_closed() {
            return;
        }
        changed.await;
    }
}
struct MonitorRetirement {
    core: Arc<Core>,
    charge: Option<EnvironmentCharge>,
}
impl Drop for MonitorRetirement {
    fn drop(&mut self) {
        self.core.expire_unclaimed();
        drop(self.charge.take());
        self.core.monitor_done.store(true, Ordering::Release);
        self.core.changed.notify_waiters();
    }
}

pub(crate) struct NativeTcpClaim {
    core: Arc<Core>,
}
impl Drop for NativeTcpClaim {
    fn drop(&mut self) {
        self.core.close();
    }
}
impl NativeTcpClaim {
    pub(crate) async fn read_piece(
        &self,
        account: &ResourceAccount,
        maximum: usize,
        stop: &CancellationToken,
        gate: &Mutex<()>,
        commit: impl Fn(Bytes) + Send + Sync,
    ) -> Result<ReadStreamStatus, SessionError> {
        let result_account = account.reserve_result().map_err(session_resource_error)?;
        let charge = result_account
            .reserve(ResourceLimits {
                sdk_bytes: maximum as u64,
                ..ResourceLimits::default()
            })
            .map_err(session_resource_error)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(maximum)
            .map_err(|_| SessionError::ResourceExhausted)?;
        buffer.resize(maximum, 0);
        let mut payload = Some(NativePayload {
            bytes: buffer,
            _charge: charge,
        });
        let socket = self.core.socket()?;
        loop {
            socket.io.readable().await.map_err(native_io_error)?;
            let transferred = {
                let _transfer = gate.lock().expect("bridge read gate");
                if stop.is_cancelled() {
                    return Err(SessionError::Canceled);
                }
                let read = account
                    .with_security(|| {
                        socket
                            .io
                            .try_read(&mut payload.as_mut().expect("native payload").bytes)
                    })
                    .map_err(session_resource_error)?;
                match read {
                    Ok(count) => {
                        let mut payload = payload.take().expect("native payload");
                        payload.bytes.truncate(count);
                        result_account.detach_result();
                        commit(Bytes::from_owner(payload));
                        if count == 0 {
                            self.core.state.lock().expect("native TCP owner").read_eof = true;
                        }
                        Some(if count == 0 {
                            ReadStreamStatus::Eof
                        } else {
                            ReadStreamStatus::Open
                        })
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                    Err(error) => return Err(native_io_error(error)),
                }
            };
            if let Some(status) = transferred {
                return Ok(status);
            }
        }
    }
    pub(crate) async fn write_piece(
        &self,
        account: &ResourceAccount,
        payload: &[u8],
        stop: &CancellationToken,
        gate: &Mutex<()>,
        accepted: impl Fn(usize) + Send + Sync,
    ) -> Result<usize, SessionError> {
        let socket = self.core.socket()?;
        loop {
            socket.io.writable().await.map_err(native_io_error)?;
            let written = {
                let _admission = gate.lock().expect("bridge native write gate");
                if stop.is_cancelled() {
                    return Err(SessionError::Canceled);
                }
                let write = account
                    .with_security(|| socket.io.try_write(payload))
                    .map_err(session_resource_error)?;
                match write {
                    Ok(0) => return Err(SessionError::OperationFailed),
                    Ok(count) => {
                        accepted(count);
                        Some(count)
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
                    Err(error) => return Err(native_io_error(error)),
                }
            };
            if let Some(count) = written {
                return Ok(count);
            }
        }
    }
    pub(crate) fn close_write(&self) -> Result<(), SessionError> {
        let socket = self.core.socket()?;
        let mut state = self.core.state.lock().expect("native TCP owner");
        if state.closed {
            return Err(SessionError::Closed);
        }
        if state.write_closed {
            return Ok(());
        }
        socket
            .shutdown
            .shutdown(Shutdown::Write)
            .map_err(native_io_error)?;
        state.write_closed = true;
        Ok(())
    }
    pub(crate) fn finish(&self) -> Result<(), SessionError> {
        let state = self.core.state.lock().expect("native TCP owner");
        if state.closed || !state.write_closed || !state.read_eof {
            return Err(SessionError::Closed);
        }
        // All successful try_write calls precede this OS write half-close.
        // This is local queue/FIN ordering, never Flowersec DRAINED proof.
        Ok(())
    }
    pub(crate) fn retire(&self) {
        self.core.close();
    }
    pub(crate) fn cleanup_status(&self) -> CleanupStatus {
        self.core.cleanup_status()
    }
    pub(crate) async fn wait_cleanup(&self) -> CleanupStatus {
        loop {
            let status = self.cleanup_status();
            if status.complete {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
struct NativePayload {
    bytes: Vec<u8>,
    _charge: ResourceCharge,
}
impl AsRef<[u8]> for NativePayload {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
fn native_resource_error(error: EnvironmentError) -> NativeTcpDuplexError {
    if error == EnvironmentError::Capacity {
        NativeTcpDuplexError::Capacity
    } else {
        NativeTcpDuplexError::Closed
    }
}
fn session_resource_error(error: EnvironmentError) -> SessionError {
    match error {
        EnvironmentError::Capacity => SessionError::ResourceExhausted,
        EnvironmentError::Closed => SessionError::Closed,
        _ => SessionError::OperationFailed,
    }
}
fn native_io_error(error: io::Error) -> SessionError {
    match error.kind() {
        io::ErrorKind::TimedOut => SessionError::Timeout,
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => SessionError::StreamReset,
        _ => SessionError::OperationFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn root_close_wakes_an_already_registered_connect_wait() {
        let environment = TransportEnvironment::new();
        let root = environment.root().clone();
        let closed = wait_root_closed(&root);
        tokio::pin!(closed);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(closed.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        root.close();
        tokio::time::timeout(Duration::from_millis(100), closed)
            .await
            .unwrap();
        assert!(environment.cleanup_status().complete);
    }
}
