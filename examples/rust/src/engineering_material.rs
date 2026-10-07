//! Explicit local acceptance deployment. This adapter never discovers trust
//! from peer bytes and never reopens a previous process's spend history.
use flowersec::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn invalid() -> std::io::Error {
    std::io::Error::other("invalid trusted engineering material")
}
fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut data)?;
    if data.is_empty() || data.len() > maximum {
        return Err(invalid().into());
    }
    Ok(data)
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().ok_or_else(|| invalid().into())
}
fn bytes(value: &Value, key: &str, maximum: usize) -> Result<Vec<u8>> {
    let encoded = text(value, key)?;
    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)?;
    if decoded.is_empty() || decoded.len() > maximum {
        return Err(invalid().into());
    }
    Ok(decoded)
}
fn fixed<const N: usize>(value: &Value, key: &str) -> Result<[u8; N]> {
    bytes(value, key, N)?
        .try_into()
        .map_err(|_| invalid().into())
}

// This is a finite host-configuration reader, not a signature verifier. The
// SDK verifies every credential independently before material acquisition.
#[derive(Debug)]
enum Cbor {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array,
    Map(Vec<(u64, Cbor)>),
    Scalar,
}
impl Cbor {
    fn parse(input: &[u8]) -> Result<Self> {
        fn item(input: &[u8], offset: &mut usize, depth: usize, nodes: &mut usize) -> Result<Cbor> {
            *nodes += 1;
            if depth > 24 || *nodes > 16384 {
                return Err(invalid().into());
            }
            let initial = *input.get(*offset).ok_or_else(invalid)?;
            *offset += 1;
            let size = match initial & 31 {
                n @ 0..=23 => u64::from(n),
                n @ 24..=27 => {
                    let count = 1usize << (n - 24);
                    let end = (*offset).checked_add(count).ok_or_else(invalid)?;
                    let raw = input.get(*offset..end).ok_or_else(invalid)?;
                    *offset = end;
                    raw.iter()
                        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
                }
                _ => return Err(invalid().into()),
            };
            match initial >> 5 {
                0 => Ok(Cbor::Uint(size)),
                2 | 3 => {
                    let count = usize::try_from(size)?;
                    let end = (*offset).checked_add(count).ok_or_else(invalid)?;
                    let raw = input.get(*offset..end).ok_or_else(invalid)?;
                    *offset = end;
                    if initial >> 5 == 2 {
                        Ok(Cbor::Bytes(raw.to_vec()))
                    } else {
                        Ok(Cbor::Text(std::str::from_utf8(raw)?.to_owned()))
                    }
                }
                4 => {
                    if size > 1024 {
                        return Err(invalid().into());
                    }
                    for _ in 0..size {
                        item(input, offset, depth + 1, nodes)?;
                    }
                    Ok(Cbor::Array)
                }
                5 => {
                    if size > 1024 {
                        return Err(invalid().into());
                    }
                    let mut fields = Vec::new();
                    for _ in 0..size {
                        let Cbor::Uint(key) = item(input, offset, depth + 1, nodes)? else {
                            return Err(invalid().into());
                        };
                        fields.push((key, item(input, offset, depth + 1, nodes)?));
                    }
                    Ok(Cbor::Map(fields))
                }
                7 => Ok(Cbor::Scalar),
                _ => Err(invalid().into()),
            }
        }
        let mut offset = 0;
        let mut nodes = 0;
        let result = item(input, &mut offset, 0, &mut nodes)?;
        if offset != input.len() {
            return Err(invalid().into());
        }
        Ok(result)
    }
    fn field(&self, key: u64) -> Result<&Self> {
        if let Self::Map(fields) = self {
            fields
                .iter()
                .find(|(id, _)| *id == key)
                .map(|(_, value)| value)
                .ok_or_else(|| invalid().into())
        } else {
            Err(invalid().into())
        }
    }
    fn uint(&self) -> Result<u64> {
        if let Self::Uint(value) = self {
            Ok(*value)
        } else {
            Err(invalid().into())
        }
    }
    fn text(&self) -> Result<&str> {
        if let Self::Text(value) = self {
            Ok(value)
        } else {
            Err(invalid().into())
        }
    }
    fn fixed<const N: usize>(&self) -> Result<[u8; N]> {
        if let Self::Bytes(value) = self {
            value.as_slice().try_into().map_err(|_| invalid().into())
        } else {
            Err(invalid().into())
        }
    }
}
#[derive(Debug)]
struct EngineeringClock {
    anchor: Instant,
    epoch_ms: u64,
}
impl TrustedTimeSource for EngineeringClock {
    fn sample(&self) -> std::result::Result<TrustedTimeSample, EnvironmentError> {
        let monotonic_sample = Instant::now();
        let elapsed = u64::try_from(monotonic_sample.duration_since(self.anchor).as_millis())
            .map_err(|_| EnvironmentError::TimeUnavailable)?;
        let now = self
            .epoch_ms
            .checked_add(elapsed)
            .ok_or(EnvironmentError::TimeUnavailable)?;
        Ok(TrustedTimeSample {
            lower_ms: now,
            upper_ms: now,
            monotonic_sample,
            clock_incarnation: 1,
            anchor_age_upper_ms: elapsed,
        })
    }
}
#[derive(Debug)]
struct FreshHistory {
    path: PathBuf,
    identity: SQLitePoolIdentity,
    epoch: AtomicU64,
}
impl SQLitePoolContinuity for FreshHistory {
    fn check(
        &self,
        identity: &SQLitePoolIdentity,
        epoch: u64,
        _: bool,
    ) -> std::result::Result<(), PoolStoreError> {
        let fail = || PoolStoreError {
            code: PoolStoreFailure::HistoryUnknown,
            write_state: PoolWriteState::NotSubmitted,
            format: None,
        };
        if identity != &self.identity
            || std::fs::read(&self.path).map_err(|_| fail())? != self.identity.store_id
        {
            return Err(fail());
        }
        let previous = self.epoch.fetch_max(epoch, Ordering::AcqRel);
        if epoch < previous {
            return Err(fail());
        }
        Ok(())
    }
}
pub struct EngineeringClient {
    pub environment: Arc<TransportEnvironment>,
    pub source: ConnectionMaterialSource,
    pub store: Arc<SQLitePoolStore>,
    pub backing: SQLitePoolBacking,
}
impl EngineeringClient {
    pub async fn open(
        material_path: &Path,
        trust_der_path: &Path,
        receipt_path: &Path,
    ) -> Result<Self> {
        if receipt_path.exists() {
            return Err(std::io::Error::other("material already has a spend receipt").into());
        }
        let raw = read_bounded(material_path, 1 << 20)?;
        let material: Value = serde_json::from_slice(&raw)?;
        if material["wire_revision"] != 4
            || material["role"] != 0
            || material["source"] != "preauthorized_pool"
        {
            return Err(invalid().into());
        }
        let profile = text(&material, "profile")?;
        let _generation_source: [u8; 16] = fixed(&material["generation"], "source")?;
        if material["generation"]["generation"]
            .as_u64()
            .is_none_or(|value| value == 0)
        {
            return Err(invalid().into());
        }
        let artifact = bytes(&material, "artifact", 65536)?;
        let activation = bytes(&material, "activation", 4096)?;
        let client_certificate = bytes(&material, "client_certificate", 8192)?;
        let server_certificate = bytes(&material, "server_certificate", 8192)?;
        let artifact_fields = Cbor::parse(&artifact)?;
        let activation_fields = Cbor::parse(&activation)?;
        if artifact_fields.field(3)?.text()? != profile {
            return Err(invalid().into());
        }
        let tenant = artifact_fields.field(4)?.text()?.to_owned();
        let issuer = artifact_fields.field(5)?.fixed::<16>()?;
        let authority = activation_fields
            .field(7)?
            .field(4)?
            .field(2)?
            .text()?
            .to_owned();
        let application_profile = match artifact_fields.field(13)?.field(5)?.uint()? {
            0 => ApplicationProfile::Transport,
            1 => ApplicationProfile::Services,
            2 => ApplicationProfile::Execution,
            _ => return Err(invalid().into()),
        };
        let clock = EngineeringClock {
            anchor: Instant::now(),
            epoch_ms: u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())?,
        };
        let environment = Arc::new(TransportEnvironment::with_options(
            TransportEnvironmentOptions {
                clock: Some(Arc::new(clock)),
                ..TransportEnvironmentOptions::default()
            },
        )?);
        let roots_der = vec![read_bounded(trust_der_path, 65536)?];
        let mut namespaces = Vec::new();
        let records = material["namespaces"].as_array().ok_or_else(invalid)?;
        if records.is_empty() || records.len() > 3 {
            return Err(invalid().into());
        }
        for record in records {
            if text(record, "tenant")? != tenant {
                return Err(invalid().into());
            }
            let namespace = environment.namespace(
                NamespaceTrustRoot {
                    tenant: tenant.clone(),
                    authority: text(record, "authority")?.to_owned(),
                    key_id: fixed(record, "root_key_id")?,
                    public_key: fixed(record, "root_public_key")?,
                    max_lifetime_ms: 30_000_000,
                },
                65536,
                8192,
            )?;
            namespace.bootstrap_from(|original| async {
                let url = text(record, "bootstrap_url")?.to_owned();
                let body = serde_json::to_vec(
                    &json!({ "tenant": tenant, "authority": text(record, "authority")?,
                    "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, original.nonce()) }),
                )?;
                let trust = roots_der[0].clone();
                // Curl retains its original 10-second bound. The blocking worker
                // owns the SDK custody through ChildOwner's actual kill/wait and
                // root-file cleanup, even if its observing future is canceled.
                let (snapshot, _physical_tail) =
                    spawn_bootstrap_worker(original, url, trust, body).await?;
                let snapshot: Value = serde_json::from_slice(&snapshot?)?;
                let response = bytes(&snapshot, "response", 32768)?;
                let state = bytes(&snapshot, "state", 65536)?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>((response, state))
            }).await?;
            namespaces.push(namespace);
        }
        let identity = environment.import_identity_keys(
            profile,
            fixed(&material, "identity_seed")?,
            fixed(&material, "dh_seed")?,
        )?;
        let parent =
            std::fs::canonicalize(receipt_path.parent().unwrap_or_else(|| Path::new(".")))?;
        let owned_receipt = parent.join(receipt_path.file_name().ok_or_else(invalid)?);
        let database = owned_receipt.with_extension("pool.sqlite");
        let marker = owned_receipt.with_extension("pool.history");
        if database.exists() || marker.exists() {
            return Err(std::io::Error::other("engineering history must be fresh").into());
        }
        let store_id: [u8; 32] =
            Sha256::digest([raw.as_slice(), receipt_path.as_os_str().as_encoded_bytes()].concat())
                .into();
        let pool_identity = SQLitePoolIdentity {
            authority,
            store_id,
            generation: 1,
        };
        let mut history = exclusive_file(&marker)?;
        history.write_all(&store_id)?;
        history.sync_all()?;
        sync_parent_directory(&marker)?;
        let continuity = Arc::new(FreshHistory {
            path: marker,
            identity: pool_identity.clone(),
            epoch: AtomicU64::new(0),
        });
        let backing = environment.sqlite_pool_backing(
            database,
            SQLitePoolLimits {
                max_pages: 64,
                max_records: 8,
                max_record_bytes: 65536,
                provider_runtime_bytes: 1 << 20,
                disk_overhead_bytes: 65536,
            },
        )?;
        let store = backing.open(SQLitePoolOptions {
            identity: pool_identity,
            continuity,
            bindings: vec![SQLitePoolBinding {
                tenant: tenant.clone(),
                issuer,
            }],
            create: true,
        })?;
        let provider = WssConnectOptions {
            binding_mode: BindingMode::AuthenticatedContext,
            remote_address: std::net::Ipv4Addr::LOCALHOST.into(),
            origin: std::env::var("FSEC_ORIGIN").ok(),
            ca_certificates_der: roots_der,
            timeout: Duration::from_secs(10),
            publication_timeout: Duration::from_secs(2),
            queue_messages: 2,
            prepare_bytes: 65536,
            native_runtime_bytes: 1 << 20,
        };
        let route = Cbor::parse(&bytes(&material, "route", 16384)?)?;
        let kind = route.field(0)?.uint()?;
        let connection = PoolCredentialBytes {
            artifact,
            activation,
            client_certificate,
            server_certificate,
        };
        let source = if kind == 0 {
            if material["tunnels"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty())
                || !material["server_allow"].is_null()
            {
                return Err(invalid().into());
            }
            LocalDirectMaterialSource::preauthorized_pool(
                &environment,
                PreauthorizedPoolSourceConfiguration {
                    namespaces,
                    identity,
                    credentials: vec![connection],
                    spend_ledger: store.clone(),
                    provider,
                    application_profile,
                },
            )?
        } else {
            if kind != 1
                || route.field(3)?.field(3)?.uint()? != 0
                || route.field(3)?.field(4)?.uint()? != 2
            {
                return Err(std::io::Error::other(
                    "example requires the original client dialer tunnel leg",
                )
                .into());
            }
            let entries = material["tunnels"].as_array().ok_or_else(invalid)?;
            if entries.len() != 2 {
                return Err(invalid().into());
            }
            let mut local = entries
                .iter()
                .filter(|entry| entry["candidate_index"] == 0 && entry["role"] == 0);
            let mut remote = entries
                .iter()
                .filter(|entry| entry["candidate_index"] == 0 && entry["role"] == 1);
            let local = local.next().ok_or_else(invalid)?;
            let remote = remote.next().ok_or_else(invalid)?;
            let relay_certificate = bytes(local, "relay_certificate", 8192)?;
            if relay_certificate != bytes(remote, "relay_certificate", 8192)? {
                return Err(invalid().into());
            }
            let allow = pool_server_allow(
                &material,
                &tenant,
                artifact_fields.field(11)?.text()?,
                bytes(remote, "grant", 9302)?,
            )?;
            LocalDirectMaterialSource::preauthorized_tunnel_pool_with_server_allow(
                &environment,
                PreauthorizedTunnelPoolSourceConfiguration {
                    namespaces,
                    identity,
                    credentials: vec![TunnelPoolCredentialBytes {
                        connection,
                        grant: bytes(local, "grant", 9302)?,
                        relay_certificate,
                    }],
                    spend_ledger: store.clone(),
                    provider,
                    application_profile,
                    // This engineering issuer's independently installed hop scopes.
                    relay_service: artifact_fields.field(11)?.text()?.to_owned(),
                    relay_audience: "flowersec.parity.relay".into(),
                },
                vec![allow],
            )?
        };
        Ok(Self {
            environment,
            source,
            store,
            backing,
        })
    }
    pub async fn connect(&self) -> Result<Session> {
        Ok(flowersec_rust_client_example::connect_current(
            &self.environment,
            &self.source,
            ConnectionRequirements {
                local_consumer_tls13_verification: true,
                application_profile: Some("services".into()),
                ..ConnectionRequirements::default()
            },
            CancellationToken::new(),
        )
        .await
        .map_err(|error| {
            eprintln!("connection_error={:?}", error.connection_facts());
            error
        })?)
    }
    pub fn commit_spend_receipt(&self, path: &Path) -> Result<()> {
        let acquisition = self.source.acquisition_observation();
        let observation = self.store.spend_observation().ok_or_else(invalid)?;
        if acquisition.acquisitions != 1 || observation.state != PoolSpendState::CommitKnown {
            return Err(invalid().into());
        }
        println!(
            "source_acquisitions={} pool_spend=commit_known",
            acquisition.acquisitions
        );
        commit_spend_receipt(path)
    }
    pub async fn close(self) -> Result<()> {
        let Self {
            environment,
            source,
            store,
            backing,
        } = self;
        source.close();
        store.close();
        backing.close();
        let store_complete = store.cleanup_complete();
        let retained_disk = backing.retained_disk_bytes();
        drop(source);
        drop(store);
        drop(backing);
        let status = environment.close().await?;
        let usage = environment.resource_usage();
        eprintln!(
            "environment_cleanup_complete={} retained_history_bytes={retained_disk}",
            status.complete
        );
        // Persistent spend history remains charged after Close. Active runtime
        // resources must nevertheless have physically retired.
        if !store_complete
            || usage.provider_bytes != 0
            || usage.tasks != 0
            || usage.timers != 0
            || usage.work_slots > u64::from(retained_disk != 0)
            || usage.connections != 0
            || usage.tls_handshakes != 0
            || usage.sessions != 0
            || usage.native_handles != 0
        {
            return Err(
                std::io::Error::other("Environment active cleanup remains incomplete").into(),
            );
        }
        Ok(())
    }
}
fn exclusive_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
pub fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let directory = File::open(path.parent().unwrap_or_else(|| Path::new(".")))?;
    directory.sync_all()
}
pub fn commit_spend_receipt(path: &Path) -> Result<()> {
    let mut receipt = exclusive_file(path)?;
    receipt.write_all(b"flowersec-v4-material-spent\n")?;
    receipt.sync_all()?;
    sync_parent_directory(path)?;
    Ok(())
}
fn spawn_bootstrap_worker(
    original: NamespaceBootstrapRequest,
    url: String,
    trust: Vec<u8>,
    body: Vec<u8>,
) -> tokio::task::JoinHandle<(Result<Vec<u8>>, NamespaceBootstrapRequest)> {
    tokio::task::spawn_blocking(move || {
        let result = bootstrap(&url, &trust, &body);
        (result, original)
    })
}

struct ChildOwner(std::process::Child);
impl Drop for ChildOwner {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn bootstrap(url: &str, root_der: &[u8], body: &[u8]) -> Result<Vec<u8>> {
    let endpoint = url::Url::parse(url)?;
    if !matches!(endpoint.scheme(), "https" | "http")
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || endpoint.scheme() == "http"
            && !matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost"))
    {
        return Err(invalid().into());
    }
    // The local acceptance host is explicit. Curl does not follow redirects,
    // use cookies or inherit proxies; TLS uses only this installed test root.
    let root = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, root_der)
    );
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root_path = std::env::temp_dir().join(format!(
        "flowersec-rust-root-{}-{nonce}.pem",
        std::process::id()
    ));
    let mut file = exclusive_file(&root_path)?;
    let outcome: Result<Vec<u8>> = (|| {
        file.write_all(root.as_bytes())?;
        let mut command = Command::new("curl");
        command
            .args([
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "10",
                "--max-filesize",
                "65536",
                "--noproxy",
                "*",
                "--proto",
                "=http,https",
                "--tlsv1.3",
                "--tls-max",
                "1.3",
                "--cacert",
            ])
            .arg(&root_path)
            .args([
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
            ]);
        let port = endpoint.port_or_known_default().ok_or_else(invalid)?;
        let resolution = format!(
            "{}:{port}:127.0.0.1",
            endpoint.host_str().ok_or_else(invalid)?
        );
        command
            .args(["--resolve", &resolution, url])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = ChildOwner(command.spawn()?);
        child.0.stdin.take().ok_or_else(invalid)?.write_all(body)?;
        let mut output = Vec::new();
        child
            .0
            .stdout
            .take()
            .ok_or_else(invalid)?
            .take(65537)
            .read_to_end(&mut output)?;
        if output.len() > 65536 {
            let _ = child.0.kill();
            let _ = child.0.wait();
            return Err(invalid().into());
        }
        if !child.0.wait()?.success() {
            return Err(std::io::Error::other("trusted namespace bootstrap failed").into());
        }
        Ok(output)
    })();
    if let Err(error) = std::fs::remove_file(root_path) {
        eprintln!("bootstrap_root_cleanup_error={error}");
        if outcome.is_ok() {
            return Err(error.into());
        }
    }
    outcome
}

fn pem_blocks(input: &str, label: &str, maximum: usize, count: usize) -> Result<Vec<Vec<u8>>> {
    if input.is_empty() || input.len() > maximum {
        return Err(invalid().into());
    }
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut remaining = input;
    let mut blocks = Vec::new();
    while !remaining.trim().is_empty() {
        remaining = remaining.trim_start();
        let body = remaining.strip_prefix(&begin).ok_or_else(invalid)?;
        let (encoded, tail) = body.split_once(&end).ok_or_else(invalid)?;
        let encoded: String = encoded
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect();
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &encoded)?;
        if bytes.is_empty() || bytes.len() > 65536 || blocks.len() >= count {
            return Err(invalid().into());
        }
        blocks.push(bytes);
        remaining = tail;
    }
    if blocks.is_empty() {
        return Err(invalid().into());
    }
    Ok(blocks)
}
fn pool_server_allow(
    material: &Value,
    tenant: &str,
    audience: &str,
    grant: Vec<u8>,
) -> Result<TunnelServerAllowConfiguration> {
    let installed_path = std::env::var("FLOWERSEC_PARITY_POOL_DEPLOYMENT")?;
    if installed_path.is_empty()
        || installed_path.len() > 4096
        || !Path::new(&installed_path).is_absolute()
    {
        return Err(invalid().into());
    }
    let installed: Value =
        serde_json::from_slice(&read_bounded(Path::new(&installed_path), 4 << 20)?)?;
    if installed["wire_revision"] != 4
        || text(&installed, "tenant")? != tenant
        || text(&installed, "audience")? != audience
    {
        return Err(invalid().into());
    }
    let ready;
    let binding = if !material["server_allow"].is_null() {
        &material["server_allow"]
    } else {
        let encoded = std::env::var("FLOWERSEC_PARITY_READY_BASE64")?;
        if encoded.len() > 3 << 20 {
            return Err(invalid().into());
        }
        let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)?;
        if decoded.len() > 2 << 20 {
            return Err(invalid().into());
        }
        ready = serde_json::from_slice::<Value>(&decoded)?;
        &ready["server_allow"]
    };
    let control = &installed["server_allow"];
    let address = text(control, "endpoint")?;
    if address.len() > 2048
        || address != text(binding, "endpoint")?
        || !control["clientCertificateDER"].is_null()
    {
        return Err(invalid().into());
    }
    let endpoint = url::Url::parse(address)?;
    let host = endpoint.host_str().ok_or_else(invalid)?;
    let remote_address: std::net::IpAddr = host.parse()?;
    let port = endpoint.port().ok_or_else(invalid)?;
    if endpoint.scheme() != "https"
        || !remote_address.is_loopback()
        || endpoint.path() != "/tunnel/server-allow"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(invalid().into());
    }
    let work_text = text(control, "workMS")?;
    let work: u64 = work_text.parse()?;
    if work == 0 || work > 2000 || work.to_string() != work_text {
        return Err(invalid().into());
    }
    let recipient = fixed(binding, "recipient")?;
    let incarnation = fixed(binding, "incarnation")?;
    if recipient == [0; 16] || incarnation == [0; 16] {
        return Err(invalid().into());
    }
    let tls = &control["tls"];
    let roots_der = pem_blocks(text(tls, "trustPEM")?, "CERTIFICATE", 262144, 16)?;
    let client_chain_der = pem_blocks(text(tls, "certificatePEM")?, "CERTIFICATE", 65536, 8)?;
    let mut keys = pem_blocks(text(tls, "privateKeyPEM")?, "PRIVATE KEY", 16384, 1)?;
    let key = keys.pop().ok_or_else(invalid)?;
    Ok(TunnelServerAllowConfiguration {
        control: ControlHTTPSConfiguration {
            host: host.to_owned(),
            port,
            remote_address,
            base_path: String::new(),
            roots_der,
            client_chain_der,
            client_key_pkcs8: key.into(),
            timeout: Duration::from_millis(work),
            provider_runtime_bytes: 1 << 20,
        },
        recipient,
        incarnation,
        grant,
    })
}

#[cfg(test)]
mod bootstrap_cleanup_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    type Fetch =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<(Vec<u8>, Vec<u8>)>> + Send>>;
    type Attempt = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

    fn original_root_files() -> std::collections::BTreeSet<PathBuf> {
        let prefix = format!("flowersec-rust-root-{}-", std::process::id());
        std::fs::read_dir(std::env::temp_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&prefix)
            })
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_curl_observer_keeps_custody_until_process_and_root_file_cleanup() {
        let environment = TransportEnvironment::with_options(TransportEnvironmentOptions {
            clock: Some(Arc::new(EngineeringClock {
                anchor: Instant::now(),
                epoch_ms: 1000,
            })),
            ..Default::default()
        })
        .unwrap();
        let namespace = environment
            .namespace(
                NamespaceTrustRoot {
                    tenant: "tenant".into(),
                    authority: "authority".into(),
                    key_id: [1; 16],
                    public_key: [2; 32],
                    max_lifetime_ms: 30_000,
                },
                4096,
                16384,
            )
            .unwrap();
        let baseline = environment.resource_usage();
        let roots_before = original_root_files();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/bootstrap", listener.local_addr().unwrap());
        let original_namespace = namespace.clone();
        let attempt: Attempt = Box::pin(async move {
            original_namespace.bootstrap_from(|original| -> Fetch { Box::pin(async move {
                let body = serde_json::to_vec(&json!({
                    "nonce": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, original.nonce())
                }))?;
                let (snapshot, _physical_tail) = spawn_bootstrap_worker(original, url, vec![1], body).await?;
                let _ = snapshot?;
                Err::<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>>(invalid().into())
            }) }).await
        });
        let observer = tokio::spawn(attempt);
        let (mut peer, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut buffer = [0; 4096];
        assert!(
            tokio::time::timeout(Duration::from_secs(2), peer.read(&mut buffer))
                .await
                .unwrap()
                .unwrap()
                > 0
        );
        let roots_during = original_root_files();
        let owned_roots: Vec<_> = roots_during.difference(&roots_before).cloned().collect();
        assert_eq!(owned_roots.len(), 1);
        observer.abort();
        assert!(observer.await.unwrap_err().is_cancelled());
        assert_eq!(environment.resource_usage().tasks, baseline.tasks + 1);
        assert_eq!(environment.resource_usage().timers, baseline.timers + 1);
        drop(namespace);
        let mut close = Box::pin(environment.close());
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(close.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(close);
        assert!(!environment.cleanup_status().complete);
        assert!(owned_roots[0].exists());
        // Leave the real server unanswered: the existing curl --max-time 10
        // must finish its actual child, with no observer left to reap it.
        tokio::time::timeout(Duration::from_secs(12), async {
            while peer.read(&mut buffer).await.unwrap() != 0 {}
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while environment.resource_usage().tasks != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(owned_roots.iter().all(|path| !path.exists()));
        assert_eq!(original_root_files(), roots_before);
        let cleanup = environment.cleanup_status();
        assert!(cleanup.complete);
        assert!(!cleanup.cleanup_incomplete);
        assert_eq!(environment.resource_usage().timers, 0);
    }
}
