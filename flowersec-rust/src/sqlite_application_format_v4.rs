//! Read-only format admission for application SQLite transaction groups.
use crate::{
    ServiceError, ServiceFailure, StorageFormatIncompatibility,
    StorageFormatMismatchReason as Reason, StorageFormatTransactionGroup as Group,
    StorageWireFormat as Wire,
};
use rusqlite::{Connection, OptionalExtension, params};

type Result<T> = std::result::Result<T, ServiceError>;
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Execution,
    Reference,
}
impl Kind {
    pub(crate) fn required(self) -> u32 {
        match self {
            Self::Execution => 2,
            Self::Reference => 1,
        }
    }
    fn group(self) -> Group {
        match self {
            Self::Execution => Group::ExecutionHistory,
            Self::Reference => Group::OperationReference,
        }
    }
    fn wire(self) -> Wire {
        match self {
            Self::Execution => Wire::FlowersecExecution2,
            Self::Reference => Wire::FlowersecOperationReference1,
        }
    }
    fn table(self) -> &'static str {
        match self {
            Self::Execution => "execution_manifest",
            Self::Reference => "reference_manifest",
        }
    }
    fn prefix(self) -> &'static str {
        match self {
            Self::Execution => "flowersec-execution-",
            Self::Reference => "flowersec-operation-reference-",
        }
    }
    pub(crate) fn error(self, observed: Option<u32>, reason: Reason) -> ServiceError {
        ServiceError(ServiceFailure::StorageFormatIncompatible(
            StorageFormatIncompatibility::new(
                self.group(),
                self.wire(),
                self.required(),
                observed,
                reason,
            ),
        ))
    }
    pub(crate) fn database<T>(
        self,
        value: rusqlite::Result<T>,
        observed: Option<u32>,
    ) -> Result<T> {
        value.map_err(|error| {
            if matches!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)) {
                return ServiceError(ServiceFailure::ServiceUnavailable);
            }
            let damaged = matches!(&error, rusqlite::Error::SqliteFailure(code, _) if matches!(code.code,
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase));
            self.error(if damaged { None } else { observed }, Reason::Schema)
        })
    }
    fn manifest_schema(self, revision: u32) -> String {
        match self {
            Self::Execution => format!(
                "CREATE TABLE execution_manifest(id INTEGER PRIMARY KEY CHECK(id=1),format TEXT NOT NULL CHECK(format='flowersec-execution-{revision}'),domain TEXT NOT NULL,max_pages INTEGER NOT NULL) STRICT, WITHOUT ROWID"
            ),
            Self::Reference => format!(
                "CREATE TABLE reference_manifest (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL CHECK(format='flowersec-operation-reference-{revision}'), domain TEXT NOT NULL, max_records INTEGER NOT NULL, max_pages INTEGER NOT NULL) STRICT, WITHOUT ROWID"
            ),
        }
    }
}
/// No current record/schema reader is reached until a bounded format header,
/// its physical declaration, configured identity and SQLite revision agree.
pub(crate) fn inspect(
    connection: &Connection,
    kind: Kind,
    domain: &str,
    max_records: Option<u32>,
    max_pages: u32,
) -> Result<()> {
    let manifest: Option<(String, String, i64)> = kind.database(connection.query_row(
        "SELECT type,substr(sql,1,512),length(sql) FROM sqlite_schema WHERE name=?1 LIMIT 1", [kind.table()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional(), None)?;
    let Some((table_type, schema, schema_bytes)) = manifest else {
        return Err(kind.error(None, Reason::MissingManifest));
    };
    if table_type != "table" || !(1..=512).contains(&schema_bytes) {
        return Err(kind.error(None, Reason::Schema));
    }
    let declared_prefix = format!("CHECK(format='{}", kind.prefix());
    let declared = schema
        .split_once(&declared_prefix)
        .and_then(|(_, suffix)| suffix.split_once("')"))
        .map(|(revision, _)| revision)
        .and_then(|revision| {
            (!revision.is_empty()
                && revision.len() <= 10
                && revision.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| revision.parse::<u32>().ok())
            .flatten()
        })
        .filter(|revision| *revision > 0);
    let Some(revision) = declared else {
        return Err(kind.error(None, Reason::WireFormat));
    };
    if schema != kind.manifest_schema(revision) {
        return Err(kind.error(None, Reason::Schema));
    }
    let query = match kind {
        Kind::Execution => {
            "SELECT id,substr(format,1,64),length(format),substr(domain,1,8192),length(domain),max_pages,0 FROM execution_manifest LIMIT 2"
        }
        Kind::Reference => {
            "SELECT id,substr(format,1,64),length(format),substr(domain,1,8192),length(domain),max_pages,max_records FROM reference_manifest LIMIT 2"
        }
    };
    let mut statement = kind.database(connection.prepare(query), None)?;
    let mut rows = kind.database(statement.query([]), None)?;
    let row = kind
        .database(rows.next(), None)?
        .ok_or_else(|| kind.error(None, Reason::MissingManifest))?;
    let id: i64 = kind.database(row.get(0), None)?;
    let format: String = kind.database(row.get(1), None)?;
    let format_length: i64 = kind.database(row.get(2), None)?;
    let identity: String = kind.database(row.get(3), None)?;
    let identity_length: i64 = kind.database(row.get(4), None)?;
    let pages: u32 = kind.database(row.get(5), None)?;
    let records: u32 = kind.database(row.get(6), None)?;
    let expected = format!("{}{revision}", kind.prefix());
    if id != 1 || kind.database(rows.next(), None)?.is_some() {
        return Err(kind.error(None, Reason::Schema));
    }
    if format != expected || format_length != expected.len() as i64 {
        return Err(kind.error(None, Reason::RevisionConflict));
    }
    if !(1..=8192).contains(&identity_length) || identity != domain {
        return Err(kind.error(None, Reason::IdentityMismatch));
    }
    let pragma: u32 = kind.database(
        connection.query_row("PRAGMA user_version", [], |row| row.get(0)),
        None,
    )?;
    if pragma != revision {
        return Err(kind.error(None, Reason::RevisionConflict));
    }
    if pages != max_pages || max_records.is_some_and(|maximum| maximum != records) {
        return Err(kind.error(Some(revision), Reason::Configuration));
    }
    if revision < kind.required() {
        return Err(kind.error(Some(revision), Reason::OlderRevision));
    }
    if revision > kind.required() {
        return Err(kind.error(Some(revision), Reason::NewerRevision));
    }
    Ok(())
}

pub(crate) fn validate_schema(connection: &Connection, kind: Kind) -> Result<()> {
    let revision = Some(kind.required());
    let mut expected = match kind {
        Kind::Execution => vec![
            ("execution_floor", "CREATE TABLE execution_floor(authority BLOB PRIMARY KEY CHECK(length(authority)=32),cutoff BLOB NOT NULL CHECK(length(cutoff)=8)) STRICT, WITHOUT ROWID".to_owned()),
            ("execution_manifest", kind.manifest_schema(kind.required())),
            ("execution_record", "CREATE TABLE execution_record(authority BLOB NOT NULL CHECK(length(authority)=32),subject TEXT NOT NULL CHECK(length(subject) BETWEEN 1 AND 128),operation BLOB NOT NULL CHECK(length(operation)=32),metadata BLOB NOT NULL CHECK(length(metadata) BETWEEN 1 AND 65536),result BLOB CHECK(result IS NULL OR length(result)<=1048576),PRIMARY KEY(authority,subject,operation)) STRICT, WITHOUT ROWID".to_owned()),
            ("execution_recovery", "CREATE TABLE execution_recovery(id INTEGER PRIMARY KEY CHECK(id=1),configuration BLOB NOT NULL CHECK(length(configuration) BETWEEN 1 AND 4096)) STRICT, WITHOUT ROWID".to_owned()),
        ],
        Kind::Reference => vec![
            ("operation_reference", "CREATE TABLE operation_reference (identity BLOB PRIMARY KEY CHECK(length(identity)=32), canonical BLOB NOT NULL CHECK(length(canonical) BETWEEN 1 AND 4096)) STRICT, WITHOUT ROWID".to_owned()),
            ("reference_manifest", kind.manifest_schema(kind.required())),
        ],
    };
    expected.sort_by_key(|(name, _)| *name);
    let mut statement = kind.database(connection.prepare("SELECT type,substr(name,1,64),substr(sql,1,2048),length(sql) FROM sqlite_schema ORDER BY name LIMIT ?1"), revision)?;
    let mut rows = kind.database(statement.query(params![expected.len() + 1]), revision)?;
    for (name, schema) in expected {
        let row = kind
            .database(rows.next(), revision)?
            .ok_or_else(|| kind.error(revision, Reason::Schema))?;
        let table_type: String = kind.database(row.get(0), revision)?;
        let actual_name: String = kind.database(row.get(1), revision)?;
        let actual_schema: String = kind.database(row.get(2), revision)?;
        let schema_length: usize = kind.database(row.get(3), revision)?;
        if table_type != "table"
            || actual_name != name
            || actual_schema != schema
            || schema_length != schema.len()
        {
            return Err(kind.error(revision, Reason::Schema));
        }
    }
    if kind.database(rows.next(), revision)?.is_some() {
        return Err(kind.error(revision, Reason::Schema));
    }
    let page_size: u64 = kind.database(
        connection.query_row("PRAGMA page_size", [], |row| row.get(0)),
        revision,
    )?;
    if page_size != 4096 {
        return Err(kind.error(revision, Reason::Configuration));
    }
    let journal: String = kind.database(
        connection.query_row("PRAGMA journal_mode", [], |row| row.get(0)),
        revision,
    )?;
    if journal != "wal" {
        return Err(kind.error(revision, Reason::Configuration));
    }
    let integrity: String = kind.database(
        connection.query_row("PRAGMA quick_check", [], |row| row.get(0)),
        revision,
    )?;
    if integrity != "ok" {
        return Err(kind.error(revision, Reason::Value));
    }
    Ok(())
}

/// Keep header, schema and all current rows in one SQLite read snapshot. The
/// same admission runs again after replacing the read-only connection, before
/// writable configuration or restart recovery can alter durable state.
pub(crate) fn read_snapshot<T>(
    connection: &Connection,
    kind: Kind,
    inspect: impl FnOnce() -> Result<T>,
) -> Result<T> {
    kind.database(connection.execute_batch("BEGIN"), None)?;
    let result = inspect();
    let rollback = kind.database(connection.execute_batch("ROLLBACK"), None);
    match result {
        Err(error) => Err(error),
        Ok(value) => {
            rollback?;
            Ok(value)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        ExecutionService, ExecutionServiceOptions, SQLiteExecutionStoreOptions,
        SQLiteReferenceStoreOptions, TransportEnvironment, TransportEnvironmentOptions,
    };
    use std::{collections::BTreeMap, fs, path::Path};

    fn environment() -> TransportEnvironment {
        TransportEnvironment::with_options(TransportEnvironmentOptions {
            clock: Some(crate::environment_v4::tests::TestClock::new(1000, 1010)),
            ..TransportEnvironmentOptions::default()
        })
        .unwrap()
    }
    fn domain() -> ExecutionServiceOptions {
        ExecutionServiceOptions {
            tenant: "format-test".into(),
            audience: "service".into(),
            namespace: "format/storage".into(),
            caller_authorities: vec![[1; 32]],
            max_records: 2,
            max_active: 1,
            result_bytes: 32,
        }
    }
    async fn open(path: &Path, kind: Kind) -> Result<()> {
        let environment = environment();
        let result = match kind {
            Kind::Reference => {
                match environment.sqlite_operation_reference_store(SQLiteReferenceStoreOptions {
                    path: path.to_owned(),
                    target_domain: "format-test".into(),
                    max_records: 2,
                    max_pages: 32,
                    provider_runtime_bytes: 262144,
                    disk_overhead_bytes: 65536,
                }) {
                    Ok(store) => {
                        store.close();
                        store
                            .wait_cleanup(tokio_util::sync::CancellationToken::new())
                            .await?;
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            Kind::Execution => match ExecutionService::new_durable(
                &environment,
                domain(),
                SQLiteExecutionStoreOptions {
                    path: path.to_owned(),
                    max_pages: 32,
                    provider_runtime_bytes: 262144,
                    disk_overhead_bytes: 65536,
                },
            ) {
                Ok(service) => {
                    drop(service);
                    Ok(())
                }
                Err(error) => Err(error),
            },
        };
        // These format fixtures retain the database for the next public open.
        // Begin Close, but do not spend its five-second observation window on
        // disk ownership that cannot retire until the fixture files are removed.
        let closing = environment.close();
        tokio::pin!(closing);
        match futures_util::poll!(closing.as_mut()) {
            std::task::Poll::Ready(status) => assert!(status.unwrap().complete),
            std::task::Poll::Pending => {
                assert!(environment.is_closed());
                assert!(environment.resource_usage().disk_bytes > 0);
                assert!(!environment.cleanup_status().complete);
            }
        }
        result
    }
    pub(crate) fn snapshot(directory: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).unwrap(),
                )
            })
            .collect()
    }
    #[tokio::test]
    async fn current_store_recovers_committed_wal_before_format_admission() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".flowersec");
        fs::create_dir_all(&fixture_root).unwrap();
        let fixture_root = fs::canonicalize(fixture_root).unwrap();
        for kind in [Kind::Execution, Kind::Reference] {
            let source = tempfile::Builder::new()
                .prefix("rust-valid-wal-source-")
                .tempdir_in(&fixture_root)
                .unwrap();
            let recovered = tempfile::Builder::new()
                .prefix("rust-valid-wal-recovery-")
                .tempdir_in(&fixture_root)
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for directory in [source.path(), recovered.path()] {
                    fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
                }
            }
            let path = source.path().join("store.sqlite3");
            open(&path, kind).await.unwrap();
            let writer = Connection::open(&path).unwrap();
            writer.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
            writer
                .pragma_update(None, "user_version", kind.required() + 7)
                .unwrap();
            writer
                .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
                .unwrap();
            let main_before = fs::read(&path).unwrap();
            assert_eq!(
                u32::from_be_bytes(main_before[60..64].try_into().unwrap()),
                kind.required() + 7
            );
            // The current revision exists only in a committed WAL frame. A
            // reader that ignores WAL would reject this valid current store.
            writer
                .pragma_update(None, "user_version", kind.required())
                .unwrap();
            writer
                .execute_batch("BEGIN; SELECT name FROM sqlite_schema")
                .unwrap();
            let files = snapshot(source.path());
            assert!(files["store.sqlite3-wal"].len() > 32);
            assert_eq!(files["store.sqlite3"], main_before);
            // Copy the crash image while the original reader keeps every WAL
            // frame alive; the recovery directory has no live SQLite owner.
            for (name, bytes) in files {
                let target = recovered.path().join(name);
                fs::write(&target, bytes).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            let target = recovered.path().join("store.sqlite3");
            open(&target, kind).await.unwrap();
            let connection = Connection::open(&target).unwrap();
            let revision: u32 = connection
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(revision, kind.required());
            validate_schema(&connection, kind).unwrap();
            connection.close().unwrap();
            open(&target, kind).await.unwrap();
        }
    }

    #[tokio::test]
    async fn recovery_policy_is_admitted_before_restart_writes() {
        use crate::checkpoint_v4::{
            CheckpointTokenProtection, ExecutionRecoveryPolicy, RecoveryConfiguration,
        };
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".flowersec");
        fs::create_dir_all(&fixture_root).unwrap();
        let fixture_root = fs::canonicalize(fixture_root).unwrap();
        for mutation in [
            "token_zero",
            "token_large",
            "duration_zero",
            "issues_zero",
            "issues_large",
        ] {
            let directory = tempfile::Builder::new()
                .prefix("rust-recovery-format-")
                .tempdir_in(&fixture_root)
                .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            }
            let path = directory.path().join("store.sqlite3");
            open(&path, Kind::Execution).await.unwrap();
            let mut configuration = RecoveryConfiguration {
                policy: ExecutionRecoveryPolicy {
                    max_issued_duration_ms: 1000,
                    max_token_bytes: 8192,
                    max_checkpoint_issues_per_operation: 1024,
                    minimum_checkpoint_interval_ms: 0,
                },
                protection: CheckpointTokenProtection::HmacSha256,
                key_id: [1; 16],
                key_fingerprint: [2; 32],
            };
            let connection = Connection::open(&path).unwrap();
            connection
                .execute(
                    "INSERT INTO execution_recovery VALUES(1,?1)",
                    [serde_json::to_vec(&configuration).unwrap()],
                )
                .unwrap();
            connection.close().unwrap();
            open(&path, Kind::Execution).await.unwrap();
            match mutation {
                "token_zero" => configuration.policy.max_token_bytes = 0,
                "token_large" => configuration.policy.max_token_bytes = 8193,
                "duration_zero" => configuration.policy.max_issued_duration_ms = 0,
                "issues_zero" => configuration.policy.max_checkpoint_issues_per_operation = 0,
                "issues_large" => configuration.policy.max_checkpoint_issues_per_operation = 1025,
                _ => unreachable!(),
            }
            let connection = Connection::open(&path).unwrap();
            connection
                .pragma_update(None, "wal_autocheckpoint", 0)
                .unwrap();
            connection
                .execute(
                    "UPDATE execution_recovery SET configuration=?1",
                    [serde_json::to_vec(&configuration).unwrap()],
                )
                .unwrap();
            // Initialize the reader index, then retain committed WAL frames
            // through the close without checkpointing the original files.
            connection
                .execute_batch("BEGIN; SELECT name FROM sqlite_schema")
                .unwrap();
            assert!(
                fs::metadata(path.with_file_name("store.sqlite3-wal"))
                    .unwrap()
                    .len()
                    > 32
            );
            connection
                .set_db_config(
                    rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                    true,
                )
                .unwrap();
            connection.execute_batch("ROLLBACK").unwrap();
            connection.close().unwrap();
            let before = snapshot(directory.path());
            let error = open(&path, Kind::Execution).await.unwrap_err();
            let projection = error.storage_format().unwrap();
            assert_eq!(projection.observed_revision, Some(2));
            assert_eq!(projection.required_revision, 2);
            assert!(
                before == snapshot(directory.path()),
                "{mutation}: durable files changed"
            );
        }
    }

    #[tokio::test]
    async fn public_open_refuses_untrusted_or_unsupported_headers_before_writes() {
        let fixture_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".flowersec");
        fs::create_dir_all(&fixture_root).unwrap();
        let fixture_root = fs::canonicalize(fixture_root).unwrap();
        for kind in [Kind::Execution, Kind::Reference] {
            for mutation in [
                "pragma",
                "row",
                "identity",
                "missing",
                "future",
                "future_layout",
                "older",
                "schema",
                "records",
                "journal",
            ] {
                let directory = tempfile::Builder::new()
                    .prefix("rust-application-format-")
                    .tempdir_in(&fixture_root)
                    .unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                let path = directory.path().join("store.sqlite3");
                open(&path, kind).await.unwrap();
                open(&path, kind).await.unwrap();
                open(&path, kind).await.unwrap();
                let connection = Connection::open(&path).unwrap();
                connection
                    .pragma_update(None, "wal_autocheckpoint", 0)
                    .unwrap();
                let required = kind.required();
                let expected = match mutation {
                    "pragma" => {
                        connection
                            .pragma_update(None, "user_version", required + 7)
                            .unwrap();
                        None
                    }
                    "row" => {
                        connection
                            .execute_batch("PRAGMA ignore_check_constraints=ON")
                            .unwrap();
                        connection
                            .execute(
                                &format!(
                                    "UPDATE {} SET format='untrusted-private-format'",
                                    kind.table()
                                ),
                                [],
                            )
                            .unwrap();
                        None
                    }
                    "identity" => {
                        connection
                            .execute(
                                &format!("UPDATE {} SET domain='private-identity'", kind.table()),
                                [],
                            )
                            .unwrap();
                        None
                    }
                    "missing" => {
                        connection
                            .execute(&format!("DROP TABLE {}", kind.table()), [])
                            .unwrap();
                        None
                    }
                    "future" | "future_layout" | "older" => {
                        let revision = if mutation == "older" {
                            required - 1
                        } else {
                            required + 1
                        };
                        connection
                            .execute(&format!("DROP TABLE {}", kind.table()), [])
                            .unwrap();
                        connection
                            .execute_batch(&kind.manifest_schema(revision))
                            .unwrap();
                        let format = format!("{}{revision}", kind.prefix());
                        match kind {
                            Kind::Execution => {
                                connection
                                    .execute(
                                        "INSERT INTO execution_manifest VALUES(1,?1,?2,32)",
                                        params![format, serde_json::to_string(&domain()).unwrap()],
                                    )
                                    .unwrap();
                            }
                            Kind::Reference => {
                                connection.execute("INSERT INTO reference_manifest VALUES(1,?1,'format-test',2,32)", [format]).unwrap();
                            }
                        }
                        connection
                            .pragma_update(None, "user_version", revision)
                            .unwrap();
                        if mutation == "future_layout" {
                            connection.execute_batch(match kind {
                                Kind::Execution => "DROP TABLE execution_record; CREATE TABLE future_records(private_value TEXT)",
                                Kind::Reference => "DROP TABLE operation_reference; CREATE TABLE future_references(private_value TEXT)",
                            }).unwrap();
                            connection
                                .pragma_update(None, "journal_mode", "DELETE")
                                .unwrap();
                        }
                        (revision > 0).then_some(revision)
                    }
                    "journal" => {
                        connection
                            .pragma_update(None, "journal_mode", "DELETE")
                            .unwrap();
                        Some(required)
                    }
                    "schema" => {
                        connection
                            .execute_batch("CREATE TABLE unexpected(value TEXT)")
                            .unwrap();
                        Some(required)
                    }
                    "records" => {
                        match kind {
                            Kind::Reference => {
                                connection
                                    .execute(
                                        "INSERT INTO operation_reference VALUES(?1,?2)",
                                        params![[0u8; 32].as_slice(), [0u8].as_slice()],
                                    )
                                    .unwrap();
                            }
                            Kind::Execution => {
                                connection.execute("INSERT INTO execution_record VALUES(?1,'client',?2,?3,NULL)", params![[1u8;32].as_slice(), [2u8;32].as_slice(), b"{".as_slice()]).unwrap();
                            }
                        }
                        Some(required)
                    }
                    _ => unreachable!(),
                };
                // Preserve committed WAL frames, and initialize the provider's
                // reader index before comparing every file byte for byte.
                connection
                    .execute_batch("BEGIN; SELECT name FROM sqlite_schema")
                    .unwrap();
                if !matches!(mutation, "journal" | "future_layout") {
                    assert!(
                        fs::metadata(path.with_file_name("store.sqlite3-wal"))
                            .unwrap()
                            .len()
                            > 32
                    );
                }
                if mutation == "older" {
                    let occupied = snapshot(directory.path());
                    let error = open(&path, kind).await.unwrap_err();
                    assert!(matches!(error.0, ServiceFailure::ServiceUnavailable));
                    assert_eq!(snapshot(directory.path()), occupied);
                }
                connection
                    .set_db_config(
                        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
                        true,
                    )
                    .unwrap();
                connection.execute_batch("ROLLBACK").unwrap();
                connection.close().unwrap();
                let before = snapshot(directory.path());
                let error = open(&path, kind).await.unwrap_err();
                let projection = error
                    .storage_format()
                    .expect("public open preserves the fixed projection");
                assert_eq!(projection.observed_revision, expected, "{mutation}");
                assert_eq!(projection.required_revision, required);
                assert_eq!(projection.transaction_group, kind.group());
                assert_eq!(projection.code(), "storage_format_incompatible");
                assert!(!projection.exact_conversion_available());
                let encoded = serde_json::to_string(projection).unwrap();
                assert!(!encoded.contains("private-identity"));
                assert!(!encoded.contains("untrusted-private-format"));
                assert!(
                    before == snapshot(directory.path()),
                    "refusal must not configure or rewrite {mutation}"
                );
            }
        }
    }
}
