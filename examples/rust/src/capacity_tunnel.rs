use super::{End, Installation, Result, err, path};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use flowersec::{Artifact, ArtifactLease, ConnectorOptions, connect_with_cancellation};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

pub(super) struct Legs {
    ingress: [String; 2],
}

#[cfg(not(unix))]
fn read_private(_: &Path) -> Result<Vec<u8>> {
    Err("the frozen Rust Tunnel capacity case requires Unix private files".into())
}

#[cfg(unix)]
fn read_private(file: &Path) -> Result<Vec<u8>> {
    use std::{fs, io::Read, os::unix::fs::MetadataExt};
    let metadata = fs::symlink_metadata(file).map_err(err)?;
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || !(1..=65_536).contains(&metadata.len())
    {
        return Err("invalid private Tunnel input".into());
    }
    let input = fs::File::open(file).map_err(err)?;
    let opened = input.metadata().map_err(err)?;
    if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino()) {
        return Err("Tunnel input changed before opening".into());
    }
    let mut bytes = Vec::new();
    input.take(65_537).read_to_end(&mut bytes).map_err(err)?;
    if bytes.len() as u64 != metadata.len() {
        return Err("incomplete Tunnel input".into());
    }
    Ok(bytes)
}

pub(super) fn initialize(
    options: ConnectorOptions,
) -> Result<(Legs, ConnectorOptions, PathBuf, Value)> {
    let ingress = [
        std::env::var("FSEC_CAPACITY_INGRESS_A").map_err(err)?,
        std::env::var("FSEC_CAPACITY_INGRESS_B").map_err(err)?,
    ];
    for url in &ingress {
        if !url.starts_with("quic://") {
            return Err("native QUIC Tunnel ingress required".into());
        }
        options.clone().with_tunnel_ingress(url).map_err(err)?;
    }
    let roots = read_private(&path("FSEC_CAPACITY_ROOTS")?)?;
    let pem = std::str::from_utf8(&roots).map_err(err)?.trim();
    let body = pem
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|s| s.strip_suffix("-----END CERTIFICATE-----"))
        .ok_or("one deployment CA required")?;
    let der = STANDARD
        .decode(body.split_ascii_whitespace().collect::<String>())
        .map_err(err)?;
    let options = options.with_trust_roots_der(vec![der]).map_err(err)?;
    let invitations = path("FSEC_CAPACITY_INVITATION_DIR")?;
    if !invitations.is_dir() {
        return Err("missing Tunnel invitations directory".into());
    }
    let reply = json!({"ingressURLs": ingress});
    Ok((Legs { ingress }, options, invitations, reply))
}

impl Legs {
    async fn offer(
        &self,
        state: &Installation,
        id: &str,
        side: usize,
    ) -> Result<(ArtifactLease, ConnectorOptions, String)> {
        let input = state
            .invitations
            .join(id)
            .join(["first.json", "second.json"][side]);
        let bytes = tokio::task::spawn_blocking(move || read_private(&input))
            .await
            .map_err(err)??;
        let artifact = Artifact::parse(&bytes).map_err(err)?;
        let envelope: Value = serde_json::from_slice(&bytes).map_err(err)?;
        if envelope["session"]["channel_id"] != id
            || envelope["path"]["kind"] != "tunnel"
            || envelope["path"]["role"].as_u64() != Some(side as u64 + 1)
        {
            return Err("published Tunnel invitation channel or role mismatch".into());
        }
        let key = artifact.credential_lookup_key();
        let receipt = state.spent.join(format!("spent-{key}"));
        let lease = ArtifactLease::new(artifact, move || crate::write_spend_receipt(receipt));
        let options = state
            .options
            .clone()
            .with_tunnel_ingress(&self.ingress[side])
            .map_err(err)?;
        Ok((lease, options, key))
    }

    pub(super) async fn connect(
        &self,
        state: &Installation,
        id: &str,
        token: &CancellationToken,
    ) -> Result<(End, End, String)> {
        let ((first, a_opts, key), (second, b_opts, other)) =
            tokio::try_join!(self.offer(state, id, 0), self.offer(state, id, 1))?;
        if key == other {
            return Err("Tunnel legs share a credential".into());
        }
        let pair = token.child_token();
        let dial = |lease, opts| {
            let child = pair.clone();
            async move {
                let result = connect_with_cancellation(lease, opts, child.clone()).await;
                if result.is_err() {
                    child.cancel();
                }
                result
            }
        };
        match tokio::join!(dial(first, a_opts), dial(second, b_opts)) {
            (Ok(a), Ok(b)) => Ok((a, b, key)),
            (Ok(end), Err(cause)) | (Err(cause), Ok(end)) => {
                end.close().await.map_err(err)?;
                Err(err(cause))
            }
            (Err(first), Err(second)) => Err(format!("Tunnel connect A: {first}; B: {second}")),
        }
    }
}
