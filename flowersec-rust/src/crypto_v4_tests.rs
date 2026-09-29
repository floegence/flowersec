use super::*;
use crate::{
    codec_v4::{
        ActivationSource,
        tests::{b, encode_map, t, u},
    },
    namespace_v4::verifier::credential::tests::Fixture,
};

struct Exchange {
    fixture: Fixture,
    keys: [Arc<LocalKeys>; 2],
    client_hello: Vec<u8>,
    server_hello: Vec<u8>,
    context: Vec<u8>,
    fsb: Vec<u8>,
    fsa: Vec<u8>,
    pool: Option<crate::pool_v4::tests::StoreFixture>,
}
fn signed(fields: &[(u64, Vec<u8>)], signature_id: u64, label: &[u8], key: &LocalKeys) -> Vec<u8> {
    let unsigned = encode_map(fields);
    let signature = key.sign(&domain(label, &[&unsigned]).unwrap()).unwrap();
    let mut fields = fields.to_vec();
    fields.push((signature_id, b(&signature)));
    encode_map(&fields)
}
impl Exchange {
    fn new(profile: Profile, source: ActivationSource) -> Self {
        let keys = [
            LocalKeys::generate(profile).unwrap(),
            LocalKeys::generate(profile).unwrap(),
        ];
        let ed = [keys[0].ed_public(), keys[1].ed_public()];
        let fixture = Fixture::with_identity(
            source,
            profile.name(),
            Some([(keys[0].dh_public(), &ed[0]), (keys[1].dh_public(), &ed[1])]),
        );
        let admission = fixture.reserve().unwrap();
        let client_hello = encode_map(&[
            (0, t("flowersec/4")),
            (1, t("4")),
            (2, t(profile.name())),
            (3, b(&admission.artifact_digest)),
            (4, b(&admission.candidate_id)),
            (5, b(&admission.route_digest)),
            (6, b(&admission.attempt_id)),
            (7, b(&[23; 32])),
            (8, u(0)),
            (9, u(2)),
            (10, b(&[])),
        ]);
        let server_hello = encode_map(&[
            (0, t("flowersec/4")),
            (1, t("4")),
            (2, t(profile.name())),
            (3, b(&admission.artifact_digest)),
            (4, b(&admission.candidate_id)),
            (5, b(&admission.route_digest)),
            (6, b(&admission.attempt_id)),
            (7, b(&[23; 32])),
            (8, b(&[31; 32])),
            (9, u(0)),
            (10, u(0)),
            (11, u(1)),
            (12, b(&[])),
        ]);
        let hello: [u8; 32] = Sha256::digest(
            domain(
                b"flowersec/v4/hello-transcript\0",
                &[&client_hello, &server_hello],
            )
            .unwrap(),
        )
        .into();
        let context = encode_map(&[
            (0, t("4")),
            (1, t(profile.name())),
            (2, u(0)),
            (3, u(0)),
            (4, b(&admission.artifact_digest)),
            (5, b(&admission.route_digest)),
            (6, b(&admission.attempt_id)),
            (7, b(&[23; 32])),
            (8, b(&hello)),
            (9, u(0)),
            (10, u(1)),
            (11, u(0)),
            (12, b(&[])),
        ]);
        let context_digest = codec::digest(
            "transport_context_digest",
            decode(&context, "TransportContext", 4096, Context::default()).unwrap(),
        )
        .unwrap();
        let fsb = signed(
            &[
                (0, b(&admission.artifact_digest)),
                (1, t("tenant")),
                (2, b(&[5; 16])),
                (3, b(&[22; 16])),
                (4, b(&[23; 32])),
                (5, b(&admission.candidate_id)),
                (6, b(&admission.route_digest)),
                (7, b(&admission.attempt_id)),
                (8, b(&[32; 32])),
                (9, b(&hello)),
                (10, u(0)),
                (11, u(1)),
                (12, b(&context_digest)),
                (13, b(&fixture.activation)),
                (14, b(&fixture.client)),
            ],
            15,
            b"flowersec/v4/fsb4/signature\0",
            &keys[0],
        );
        let binding = codec::digest(
            "admission_binding",
            decode(
                &fsb,
                "FSB4",
                65_536,
                Context::with_activation_source(source),
            )
            .unwrap(),
        )
        .unwrap();
        let fsa = signed(
            &[
                (0, u(0)),
                (1, u(0)),
                (2, u(1)),
                (3, b(&[33; 32])),
                (4, b(&binding)),
                (5, b(&admission.route_digest)),
                (6, b(&hello)),
                (7, u(0)),
                (8, u(1)),
                (9, b(&context_digest)),
                (10, b(&admission.certificate_digests[0])),
                (11, b(&admission.certificate_digests[1])),
                (12, b(&fixture.server)),
            ],
            13,
            b"flowersec/v4/fsa4/signature\0",
            &keys[1],
        );
        drop(admission);
        let pool = (source == ActivationSource::PreauthorizedPool)
            .then(|| crate::pool_v4::tests::StoreFixture::new(&fixture));
        Self {
            fixture,
            pool,
            keys,
            client_hello,
            server_hello,
            context,
            fsb,
            fsa,
        }
    }
    fn input(&self) -> HandshakeInput<'_> {
        HandshakeInput {
            artifact: &self.fixture.artifact,
            client_hello: &self.client_hello,
            server_hello: &self.server_hello,
            transport_context: &self.context,
            fsb: &self.fsb,
            fsa: &self.fsa,
        }
    }
    fn handshake(&self, role: Role) -> Handshake {
        let admission = self.fixture.reserve().unwrap();
        let admission = if role == Role::Client
            && let Some(pool) = &self.pool
        {
            pool.consume(admission)
        } else {
            admission
        };
        Handshake::new(
            admission,
            role,
            self.keys[role.index()].clone(),
            self.input(),
        )
        .unwrap()
    }
    fn noise_pair(&self) -> (Handshake, Handshake) {
        let mut client = self.handshake(Role::Client);
        let mut server = self.handshake(Role::Server);
        let mut first = [0; 81];
        let n = client.write_noise(&mut first).unwrap();
        assert_eq!(n, client.binding.profile.public_len() + 16);
        server.read_noise(&first[..n]).unwrap();
        let mut second = [0; 81];
        let n = server.write_noise(&mut second).unwrap();
        client.read_noise(&second[..n]).unwrap();
        (client, server)
    }
}
#[derive(Default)]
struct Writer {
    payload: Option<[u8; 103]>,
    revoke: Option<ResourceAccount>,
    reject: bool,
}
impl ReadyWriter for Writer {
    fn submit_ready(&mut self, payload: &[u8; 103]) -> Result<()> {
        if self.reject {
            return Err(CryptoError::State);
        }
        assert!(self.payload.is_none());
        self.payload = Some(*payload);
        if let Some(account) = &self.revoke {
            account.revoke();
        }
        Ok(())
    }
}
fn ready_pair(mut client: Handshake, mut server: Handshake) -> (RecordEngine, RecordEngine) {
    let mut c = Writer::default();
    let mut s = Writer::default();
    server.submit_ready(&mut s).unwrap();
    client.submit_ready(&mut c).unwrap();
    assert_eq!(client.hash, server.hash);
    client.verify_ready(&s.payload.unwrap()).unwrap();
    server.verify_ready(&c.payload.unwrap()).unwrap();
    (
        client.into_records().unwrap(),
        server.into_records().unwrap(),
    )
}
#[test]
fn real_credentials_random_noise_dual_ready_and_bidirectional_records() {
    for profile in [Profile::X25519, Profile::P256] {
        for source in [
            ActivationSource::LiveAuthority,
            ActivationSource::PreauthorizedPool,
        ] {
            let exchange = Exchange::new(profile, source);
            let baseline = exchange.fixture.environment.resource_usage();
            let (client, server) = exchange.noise_pair();
            let (mut client, mut server) = ready_pair(client, server);
            client.install_reliable_scope(1).unwrap();
            server.install_reliable_scope(1).unwrap();
            let mut wire = [0; 256];
            let mut out = [0; 256];
            let mut roundtrip =
                |sender: &mut RecordEngine, receiver: &mut RecordEngine, message: &[u8]| {
                    let n = sender.seal_reliable(1, 8, message, &mut wire).unwrap();
                    let m = receiver
                        .open_reliable(1, &wire[..n], &mut out, |kind, plain| {
                            assert_eq!(kind, 8);
                            assert_eq!(plain, message);
                            Ok(())
                        })
                        .unwrap();
                    assert_eq!(&out[..m], message);
                };
            roundtrip(&mut client, &mut server, b"client payload");
            roundtrip(&mut server, &mut client, b"server payload");
            assert!(client.install_reliable_scope(1).is_err());
            drop(client);
            drop(server);
            assert_eq!(exchange.fixture.environment.resource_usage(), baseline);
        }
    }
}
#[test]
fn production_ephemeral_is_fresh_and_noise_errors_consume_the_attempt() {
    for profile in [Profile::X25519, Profile::P256] {
        let exchange = Exchange::new(profile, ActivationSource::LiveAuthority);
        let mut first = exchange.handshake(Role::Client);
        let mut second = exchange.handshake(Role::Client);
        let mut a = [0; 81];
        let mut b = [0; 81];
        let n = first.write_noise(&mut a).unwrap();
        second.write_noise(&mut b).unwrap();
        assert_ne!(&a[..profile.public_len()], &b[..profile.public_len()]);
        let mut server = exchange.handshake(Role::Server);
        a[n - 1] ^= 1;
        assert!(server.read_noise(&a[..n]).is_err());
        assert!(server.read_noise(&b[..n]).is_err());
        assert!(first.write_noise(&mut a).is_err());
        assert!(first.into_records().is_err());
    }
}
#[test]
fn ready_requires_both_independent_proof_and_actual_local_submission() {
    let exchange = Exchange::new(Profile::X25519, ActivationSource::LiveAuthority);
    let (mut client, mut server) = exchange.noise_pair();
    let mut s = Writer::default();
    server.submit_ready(&mut s).unwrap();
    client.verify_ready(&s.payload.unwrap()).unwrap();
    assert!(client.into_records().is_err());
    let (mut client, mut server) = exchange.noise_pair();
    let mut s = Writer::default();
    server.submit_ready(&mut s).unwrap();
    let mut wire = s.payload.unwrap();
    wire[4..68].fill(0);
    let proof = [0; 64];
    let tag = mac(
        &server.ready_key(1).unwrap(),
        &server.ready_inputs(1, Some(&proof)).unwrap(),
    );
    wire[71..].copy_from_slice(&tag);
    assert!(client.verify_ready(&wire).is_err());
    assert!(client.into_records().is_err());
    let (mut client, _) = exchange.noise_pair();
    let mut reject = Writer {
        reject: true,
        ..Writer::default()
    };
    assert!(client.submit_ready(&mut reject).is_err());
    assert!(client.into_records().is_err());
}
#[test]
fn pool_handshake_requires_original_commit_and_rechecks_it_at_ready() {
    let exchange = Exchange::new(Profile::X25519, ActivationSource::PreauthorizedPool);
    assert!(
        Handshake::new(
            exchange.fixture.reserve().unwrap(),
            Role::Client,
            exchange.keys[0].clone(),
            exchange.input()
        )
        .is_err()
    );
    let (mut client, mut server) = exchange.noise_pair();
    let mut c = Writer::default();
    let mut s = Writer::default();
    client.submit_ready(&mut c).unwrap();
    server.submit_ready(&mut s).unwrap();
    client.verify_ready(&s.payload.unwrap()).unwrap();
    server.verify_ready(&c.payload.unwrap()).unwrap();
    exchange.pool.as_ref().unwrap().store.close();
    assert!(client.into_records().is_err());
}

#[test]
fn original_authorization_is_rechecked_after_irreversible_ready_submission() {
    let exchange = Exchange::new(Profile::P256, ActivationSource::LiveAuthority);
    let (mut client, _) = exchange.noise_pair();
    let mut writer = Writer {
        revoke: Some(client.account.clone()),
        ..Writer::default()
    };
    assert!(client.submit_ready(&mut writer).is_err());
    assert!(writer.payload.is_some());
    assert!(client.into_records().is_err());
}
#[test]
fn transcript_substitution_and_bad_record_do_not_advance_other_scopes() {
    let mut exchange = Exchange::new(Profile::X25519, ActivationSource::LiveAuthority);
    let original = exchange.fsa.clone();
    let last = exchange.fsa.len() - 1;
    exchange.fsa[last] ^= 1;
    assert!(
        Handshake::new(
            exchange.fixture.reserve().unwrap(),
            Role::Client,
            exchange.keys[0].clone(),
            exchange.input()
        )
        .is_err()
    );
    exchange.fsa = original;
    let (client, server) = exchange.noise_pair();
    let (mut client, mut server) = ready_pair(client, server);
    for scope in [1, 3] {
        client.install_reliable_scope(scope).unwrap();
        server.install_reliable_scope(scope).unwrap();
    }
    let mut wire = [0; 128];
    let mut out = [0; 128];
    let n = client.seal_reliable(1, 8, b"bad tag", &mut wire).unwrap();
    wire[n - 1] ^= 1;
    assert!(
        server
            .open_reliable(1, &wire[..n], &mut out, |_, _| Ok(()))
            .is_err()
    );
    assert!(out.iter().all(|byte| *byte == 0));
    let n = client.seal_reliable(3, 8, b"healthy", &mut wire).unwrap();
    let m = server
        .open_reliable(3, &wire[..n], &mut out, |_, _| Ok(()))
        .unwrap();
    assert_eq!(&out[..m], b"healthy");
    assert!(
        server
            .open_reliable(1, &wire[..n], &mut out, |_, _| Ok(()))
            .is_err()
    );
}

fn hex(value: &serde_json::Value) -> Vec<u8> {
    codec::tests::hex(value.as_str().unwrap())
}
fn fixed32(value: &serde_json::Value) -> [u8; 32] {
    hex(value).try_into().unwrap()
}
#[test]
fn production_ready_encoding_and_keys_match_the_independent_shared_corpus() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/ready.json")).unwrap();
    for vector in vectors["vectors"].as_array().unwrap() {
        let c = &vector["context"];
        let profile = Profile::parse(c["crypto_profile_id"].as_str().unwrap()).unwrap();
        let exchange = Exchange::new(profile, ActivationSource::LiveAuthority);
        let mut handshake = exchange.handshake(Role::Client);
        let role = c["role"].as_u64().unwrap() as usize;
        handshake.hash = fixed32(&c["handshake_hash_hex"]);
        handshake.binding.fsb = fixed32(&c["fsb_digest_hex"]);
        handshake.binding.fsa = fixed32(&c["fsa_digest_hex"]);
        handshake.binding.context = fixed32(&c["transport_context_digest_hex"]);
        handshake.binding.admission = fixed32(&c["admission_binding_hex"]);
        handshake.binding.certificates[role] = fixed32(&c["certificate_digest_hex"]);
        // Fixed roots are isolated test inputs to the exact production encoder,
        // not a production import API or a protocol completion assertion.
        let born = handshake.account.security_time().unwrap();
        handshake.records = Some(
            RecordEngine::prepare(
                handshake.account.clone(),
                &handshake.binding,
                handshake.hash,
                born,
                Zeroizing::new(fixed32(&c["epoch_root_hex"])),
            )
            .unwrap(),
        );
        handshake.binding.features = c["selected_features"].as_u64().unwrap();
        let proof: [u8; 64] = hex(&vector["identity_proof_hex"]).try_into().unwrap();
        assert_eq!(
            handshake.ready_inputs(role, None).unwrap(),
            hex(&vector["signature_message_hex"])
        );
        assert_eq!(
            handshake.ready_inputs(role, Some(&proof)).unwrap(),
            hex(&vector["mac_message_hex"])
        );
        let key = handshake.ready_key(role).unwrap();
        assert_eq!(key.as_slice(), hex(&vector["key_hex"]));
        assert_eq!(
            mac(&key, &handshake.ready_inputs(role, Some(&proof)).unwrap()).as_slice(),
            hex(&vector["confirmation_mac_hex"])
        );
    }
}
#[test]
fn production_initial_record_bytes_match_both_profiles_and_directions() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/records.json")).unwrap();
    let mut count = 0;
    for vector in vectors["vectors"].as_array().unwrap() {
        let scope = vector["sequence_scope"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        if vector["epoch"] != 0 || vector["sequence"] != "0" || scope > 4_194_335 {
            continue;
        }
        let profile = Profile::parse(vector["profile"].as_str().unwrap()).unwrap();
        let exchange = Exchange::new(profile, ActivationSource::LiveAuthority);
        let role = if vector["direction"] == 0 {
            Role::Client
        } else {
            Role::Server
        };
        let handshake = exchange.handshake(role);
        let born = handshake.account.security_time().unwrap();
        let mut records = RecordEngine::prepare(
            handshake.account.clone(),
            &handshake.binding,
            fixed32(&vector["handshake_hash_hex"]),
            born,
            Zeroizing::new(fixed32(&vector["epoch_root_hex"])),
        )
        .unwrap();
        records.start(born).unwrap();
        if scope != 0 {
            records.install_reliable_scope(scope).unwrap();
        }
        let plaintext = hex(&vector["plaintext_hex"]);
        let expected = hex(&vector["wire_hex"]);
        let mut out = vec![0; expected.len()];
        let n = records
            .seal_reliable(
                scope,
                vector["frame_type"].as_u64().unwrap() as u8,
                &plaintext,
                &mut out,
            )
            .unwrap();
        assert_eq!(&out[..n], expected, "{}", vector["id"]);
        count += 1;
    }
    assert!(count >= 4);
}

pub(super) fn record_pair_for_limits(profile: Profile) -> (Fixture, RecordEngine, RecordEngine) {
    let exchange = Exchange::new(profile, ActivationSource::LiveAuthority);
    let (c, s) = exchange.noise_pair();
    let (c, s) = ready_pair(c, s);
    (exchange.fixture, c, s)
}
