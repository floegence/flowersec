//! Library execution with public fixed inputs. Admission, READY, runtime owners
//! and full four-SDK cryptographic composition remain separate obligations.
#[path = "../src/profile_dh_v4_reference.rs"]
mod dh;
#[path = "../src/noise_v4_reference.rs"]
mod noise;
#[allow(dead_code)]
#[path = "../src/protocol_v4_registry_generated.rs"]
mod registry;

use noise::{FixedHandshake, FixedInput, profile};

const PROFILES: [&str; 2] = [registry::DH_PROFILE_X25519, registry::DH_PROFILE_P256];

struct Material {
    profile: &'static str,
    statics: [[u8; 32]; 2],
    publics: [Vec<u8>; 2],
    ephemerals: [[u8; 32]; 2],
    psks: [[u8; 32]; 2],
    prologues: [Vec<u8>; 2],
}

impl Material {
    fn new(profile: &'static str) -> Self {
        let statics = [[0x11; 32], [0x22; 32]];
        Self {
            profile,
            publics: statics.map(|private| dh::public(profile, &private).unwrap()),
            statics,
            ephemerals: [[0x33; 32], [0x44; 32]],
            psks: [[0x55; 32]; 2],
            // Opaque library fixture, deliberately not represented as an
            // authenticated Flowersec FSB4/FSA4/admission transcript.
            prologues: [
                b"public Noise library fixture".to_vec(),
                b"public Noise library fixture".to_vec(),
            ],
        }
    }
    fn input(&self, side: usize) -> FixedInput<'_> {
        FixedInput {
            profile: self.profile,
            initiator: side == 0,
            local_private: &self.statics[side],
            local_public: &self.publics[side],
            remote_public: &self.publics[1 - side],
            ephemeral_private: &self.ephemerals[side],
            psk: &self.psks[side],
            prologue: &self.prologues[side],
            context_digest: [0x66; 32],
        }
    }
    fn pair(&self) -> (FixedHandshake, FixedHandshake) {
        (
            FixedHandshake::new(self.input(0)).unwrap(),
            FixedHandshake::new(self.input(1)).unwrap(),
        )
    }
}

fn assert_dead(state: &mut FixedHandshake) {
    assert!(state.finish().is_err());
    assert!(state.write().is_err());
    assert!(state.read(&[]).is_err());
}

#[test]
fn two_empty_messages_and_one_shot_canonical_root() {
    for name in PROFILES {
        let material = Material::new(name);
        let (mut client, mut server) = material.pair();
        let first = client.write().unwrap();
        assert_eq!(first.len(), profile(name).unwrap().handshake_message_bytes);
        assert_eq!(
            &first[..profile(name).unwrap().dh_public_bytes],
            dh::public(name, &material.ephemerals[0]).unwrap()
        );
        server.read(&first).unwrap();
        let second = server.write().unwrap();
        assert_eq!(second.len(), profile(name).unwrap().handshake_message_bytes);
        assert_eq!(
            &second[..profile(name).unwrap().dh_public_bytes],
            dh::public(name, &material.ephemerals[1]).unwrap()
        );
        // Server completes after Read1/Write2; it does not wait for an extra
        // acknowledgement that the client received message 2.
        let server_root = server.finish().unwrap();
        client.read(&second).unwrap();
        let client_root = client.finish().unwrap();
        assert_eq!(client_root.handshake_hash, server_root.handshake_hash);
        assert!(client_root.same_root(&server_root));
        assert_dead(&mut client);
        assert_dead(&mut server);
    }
}

#[test]
fn completion_requires_both_successful_local_operations() {
    for name in PROFILES {
        let material = Material::new(name);
        for side in 0..2 {
            let mut fresh = FixedHandshake::new(material.input(side)).unwrap();
            assert_dead(&mut fresh);
        }
        let (mut client, mut server) = material.pair();
        let first = client.write().unwrap();
        assert_dead(&mut client);
        server.read(&first).unwrap();
        assert_dead(&mut server);
    }
}

#[test]
fn wrong_turn_or_duplicate_operation_consumes_attempt() {
    for name in PROFILES {
        let material = Material::new(name);
        let (mut client, mut server) = material.pair();
        assert!(server.write().is_err());
        assert_dead(&mut server);
        assert!(
            client
                .read(&vec![0; profile(name).unwrap().handshake_message_bytes])
                .is_err()
        );
        assert_dead(&mut client);

        let (mut client, mut server) = material.pair();
        let first = client.write().unwrap();
        assert!(client.write().is_err());
        assert_dead(&mut client);
        server.read(&first).unwrap();
        assert!(server.read(&first).is_err());
        assert_dead(&mut server);
    }
}

#[test]
fn mismatched_psk_prologue_or_known_static_never_completes() {
    for name in PROFILES {
        for variant in 0..3 {
            let mut material = Material::new(name);
            if variant == 0 {
                material.psks[1][0] ^= 1;
            }
            if variant == 1 {
                material.prologues[1][0] ^= 1;
            }
            let (mut client, mut server) = if variant == 2 {
                let wrong_static = dh::public(name, &[0x77; 32]).unwrap();
                let mut server_input = material.input(1);
                server_input.remote_public = &wrong_static;
                (
                    FixedHandshake::new(material.input(0)).unwrap(),
                    FixedHandshake::new(server_input).unwrap(),
                )
            } else {
                material.pair()
            };
            let first = client.write().unwrap();
            assert_eq!(server.read(&first), Err(noise::FAILURE));
            assert_dead(&mut server);
            assert_dead(&mut client);
        }
    }
}

#[test]
fn each_message_rejects_truncation_extension_and_every_byte_mutation() {
    for name in PROFILES {
        let material = Material::new(name);
        let size = profile(name).unwrap().handshake_message_bytes;
        for flight in 0..2 {
            for variant in 0..(size * 2 + 2) {
                let (mut client, mut server) = material.pair();
                let first = client.write().unwrap();
                let (mut message, receiver) = if flight == 0 {
                    (first, &mut server)
                } else {
                    server.read(&first).unwrap();
                    (server.write().unwrap(), &mut client)
                };
                if variant < size {
                    message.truncate(variant);
                } else if variant < size * 2 {
                    message[variant - size] ^= 0x80;
                } else {
                    message.extend_from_slice(&[0, 1][..variant - size * 2 + 1]);
                }
                assert_eq!(
                    receiver.read(&message),
                    Err(noise::FAILURE),
                    "{name} flight {flight} variant {variant}"
                );
                assert_dead(receiver);
            }
        }
    }
}

#[test]
fn malformed_material_is_rejected_before_snow_builder() {
    for name in PROFILES {
        let material = Material::new(name);
        for length in [0, 31, 33, 66, 1024] {
            let invalid = vec![0; length];
            let mut input = material.input(0);
            input.local_private = &invalid;
            assert!(FixedHandshake::new(input).is_err());
            let mut input = material.input(0);
            input.ephemeral_private = &invalid;
            assert!(FixedHandshake::new(input).is_err());
            let mut input = material.input(0);
            input.remote_public = &invalid;
            assert!(FixedHandshake::new(input).is_err());
            let mut input = material.input(0);
            input.psk = &invalid;
            assert!(FixedHandshake::new(input).is_err());
        }
        let mut input = material.input(0);
        input.local_public = &material.publics[1];
        assert!(FixedHandshake::new(input).is_err());
        let mut input = material.input(0);
        input.profile = "unregistered";
        assert!(FixedHandshake::new(input).is_err());
    }
}

#[test]
fn zero_dh_result_cannot_reach_root() {
    // X25519 permits this exact-width public encoding, then rejects its real
    // shared result before MixKey even though a nonzero PSK is available.
    let material = Material::new(registry::DH_PROFILE_X25519);
    let zero = [0; 32];
    let mut input = material.input(0);
    input.remote_public = &zero;
    let mut client = FixedHandshake::new(input).unwrap();
    assert_eq!(client.write(), Err(noise::FAILURE));
    assert_dead(&mut client);
    for flight in 0..2 {
        let (mut client, mut server) = material.pair();
        let mut first = client.write().unwrap();
        if flight == 0 {
            first[..32].copy_from_slice(&zero);
            assert_eq!(server.read(&first), Err(noise::FAILURE));
            assert_dead(&mut server);
        } else {
            server.read(&first).unwrap();
            let mut second = server.write().unwrap();
            second[..32].copy_from_slice(&zero);
            assert_eq!(client.read(&second), Err(noise::FAILURE));
            assert_dead(&mut client);
        }
    }
    // A valid P-256 zero-x public point yields zero under scalar 1. This is
    // not an invalid-point test; the actual es call must reject the result.
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../../testdata/transport_v4/profile_dh.json")).unwrap();
    let vector = corpus["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "dh_p_zero_result")
        .unwrap();
    let zero_x = noise::decode_hex(vector["public_hex"].as_str().unwrap()).unwrap();
    let scalar_one = noise::decode_hex(vector["private_hex"].as_str().unwrap()).unwrap();
    let material = Material::new(registry::DH_PROFILE_P256);
    let mut input = material.input(0);
    input.remote_public = &zero_x;
    input.ephemeral_private = &scalar_one;
    let mut client = FixedHandshake::new(input).unwrap();
    assert_eq!(client.write(), Err(noise::FAILURE));
    assert_dead(&mut client);
}
