pub const ABI: u32 = 1;
pub const INPUT_BYTES: usize = 1048576;
pub const PROLOGUE_OFFSET: usize = 266;
pub const PROFILE_NAMES: [&str; 2] = [
    "fs4-kkpsk0-x25519-chachapoly-ed25519-sha256-1",
    "fs4-kkpsk0-p256-aes256gcm-ed25519-sha256-1",
];
pub const NOISE_NAMES: [&str; 2] = [
    "Noise_KKpsk0_25519_ChaChaPoly_SHA256",
    "Noise_KKpsk0_P256_AESGCM_SHA256",
];
pub const ROOT_LABEL: &[u8] = b"flowersec/v4/initial-root\0";
