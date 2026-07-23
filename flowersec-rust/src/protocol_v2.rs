//! Carrier-neutral Flowersec v2 wire and cryptographic primitives.
//!
//! This module is intentionally stateless. Session actors must enforce sequence
//! monotonicity, epoch transitions, replay rejection, and bounded buffering.

use aes_gcm::{
    Aes256Gcm, KeyInit,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SETUP_PREFACE_V2_SIZE: usize = 56;
pub const RECORD_HEADER_V2_SIZE: usize = 24;
pub const INNER_HEADER_V2_SIZE: usize = 8;
pub const AEAD_TAG_V2_SIZE: usize = 16;
pub const MAX_DATA_V2_BYTES: usize = 16_384;
pub const MAX_CIPHERTEXT_V2_BYTES: usize =
    INNER_HEADER_V2_SIZE + MAX_DATA_V2_BYTES + AEAD_TAG_V2_SIZE;
pub const OPEN_FIXED_PAYLOAD_V2_BYTES: usize = 46;
pub const MAX_OPEN_V2_BYTES: usize = 8_192;
pub const MAX_OPEN_KIND_V2_BYTES: usize = 128;
pub const MAX_OPEN_METADATA_V2_BYTES: usize = 4_096;
pub(crate) const UNRELIABLE_HEADER_V2_SIZE: usize = 32;
pub(crate) const MAX_UNRELIABLE_PLAINTEXT_V2_BYTES: usize = 1_024;
pub(crate) const MAX_UNRELIABLE_WIRE_V2_BYTES: usize =
    UNRELIABLE_HEADER_V2_SIZE + MAX_UNRELIABLE_PLAINTEXT_V2_BYTES + AEAD_TAG_V2_SIZE;

const MAX_OPEN_METADATA_DEPTH: usize = 4;
const MAX_OPEN_METADATA_NODES: usize = 64;
const MAX_OPEN_METADATA_KEYS: usize = 64;
const MAX_OPEN_METADATA_ARRAY: usize = 32;
const MAX_OPEN_METADATA_KEY_BYTES: usize = 64;
const MAX_OPEN_METADATA_STRING_BYTES: usize = 512;
const MAX_IJSON_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const UNICODE_15_1_ASSIGNED_RANGES_HEX: &str = concat!(
    "00000000037700037A00037F00038400038A00038C00038C00038E0003A10003A300052F00053100055600055900058A00058D00058F0005910005C7",
    "0005D00005EA0005EF0005F400060000070D00070F00074A00074D0007B10007C00007FA0007FD00082D00083000083E00084000085B00085E00085E",
    "00086000086A00087000088E00089000089100089800098300098500098C00098F0009900009930009A80009AA0009B00009B20009B20009B60009B9",
    "0009BC0009C40009C70009C80009CB0009CE0009D70009D70009DC0009DD0009DF0009E30009E60009FE000A01000A03000A05000A0A000A0F000A10",
    "000A13000A28000A2A000A30000A32000A33000A35000A36000A38000A39000A3C000A3C000A3E000A42000A47000A48000A4B000A4D000A51000A51",
    "000A59000A5C000A5E000A5E000A66000A76000A81000A83000A85000A8D000A8F000A91000A93000AA8000AAA000AB0000AB2000AB3000AB5000AB9",
    "000ABC000AC5000AC7000AC9000ACB000ACD000AD0000AD0000AE0000AE3000AE6000AF1000AF9000AFF000B01000B03000B05000B0C000B0F000B10",
    "000B13000B28000B2A000B30000B32000B33000B35000B39000B3C000B44000B47000B48000B4B000B4D000B55000B57000B5C000B5D000B5F000B63",
    "000B66000B77000B82000B83000B85000B8A000B8E000B90000B92000B95000B99000B9A000B9C000B9C000B9E000B9F000BA3000BA4000BA8000BAA",
    "000BAE000BB9000BBE000BC2000BC6000BC8000BCA000BCD000BD0000BD0000BD7000BD7000BE6000BFA000C00000C0C000C0E000C10000C12000C28",
    "000C2A000C39000C3C000C44000C46000C48000C4A000C4D000C55000C56000C58000C5A000C5D000C5D000C60000C63000C66000C6F000C77000C8C",
    "000C8E000C90000C92000CA8000CAA000CB3000CB5000CB9000CBC000CC4000CC6000CC8000CCA000CCD000CD5000CD6000CDD000CDE000CE0000CE3",
    "000CE6000CEF000CF1000CF3000D00000D0C000D0E000D10000D12000D44000D46000D48000D4A000D4F000D54000D63000D66000D7F000D81000D83",
    "000D85000D96000D9A000DB1000DB3000DBB000DBD000DBD000DC0000DC6000DCA000DCA000DCF000DD4000DD6000DD6000DD8000DDF000DE6000DEF",
    "000DF2000DF4000E01000E3A000E3F000E5B000E81000E82000E84000E84000E86000E8A000E8C000EA3000EA5000EA5000EA7000EBD000EC0000EC4",
    "000EC6000EC6000EC8000ECE000ED0000ED9000EDC000EDF000F00000F47000F49000F6C000F71000F97000F99000FBC000FBE000FCC000FCE000FDA",
    "0010000010C50010C70010C70010CD0010CD0010D000124800124A00124D00125000125600125800125800125A00125D00126000128800128A00128D",
    "0012900012B00012B20012B50012B80012BE0012C00012C00012C20012C50012C80012D60012D800131000131200131500131800135A00135D00137C",
    "0013800013990013A00013F50013F80013FD00140000169C0016A00016F800170000171500171F00173600174000175300176000176C00176E001770",
    "0017720017730017800017DD0017E00017E90017F00017F90018000018190018200018780018800018AA0018B00018F500190000191E00192000192B",
    "00193000193B00194000194000194400196D0019700019740019800019AB0019B00019C90019D00019DA0019DE001A1B001A1E001A5E001A60001A7C",
    "001A7F001A89001A90001A99001AA0001AAD001AB0001ACE001B00001B4C001B50001B7E001B80001BF3001BFC001C37001C3B001C49001C4D001C88",
    "001C90001CBA001CBD001CC7001CD0001CFA001D00001F15001F18001F1D001F20001F45001F48001F4D001F50001F57001F59001F59001F5B001F5B",
    "001F5D001F5D001F5F001F7D001F80001FB4001FB6001FC4001FC6001FD3001FD6001FDB001FDD001FEF001FF2001FF4001FF6001FFE002000002064",
    "00206600207100207400208E00209000209C0020A00020C00020D00020F000210000218B00219000242600244000244A002460002B73002B76002B95",
    "002B97002CF3002CF9002D25002D27002D27002D2D002D2D002D30002D67002D6F002D70002D7F002D96002DA0002DA6002DA8002DAE002DB0002DB6",
    "002DB8002DBE002DC0002DC6002DC8002DCE002DD0002DD6002DD8002DDE002DE0002E5D002E80002E99002E9B002EF3002F00002FD5002FF000303F",
    "0030410030960030990030FF00310500312F00313100318E0031900031E30031EF00321E00322000A48C00A49000A4C600A4D000A62B00A64000A6F7",
    "00A70000A7CA00A7D000A7D100A7D300A7D300A7D500A7D900A7F200A82C00A83000A83900A84000A87700A88000A8C500A8CE00A8D900A8E000A953",
    "00A95F00A97C00A98000A9CD00A9CF00A9D900A9DE00A9FE00AA0000AA3600AA4000AA4D00AA5000AA5900AA5C00AAC200AADB00AAF600AB0100AB06",
    "00AB0900AB0E00AB1100AB1600AB2000AB2600AB2800AB2E00AB3000AB6B00AB7000ABED00ABF000ABF900AC0000D7A300D7B000D7C600D7CB00D7FB",
    "00D80000FA6D00FA7000FAD900FB0000FB0600FB1300FB1700FB1D00FB3600FB3800FB3C00FB3E00FB3E00FB4000FB4100FB4300FB4400FB4600FBC2",
    "00FBD300FD8F00FD9200FDC700FDCF00FE1900FE2000FE5200FE5400FE6600FE6800FE6B00FE7000FE7400FE7600FEFC00FEFF00FEFF00FF0100FFBE",
    "00FFC200FFC700FFCA00FFCF00FFD200FFD700FFDA00FFDC00FFE000FFE600FFE800FFEE00FFF901000B01000D01002601002801003A01003C01003D",
    "01003F01004D01005001005D0100800100FA01010001010201010701013301013701018E01019001019C0101A00101A00101D00101FD01028001029C",
    "0102A00102D00102E00102FB01030001032301032D01034A01035001037A01038001039D01039F0103C30103C80103D501040001049D0104A00104A9",
    "0104B00104D30104D80104FB01050001052701053001056301056F01057A01057C01058A01058C0105920105940105950105970105A10105A30105B1",
    "0105B30105B90105BB0105BC0106000107360107400107550107600107670107800107850107870107B00107B20107BA010800010805010808010808",
    "01080A01083501083701083801083C01083C01083F01085501085701089E0108A70108AF0108E00108F20108F40108F50108FB01091B01091F010939",
    "01093F01093F0109800109B70109BC0109CF0109D2010A03010A05010A06010A0C010A13010A15010A17010A19010A35010A38010A3A010A3F010A48",
    "010A50010A58010A60010A9F010AC0010AE6010AEB010AF6010B00010B35010B39010B55010B58010B72010B78010B91010B99010B9C010BA9010BAF",
    "010C00010C48010C80010CB2010CC0010CF2010CFA010D27010D30010D39010E60010E7E010E80010EA9010EAB010EAD010EB0010EB1010EFD010F27",
    "010F30010F59010F70010F89010FB0010FCB010FE0010FF601100001104D01105201107501107F0110C20110CD0110CD0110D00110E80110F00110F9",
    "0111000111340111360111470111500111760111800111DF0111E10111F401120001121101121301124101128001128601128801128801128A01128D",
    "01128F01129D01129F0112A90112B00112EA0112F00112F901130001130301130501130C01130F01131001131301132801132A011330011332011333",
    "01133501133901133B01134401134701134801134B01134D01135001135001135701135701135D01136301136601136C01137001137401140001145B",
    "01145D0114610114800114C70114D00114D90115800115B50115B80115DD01160001164401165001165901166001166C0116800116B90116C00116C9",
    "01170001171A01171D01172B01173001174601180001183B0118A00118F20118FF01190601190901190901190C011913011915011916011918011935",
    "01193701193801193B0119460119500119590119A00119A70119AA0119D70119DA0119E4011A00011A47011A50011AA2011AB0011AF8011B00011B09",
    "011C00011C08011C0A011C36011C38011C45011C50011C6C011C70011C8F011C92011CA7011CA9011CB6011D00011D06011D08011D09011D0B011D36",
    "011D3A011D3A011D3C011D3D011D3F011D47011D50011D59011D60011D65011D67011D68011D6A011D8E011D90011D91011D93011D98011DA0011DA9",
    "011EE0011EF8011F00011F10011F12011F3A011F3E011F59011FB0011FB0011FC0011FF1011FFF01239901240001246E012470012474012480012543",
    "012F90012FF2013000013455014400014646016800016A38016A40016A5E016A60016A69016A6E016ABE016AC0016AC9016AD0016AED016AF0016AF5",
    "016B00016B45016B50016B59016B5B016B61016B63016B77016B7D016B8F016E40016E9A016F00016F4A016F4F016F87016F8F016F9F016FE0016FE4",
    "016FF0016FF10170000187F7018800018CD5018D00018D0801AFF001AFF301AFF501AFFB01AFFD01AFFE01B00001B12201B13201B13201B15001B152",
    "01B15501B15501B16401B16701B17001B2FB01BC0001BC6A01BC7001BC7C01BC8001BC8801BC9001BC9901BC9C01BCA301CF0001CF2D01CF3001CF46",
    "01CF5001CFC301D00001D0F501D10001D12601D12901D1EA01D20001D24501D2C001D2D301D2E001D2F301D30001D35601D36001D37801D40001D454",
    "01D45601D49C01D49E01D49F01D4A201D4A201D4A501D4A601D4A901D4AC01D4AE01D4B901D4BB01D4BB01D4BD01D4C301D4C501D50501D50701D50A",
    "01D50D01D51401D51601D51C01D51E01D53901D53B01D53E01D54001D54401D54601D54601D54A01D55001D55201D6A501D6A801D7CB01D7CE01DA8B",
    "01DA9B01DA9F01DAA101DAAF01DF0001DF1E01DF2501DF2A01E00001E00601E00801E01801E01B01E02101E02301E02401E02601E02A01E03001E06D",
    "01E08F01E08F01E10001E12C01E13001E13D01E14001E14901E14E01E14F01E29001E2AE01E2C001E2F901E2FF01E2FF01E4D001E4F901E7E001E7E6",
    "01E7E801E7EB01E7ED01E7EE01E7F001E7FE01E80001E8C401E8C701E8D601E90001E94B01E95001E95901E95E01E95F01EC7101ECB401ED0101ED3D",
    "01EE0001EE0301EE0501EE1F01EE2101EE2201EE2401EE2401EE2701EE2701EE2901EE3201EE3401EE3701EE3901EE3901EE3B01EE3B01EE4201EE42",
    "01EE4701EE4701EE4901EE4901EE4B01EE4B01EE4D01EE4F01EE5101EE5201EE5401EE5401EE5701EE5701EE5901EE5901EE5B01EE5B01EE5D01EE5D",
    "01EE5F01EE5F01EE6101EE6201EE6401EE6401EE6701EE6A01EE6C01EE7201EE7401EE7701EE7901EE7C01EE7E01EE7E01EE8001EE8901EE8B01EE9B",
    "01EEA101EEA301EEA501EEA901EEAB01EEBB01EEF001EEF101F00001F02B01F03001F09301F0A001F0AE01F0B101F0BF01F0C101F0CF01F0D101F0F5",
    "01F10001F1AD01F1E601F20201F21001F23B01F24001F24801F25001F25101F26001F26501F30001F6D701F6DC01F6EC01F6F001F6FC01F70001F776",
    "01F77B01F7D901F7E001F7EB01F7F001F7F001F80001F80B01F81001F84701F85001F85901F86001F88701F89001F8AD01F8B001F8B101F90001FA53",
    "01FA6001FA6D01FA7001FA7C01FA8001FA8801FA9001FABD01FABF01FAC501FACE01FADB01FAE001FAE801FAF001FAF801FB0001FB9201FB9401FBCA",
    "01FBF001FBF901FFFE02A6DF02A70002B73902B74002B81D02B82002CEA102CEB002EBE002EBF002EE5D02F80002FA1D02FFFE03134A0313500323AF",
    "03FFFE03FFFF04FFFE04FFFF05FFFE05FFFF06FFFE06FFFF07FFFE07FFFF08FFFE08FFFF09FFFE09FFFF0AFFFE0AFFFF0BFFFE0BFFFF0CFFFE0CFFFF",
    "0DFFFE0DFFFF0E00010E00010E00200E007F0E01000E01EF0EFFFE10FFFF",
);

const PROTOCOL_V2_VERSION: u8 = 2;

/// Stable failures produced by the v2 wire and cryptographic primitives.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolV2Error {
    #[error("invalid v2 direction")]
    InvalidDirection,
    #[error("invalid FSS2 setup preface")]
    InvalidSetupPreface,
    #[error("invalid FSR2 record header")]
    InvalidRecordHeader,
    #[error("FSR2 record is too large")]
    RecordTooLarge,
    #[error("invalid FSR2 inner record")]
    InvalidInnerRecord,
    #[error("invalid Flowersec v2 OPEN payload")]
    InvalidOpenPayload,
    #[error("v2 record authentication failed")]
    Authentication,
    #[error("v2 cryptographic operation failed")]
    Crypto,
    #[error("v2 HKDF expansion failed")]
    Hkdf,
    #[error("invalid Flowersec v2 unreliable message")]
    InvalidUnreliableMessage,
}

/// Direction of one v2 record key schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DirectionV2 {
    ClientToServer = 1,
    ServerToClient = 2,
}

impl TryFrom<u8> for DirectionV2 {
    type Error = ProtocolV2Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientToServer),
            2 => Ok(Self::ServerToClient),
            _ => Err(ProtocolV2Error::InvalidDirection),
        }
    }
}

/// AEAD suites defined by the Flowersec v2 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherSuiteV2 {
    ChaCha20Poly1305,
    Aes256Gcm,
}

/// Role that allocated a logical stream identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StreamOpenerRoleV2 {
    Client = 1,
    Server = 2,
}

/// Directional roots for one session epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EpochRootsV2 {
    epoch_secret: [u8; 32],
    control_root: [u8; 32],
    stream_root: [u8; 32],
    setup_root: [u8; 32],
    rekey_root: [u8; 32],
}

impl EpochRootsV2 {
    pub(crate) fn epoch_secret(&self) -> &[u8; 32] {
        &self.epoch_secret
    }

    pub fn control_root(&self) -> &[u8; 32] {
        &self.control_root
    }

    pub fn stream_root(&self) -> &[u8; 32] {
        &self.stream_root
    }

    pub fn setup_root(&self) -> &[u8; 32] {
        &self.setup_root
    }

    pub fn rekey_root(&self) -> &[u8; 32] {
        &self.rekey_root
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub(crate) struct UnreliableMaterialV2 {
    key: [u8; 32],
    nonce_prefix: [u8; 4],
}

impl std::fmt::Debug for UnreliableMaterialV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UnreliableMaterialV2([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UnreliableHeaderV2 {
    pub epoch: u32,
    pub sequence: u64,
    pub expires_at_unix_ms: u64,
    pub ciphertext_length: u32,
}

impl UnreliableHeaderV2 {
    pub(crate) fn encode(self) -> Result<[u8; UNRELIABLE_HEADER_V2_SIZE], ProtocolV2Error> {
        let ciphertext_length = usize::try_from(self.ciphertext_length)
            .map_err(|_| ProtocolV2Error::InvalidUnreliableMessage)?;
        if !(AEAD_TAG_V2_SIZE..=MAX_UNRELIABLE_PLAINTEXT_V2_BYTES + AEAD_TAG_V2_SIZE)
            .contains(&ciphertext_length)
            || self.expires_at_unix_ms == 0
        {
            return Err(ProtocolV2Error::InvalidUnreliableMessage);
        }
        let mut raw = [0_u8; UNRELIABLE_HEADER_V2_SIZE];
        raw[..4].copy_from_slice(b"FSD2");
        raw[4] = 2;
        raw[6..8].copy_from_slice(&(UNRELIABLE_HEADER_V2_SIZE as u16).to_be_bytes());
        raw[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        raw[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        raw[20..28].copy_from_slice(&self.expires_at_unix_ms.to_be_bytes());
        raw[28..32].copy_from_slice(&self.ciphertext_length.to_be_bytes());
        Ok(raw)
    }

    pub(crate) fn decode(raw: &[u8]) -> Result<Self, ProtocolV2Error> {
        if raw.len() != UNRELIABLE_HEADER_V2_SIZE
            || &raw[..4] != b"FSD2"
            || raw[4] != 2
            || raw[5] != 0
            || u16::from_be_bytes(raw[6..8].try_into().unwrap()) != UNRELIABLE_HEADER_V2_SIZE as u16
        {
            return Err(ProtocolV2Error::InvalidUnreliableMessage);
        }
        let header = Self {
            epoch: u32::from_be_bytes(raw[8..12].try_into().unwrap()),
            sequence: u64::from_be_bytes(raw[12..20].try_into().unwrap()),
            expires_at_unix_ms: u64::from_be_bytes(raw[20..28].try_into().unwrap()),
            ciphertext_length: u32::from_be_bytes(raw[28..32].try_into().unwrap()),
        };
        header.encode()?;
        Ok(header)
    }
}

impl std::fmt::Debug for EpochRootsV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EpochRootsV2([REDACTED])")
    }
}

/// Per-stream record key material for one direction and epoch.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecordMaterialV2 {
    secret: [u8; 32],
    record_key: [u8; 32],
    nonce_prefix: [u8; 4],
}

impl RecordMaterialV2 {
    #[cfg(test)]
    pub fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn record_key(&self) -> &[u8; 32] {
        &self.record_key
    }

    pub fn nonce_prefix(&self) -> &[u8; 4] {
        &self.nonce_prefix
    }
}

impl std::fmt::Debug for RecordMaterialV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecordMaterialV2([REDACTED])")
    }
}

/// Fixed FSS2 setup preface fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupPrefaceV2 {
    opener_role: StreamOpenerRoleV2,
    logical_stream_id: u64,
    initial_epoch: u32,
    setup_mac: [u8; 32],
}

impl SetupPrefaceV2 {
    pub fn new(
        opener_role: StreamOpenerRoleV2,
        logical_stream_id: u64,
        initial_epoch: u32,
    ) -> Self {
        Self {
            opener_role,
            logical_stream_id,
            initial_epoch,
            setup_mac: [0; 32],
        }
    }

    pub fn set_setup_mac(&mut self, setup_mac: [u8; 32]) {
        self.setup_mac = setup_mac;
    }

    pub const fn opener_role(&self) -> StreamOpenerRoleV2 {
        self.opener_role
    }

    pub const fn logical_stream_id(&self) -> u64 {
        self.logical_stream_id
    }

    pub const fn initial_epoch(&self) -> u32 {
        self.initial_epoch
    }

    pub const fn setup_mac(&self) -> &[u8; 32] {
        &self.setup_mac
    }

    pub fn encode(&self) -> Result<[u8; SETUP_PREFACE_V2_SIZE], ProtocolV2Error> {
        if !valid_logical_stream_id(self.opener_role, self.logical_stream_id) {
            return Err(ProtocolV2Error::InvalidSetupPreface);
        }
        let mut output = [0_u8; SETUP_PREFACE_V2_SIZE];
        output[..4].copy_from_slice(b"FSS2");
        output[4] = PROTOCOL_V2_VERSION;
        output[5] = self.opener_role as u8;
        output[8..16].copy_from_slice(&self.logical_stream_id.to_be_bytes());
        output[16..20].copy_from_slice(&self.initial_epoch.to_be_bytes());
        output[24..].copy_from_slice(&self.setup_mac);
        Ok(output)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolV2Error> {
        if raw.len() != SETUP_PREFACE_V2_SIZE
            || &raw[..4] != b"FSS2"
            || raw[4] != PROTOCOL_V2_VERSION
            || raw[6] != 0
            || raw[7] != 0
            || raw[20..24] != [0; 4]
        {
            return Err(ProtocolV2Error::InvalidSetupPreface);
        }
        let opener_role = match raw[5] {
            1 => StreamOpenerRoleV2::Client,
            2 => StreamOpenerRoleV2::Server,
            _ => return Err(ProtocolV2Error::InvalidSetupPreface),
        };
        let logical_stream_id = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        if !valid_logical_stream_id(opener_role, logical_stream_id) {
            return Err(ProtocolV2Error::InvalidSetupPreface);
        }
        let mut setup_mac = [0; 32];
        setup_mac.copy_from_slice(&raw[24..56]);
        Ok(Self {
            opener_role,
            logical_stream_id,
            initial_epoch: u32::from_be_bytes(raw[16..20].try_into().unwrap()),
            setup_mac,
        })
    }
}

/// Fixed authenticated FSR2 record header fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordHeaderV2 {
    epoch: u32,
    sequence: u64,
    ciphertext_length: u32,
}

/// Canonical Flowersec v2 OPEN fields.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenPayloadV2 {
    logical_stream_id: u64,
    fss2_hash: [u8; 32],
    kind: String,
    metadata: Vec<u8>,
}

impl OpenPayloadV2 {
    pub fn new(
        logical_stream_id: u64,
        fss2_hash: [u8; 32],
        kind: String,
        metadata: Vec<u8>,
    ) -> Self {
        Self {
            logical_stream_id,
            fss2_hash,
            kind,
            metadata,
        }
    }

    pub const fn logical_stream_id(&self) -> u64 {
        self.logical_stream_id
    }

    pub const fn fss2_hash(&self) -> &[u8; 32] {
        &self.fss2_hash
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }
}

impl RecordHeaderV2 {
    pub const fn new(epoch: u32, sequence: u64, ciphertext_length: u32) -> Self {
        Self {
            epoch,
            sequence,
            ciphertext_length,
        }
    }

    pub const fn ciphertext_length(self) -> u32 {
        self.ciphertext_length
    }

    pub const fn epoch(self) -> u32 {
        self.epoch
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub fn encode(&self) -> Result<[u8; RECORD_HEADER_V2_SIZE], ProtocolV2Error> {
        if self.ciphertext_length < AEAD_TAG_V2_SIZE as u32 {
            return Err(ProtocolV2Error::InvalidRecordHeader);
        }
        if self.ciphertext_length as usize > MAX_CIPHERTEXT_V2_BYTES {
            return Err(ProtocolV2Error::RecordTooLarge);
        }
        let mut output = [0_u8; RECORD_HEADER_V2_SIZE];
        output[..4].copy_from_slice(b"FSR2");
        output[4] = PROTOCOL_V2_VERSION;
        output[5] = RECORD_HEADER_V2_SIZE as u8;
        output[8..12].copy_from_slice(&self.epoch.to_be_bytes());
        output[12..20].copy_from_slice(&self.sequence.to_be_bytes());
        output[20..24].copy_from_slice(&self.ciphertext_length.to_be_bytes());
        Ok(output)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, ProtocolV2Error> {
        if raw.len() != RECORD_HEADER_V2_SIZE
            || &raw[..4] != b"FSR2"
            || raw[4] != PROTOCOL_V2_VERSION
            || raw[5] != RECORD_HEADER_V2_SIZE as u8
            || raw[6] != 0
            || raw[7] != 0
        {
            return Err(ProtocolV2Error::InvalidRecordHeader);
        }
        let header = Self::new(
            u32::from_be_bytes(raw[8..12].try_into().unwrap()),
            u64::from_be_bytes(raw[12..20].try_into().unwrap()),
            u32::from_be_bytes(raw[20..24].try_into().unwrap()),
        );
        header.encode()?;
        Ok(header)
    }
}

/// Inner record types implemented by this crypto slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum InnerRecordTypeV2 {
    Open = 1,
    OpenAck = 2,
    OpenReject = 3,
    Data = 4,
    Fin = 5,
    StreamKeyUpdate = 6,
    SessionReady = 16,
    Ping = 17,
    Pong = 18,
    SessionKeyUpdate = 19,
    StreamReset = 20,
    GoAway = 21,
    SessionClose = 22,
    SessionReadyAck = 23,
    SessionKeyUpdateAck = 24,
    StreamKeyUpdateAck = 25,
}

impl TryFrom<u8> for InnerRecordTypeV2 {
    type Error = ProtocolV2Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::OpenAck),
            3 => Ok(Self::OpenReject),
            4 => Ok(Self::Data),
            5 => Ok(Self::Fin),
            6 => Ok(Self::StreamKeyUpdate),
            16 => Ok(Self::SessionReady),
            17 => Ok(Self::Ping),
            18 => Ok(Self::Pong),
            19 => Ok(Self::SessionKeyUpdate),
            20 => Ok(Self::StreamReset),
            21 => Ok(Self::GoAway),
            22 => Ok(Self::SessionClose),
            23 => Ok(Self::SessionReadyAck),
            24 => Ok(Self::SessionKeyUpdateAck),
            25 => Ok(Self::StreamKeyUpdateAck),
            _ => Err(ProtocolV2Error::InvalidInnerRecord),
        }
    }
}

/// Derives the directional epoch-zero roots from an existing session PRK.
pub fn derive_epoch_zero_v2(
    session_prk: &[u8; 32],
    direction: DirectionV2,
) -> Result<EpochRootsV2, ProtocolV2Error> {
    let epoch_secret = expand_32(
        session_prk,
        &label_with(b"flowersec v2 epoch zero", &[&[direction as u8]]),
    )?;
    Ok(EpochRootsV2 {
        epoch_secret,
        control_root: expand_32(
            &epoch_secret,
            &label_with(b"flowersec v2 control root", &[]),
        )?,
        stream_root: expand_32(&epoch_secret, &label_with(b"flowersec v2 stream root", &[]))?,
        setup_root: expand_32(&epoch_secret, &label_with(b"flowersec v2 setup root", &[]))?,
        rekey_root: expand_32(&epoch_secret, &label_with(b"flowersec v2 rekey root", &[]))?,
    })
}

/// Derives record material for one logical stream, direction, and epoch.
pub fn derive_stream_material_v2(
    stream_root: &[u8; 32],
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV2,
    epoch: u32,
) -> Result<RecordMaterialV2, ProtocolV2Error> {
    if logical_stream_id == 0 {
        return Err(ProtocolV2Error::InvalidSetupPreface);
    }
    let stream_id = logical_stream_id.to_be_bytes();
    let epoch_bytes = epoch.to_be_bytes();
    let secret = expand_32(
        stream_root,
        &label_with(
            b"flowersec v2 stream",
            &[h3, &stream_id, &[direction as u8], &epoch_bytes],
        ),
    )?;
    Ok(RecordMaterialV2 {
        secret,
        record_key: expand_32(&secret, &label_with(b"flowersec v2 record key", &[]))?,
        nonce_prefix: expand_4(&secret, &label_with(b"flowersec v2 nonce", &[]))?,
    })
}

pub fn derive_control_material_v2(
    control_root: &[u8; 32],
    h3: &[u8; 32],
    direction: DirectionV2,
    epoch: u32,
) -> Result<RecordMaterialV2, ProtocolV2Error> {
    let epoch_bytes = epoch.to_be_bytes();
    let stream_id = 0_u64.to_be_bytes();
    let secret = expand_32(
        control_root,
        &label_with(
            b"flowersec v2 control",
            &[h3, &stream_id, &[direction as u8], &epoch_bytes],
        ),
    )?;
    Ok(RecordMaterialV2 {
        secret,
        record_key: expand_32(&secret, &label_with(b"flowersec v2 record key", &[]))?,
        nonce_prefix: expand_4(&secret, &label_with(b"flowersec v2 nonce", &[]))?,
    })
}

pub(crate) fn derive_unreliable_material_v2(
    roots: &EpochRootsV2,
    h3: &[u8; 32],
    direction: DirectionV2,
    epoch: u32,
) -> Result<UnreliableMaterialV2, ProtocolV2Error> {
    let unreliable_root = expand_32(
        roots.epoch_secret(),
        &label_with(b"flowersec v2 unreliable root", &[]),
    )?;
    let material = expand_32(
        &unreliable_root,
        &label_with(
            b"flowersec v2 unreliable",
            &[h3, &[direction as u8], &epoch.to_be_bytes()],
        ),
    )?;
    Ok(UnreliableMaterialV2 {
        key: expand_32(&material, &label_with(b"flowersec v2 unreliable key", &[]))?,
        nonce_prefix: expand_4(
            &material,
            &label_with(b"flowersec v2 unreliable nonce", &[]),
        )?,
    })
}

pub(crate) fn seal_unreliable_v2(
    suite: CipherSuiteV2,
    material: &UnreliableMaterialV2,
    h3: &[u8; 32],
    direction: DirectionV2,
    header: UnreliableHeaderV2,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolV2Error> {
    if plaintext.is_empty()
        || plaintext.len() > MAX_UNRELIABLE_PLAINTEXT_V2_BYTES
        || plaintext.len() + AEAD_TAG_V2_SIZE != header.ciphertext_length as usize
    {
        return Err(ProtocolV2Error::InvalidUnreliableMessage);
    }
    let raw_header = header.encode()?;
    let aad = label_with(
        b"flowersec-v2-unreliable",
        &[h3, &[direction as u8], &raw_header],
    );
    let nonce = record_nonce(material.nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV2::ChaCha20Poly1305 => seal_chacha(&material.key, nonce, &aad, plaintext),
        CipherSuiteV2::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(&material.key).map_err(|_| ProtocolV2Error::Crypto)?;
            cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV2Error::Crypto)
        }
    }
}

pub(crate) fn open_unreliable_v2(
    suite: CipherSuiteV2,
    material: &UnreliableMaterialV2,
    h3: &[u8; 32],
    direction: DirectionV2,
    header: UnreliableHeaderV2,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolV2Error> {
    if ciphertext.len() != header.ciphertext_length as usize {
        return Err(ProtocolV2Error::InvalidUnreliableMessage);
    }
    let raw_header = header.encode()?;
    let aad = label_with(
        b"flowersec-v2-unreliable",
        &[h3, &[direction as u8], &raw_header],
    );
    let nonce = record_nonce(material.nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV2::ChaCha20Poly1305 => open_chacha(&material.key, nonce, &aad, ciphertext),
        CipherSuiteV2::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(&material.key).map_err(|_| ProtocolV2Error::Crypto)?;
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV2Error::Authentication)
        }
    }
}

pub fn derive_next_epoch_v2(
    rekey_root: &[u8; 32],
    h3: &[u8; 32],
    direction: DirectionV2,
    next_epoch: u32,
) -> Result<EpochRootsV2, ProtocolV2Error> {
    let epoch = next_epoch.to_be_bytes();
    let secret = expand_32(
        rekey_root,
        &label_with(
            b"flowersec v2 next epoch",
            &[h3, &[direction as u8], &epoch],
        ),
    )?;
    Ok(EpochRootsV2 {
        epoch_secret: secret,
        control_root: expand_32(&secret, &label_with(b"flowersec v2 control root", &[]))?,
        stream_root: expand_32(&secret, &label_with(b"flowersec v2 stream root", &[]))?,
        setup_root: expand_32(&secret, &label_with(b"flowersec v2 setup root", &[]))?,
        rekey_root: expand_32(&secret, &label_with(b"flowersec v2 rekey root", &[]))?,
    })
}

/// Computes the setup MAC over the fixed preface fields and handshake hash.
pub fn compute_setup_mac_v2(
    setup_root: &[u8; 32],
    h3: &[u8; 32],
    preface: &SetupPrefaceV2,
) -> Result<[u8; 32], ProtocolV2Error> {
    let raw = preface.encode()?;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(setup_root).map_err(|_| ProtocolV2Error::Crypto)?;
    mac.update(&label_with(b"flowersec-v2-setup", &[]));
    mac.update(h3);
    mac.update(&raw[..24]);
    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_setup_mac_v2(setup_root: &[u8; 32], h3: &[u8; 32], preface: &SetupPrefaceV2) -> bool {
    use subtle::ConstantTimeEq;
    compute_setup_mac_v2(setup_root, h3, preface)
        .map(|expected| expected.ct_eq(preface.setup_mac()).into())
        .unwrap_or(false)
}

pub fn compute_fss2_hash_v2(raw: &[u8]) -> Result<[u8; 32], ProtocolV2Error> {
    SetupPrefaceV2::decode(raw)?;
    Ok(Sha256::digest(raw).into())
}

pub fn compute_open_hash_v2(raw: &[u8]) -> Result<[u8; 32], ProtocolV2Error> {
    decode_open_payload_v2(raw)?;
    let mut hash = Sha256::new();
    hash.update(b"flowersec-v2-open\0");
    hash.update((raw.len() as u32).to_be_bytes());
    hash.update(raw);
    Ok(hash.finalize().into())
}

/// Encodes one bounded inner record.
pub fn encode_inner_record_v2(
    record_type: InnerRecordTypeV2,
    payload: &[u8],
) -> Result<Vec<u8>, ProtocolV2Error> {
    validate_inner_payload(record_type, payload.len())?;
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| ProtocolV2Error::InvalidInnerRecord)?;
    let mut output = Vec::with_capacity(INNER_HEADER_V2_SIZE + payload.len());
    output.push(record_type as u8);
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&payload_length.to_be_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_inner_record_v2(raw: &[u8]) -> Result<(InnerRecordTypeV2, &[u8]), ProtocolV2Error> {
    if raw.len() < INNER_HEADER_V2_SIZE || raw[1..4] != [0; 3] {
        return Err(ProtocolV2Error::InvalidInnerRecord);
    }
    let payload_length = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
    if INNER_HEADER_V2_SIZE.checked_add(payload_length) != Some(raw.len()) {
        return Err(ProtocolV2Error::InvalidInnerRecord);
    }
    let record_type = InnerRecordTypeV2::try_from(raw[0])?;
    validate_inner_payload(record_type, payload_length)?;
    Ok((record_type, &raw[INNER_HEADER_V2_SIZE..]))
}

fn validate_inner_payload(
    record_type: InnerRecordTypeV2,
    payload_length: usize,
) -> Result<(), ProtocolV2Error> {
    let valid = match record_type {
        InnerRecordTypeV2::Open => (1..=MAX_OPEN_V2_BYTES).contains(&payload_length),
        InnerRecordTypeV2::Data => (1..=MAX_DATA_V2_BYTES).contains(&payload_length),
        InnerRecordTypeV2::Fin
        | InnerRecordTypeV2::SessionReady
        | InnerRecordTypeV2::SessionReadyAck => payload_length == 0,
        InnerRecordTypeV2::OpenAck => payload_length == 32,
        InnerRecordTypeV2::OpenReject => payload_length == 34,
        InnerRecordTypeV2::StreamKeyUpdate => payload_length == 12,
        InnerRecordTypeV2::Ping | InnerRecordTypeV2::Pong => payload_length == 8,
        InnerRecordTypeV2::SessionKeyUpdate
        | InnerRecordTypeV2::SessionKeyUpdateAck
        | InnerRecordTypeV2::StreamKeyUpdateAck => payload_length == 20,
        InnerRecordTypeV2::StreamReset | InnerRecordTypeV2::GoAway => payload_length == 10,
        InnerRecordTypeV2::SessionClose => payload_length == 2,
    };
    valid
        .then_some(())
        .ok_or(ProtocolV2Error::InvalidInnerRecord)
}

/// Encodes one canonical OPEN payload.
pub fn encode_open_payload_v2(payload: &OpenPayloadV2) -> Result<Vec<u8>, ProtocolV2Error> {
    if payload.logical_stream_id == 0 || !valid_open_kind(&payload.kind) {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    let metadata = canonical_open_metadata(&payload.metadata, true)?;
    let total = OPEN_FIXED_PAYLOAD_V2_BYTES
        .checked_add(payload.kind.len())
        .and_then(|value| value.checked_add(metadata.len()))
        .filter(|value| *value <= MAX_OPEN_V2_BYTES)
        .ok_or(ProtocolV2Error::InvalidOpenPayload)?;
    let kind_length =
        u16::try_from(payload.kind.len()).map_err(|_| ProtocolV2Error::InvalidOpenPayload)?;
    let metadata_length =
        u32::try_from(metadata.len()).map_err(|_| ProtocolV2Error::InvalidOpenPayload)?;
    let mut output = vec![0_u8; total];
    output[..8].copy_from_slice(&payload.logical_stream_id.to_be_bytes());
    output[8..40].copy_from_slice(&payload.fss2_hash);
    output[40..42].copy_from_slice(&kind_length.to_be_bytes());
    output[42..46].copy_from_slice(&metadata_length.to_be_bytes());
    output[46..46 + payload.kind.len()].copy_from_slice(payload.kind.as_bytes());
    output[46 + payload.kind.len()..].copy_from_slice(&metadata);
    Ok(output)
}

/// Decodes and validates one canonical OPEN payload.
pub fn decode_open_payload_v2(raw: &[u8]) -> Result<OpenPayloadV2, ProtocolV2Error> {
    if raw.len() < OPEN_FIXED_PAYLOAD_V2_BYTES || raw.len() > MAX_OPEN_V2_BYTES {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    let logical_stream_id = u64::from_be_bytes(
        raw[..8]
            .try_into()
            .map_err(|_| ProtocolV2Error::InvalidOpenPayload)?,
    );
    if logical_stream_id == 0 {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    let kind_length = usize::from(u16::from_be_bytes([raw[40], raw[41]]));
    let metadata_length = u32::from_be_bytes(raw[42..46].try_into().unwrap()) as usize;
    if OPEN_FIXED_PAYLOAD_V2_BYTES
        .checked_add(kind_length)
        .and_then(|value| value.checked_add(metadata_length))
        != Some(raw.len())
    {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    let kind_end = 46 + kind_length;
    let kind = std::str::from_utf8(&raw[46..kind_end])
        .map_err(|_| ProtocolV2Error::InvalidOpenPayload)?
        .to_owned();
    if !valid_open_kind(&kind) {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    let metadata = canonical_open_metadata(&raw[kind_end..], false)?;
    let mut fss2_hash = [0_u8; 32];
    fss2_hash.copy_from_slice(&raw[8..40]);
    Ok(OpenPayloadV2::new(
        logical_stream_id,
        fss2_hash,
        kind,
        metadata,
    ))
}

/// Builds the AAD binding a record to its handshake, stream, and direction.
pub fn record_aad_v2(
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV2,
    header: &RecordHeaderV2,
) -> Result<Vec<u8>, ProtocolV2Error> {
    let stream_id = logical_stream_id.to_be_bytes();
    let raw_header = header.encode()?;
    Ok(label_with(
        b"flowersec-v2-record",
        &[h3, &stream_id, &[direction as u8], &raw_header],
    ))
}

#[allow(clippy::too_many_arguments)]
/// Seals one record. Callers must never reuse a key/sequence nonce pair.
pub fn seal_record_v2(
    suite: CipherSuiteV2,
    key: &[u8; 32],
    nonce_prefix: &[u8; 4],
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV2,
    header: &RecordHeaderV2,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolV2Error> {
    if plaintext
        .len()
        .checked_add(AEAD_TAG_V2_SIZE)
        .and_then(|length| u32::try_from(length).ok())
        != Some(header.ciphertext_length)
    {
        return Err(ProtocolV2Error::InvalidRecordHeader);
    }
    let aad = record_aad_v2(h3, logical_stream_id, direction, header)?;
    let nonce = record_nonce(*nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV2::ChaCha20Poly1305 => seal_chacha(key, nonce, &aad, plaintext),
        CipherSuiteV2::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtocolV2Error::Crypto)?;
            cipher
                .encrypt(
                    (&nonce).into(),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV2Error::Crypto)
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// Authenticates and opens one record under its complete record context.
pub fn open_record_v2(
    suite: CipherSuiteV2,
    key: &[u8; 32],
    nonce_prefix: &[u8; 4],
    h3: &[u8; 32],
    logical_stream_id: u64,
    direction: DirectionV2,
    header: &RecordHeaderV2,
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolV2Error> {
    if ciphertext.len() != header.ciphertext_length as usize {
        return Err(ProtocolV2Error::InvalidRecordHeader);
    }
    let aad = record_aad_v2(h3, logical_stream_id, direction, header)?;
    let nonce = record_nonce(*nonce_prefix, header.sequence);
    match suite {
        CipherSuiteV2::ChaCha20Poly1305 => open_chacha(key, nonce, &aad, ciphertext),
        CipherSuiteV2::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| ProtocolV2Error::Crypto)?;
            cipher
                .decrypt(
                    (&nonce).into(),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| ProtocolV2Error::Authentication)
        }
    }
}

fn seal_chacha(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolV2Error> {
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| ProtocolV2Error::Crypto)?,
    );
    let mut output = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut output,
    )
    .map_err(|_| ProtocolV2Error::Crypto)?;
    Ok(output)
}

fn open_chacha(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, ProtocolV2Error> {
    let key = LessSafeKey::new(
        UnboundKey::new(&CHACHA20_POLY1305, key).map_err(|_| ProtocolV2Error::Crypto)?,
    );
    let mut output = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut output,
        )
        .map_err(|_| ProtocolV2Error::Authentication)?;
    Ok(plaintext.to_vec())
}

fn record_nonce(prefix: [u8; 4], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn valid_logical_stream_id(role: StreamOpenerRoleV2, logical_stream_id: u64) -> bool {
    match role {
        StreamOpenerRoleV2::Client => logical_stream_id != 0 && logical_stream_id & 1 == 1,
        StreamOpenerRoleV2::Server => logical_stream_id != 0 && logical_stream_id & 1 == 0,
    }
}

fn expand_32(prk: &[u8; 32], info: &[u8]) -> Result<[u8; 32], ProtocolV2Error> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| ProtocolV2Error::Hkdf)?;
    let mut output = [0_u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| ProtocolV2Error::Hkdf)?;
    Ok(output)
}

fn expand_4(prk: &[u8; 32], info: &[u8]) -> Result<[u8; 4], ProtocolV2Error> {
    let hkdf = Hkdf::<Sha256>::from_prk(prk).map_err(|_| ProtocolV2Error::Hkdf)?;
    let mut output = [0_u8; 4];
    hkdf.expand(info, &mut output)
        .map_err(|_| ProtocolV2Error::Hkdf)?;
    Ok(output)
}

fn label_with(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let capacity = label.len() + 1 + parts.iter().map(|part| part.len()).sum::<usize>();
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(label);
    output.push(0);
    for part in parts {
        output.extend_from_slice(part);
    }
    output
}

fn valid_open_kind(value: &str) -> bool {
    if !valid_open_unicode_string(value, MAX_OPEN_KIND_V2_BYTES, false) {
        return false;
    }
    let Some(first) = value.chars().next() else {
        return false;
    };
    let Some(last) = value.chars().next_back() else {
        return false;
    };
    !first.is_whitespace() && !last.is_whitespace()
}

fn canonical_open_metadata(raw: &[u8], allow_empty: bool) -> Result<Vec<u8>, ProtocolV2Error> {
    if raw.is_empty() && allow_empty {
        return Ok(b"{}".to_vec());
    }
    if raw.is_empty() || raw.len() > MAX_OPEN_METADATA_V2_BYTES {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    let value: Value =
        serde_json::from_slice(raw).map_err(|_| ProtocolV2Error::InvalidOpenPayload)?;
    if !value.is_object() {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    let mut nodes = -1_i32;
    validate_metadata_value(&value, 1, &mut nodes)?;
    let mut canonical = Vec::with_capacity(raw.len());
    append_canonical_json(&mut canonical, &value)?;
    if canonical.len() > MAX_OPEN_METADATA_V2_BYTES || canonical != raw {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    Ok(canonical)
}

fn validate_metadata_value(
    value: &Value,
    depth: usize,
    nodes: &mut i32,
) -> Result<(), ProtocolV2Error> {
    if depth > MAX_OPEN_METADATA_DEPTH {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    *nodes += 1;
    if *nodes > MAX_OPEN_METADATA_NODES as i32 {
        return Err(ProtocolV2Error::InvalidOpenPayload);
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::Number(number) => match number.as_i64() {
            Some(value) if (-MAX_IJSON_SAFE_INTEGER..=MAX_IJSON_SAFE_INTEGER).contains(&value) => {
                Ok(())
            }
            _ => Err(ProtocolV2Error::InvalidOpenPayload),
        },
        Value::String(value) => {
            if valid_open_unicode_string(value, MAX_OPEN_METADATA_STRING_BYTES, true) {
                Ok(())
            } else {
                Err(ProtocolV2Error::InvalidOpenPayload)
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_OPEN_METADATA_ARRAY {
                return Err(ProtocolV2Error::InvalidOpenPayload);
            }
            for value in values {
                validate_metadata_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > MAX_OPEN_METADATA_KEYS {
                return Err(ProtocolV2Error::InvalidOpenPayload);
            }
            for (key, value) in values {
                if !valid_open_unicode_string(key, MAX_OPEN_METADATA_KEY_BYTES, false) {
                    return Err(ProtocolV2Error::InvalidOpenPayload);
                }
                validate_metadata_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
    }
}

fn append_canonical_json(output: &mut Vec<u8>, value: &Value) -> Result<(), ProtocolV2Error> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => append_canonical_json_string(output, value),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                append_canonical_json(output, value)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
            keys.sort_by(|left, right| compare_utf16(left, right));
            output.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                append_canonical_json_string(output, key);
                output.push(b':');
                append_canonical_json(output, &values[key])?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn append_canonical_json_string(output: &mut Vec<u8>, value: &str) {
    output.push(b'"');
    for byte in value.as_bytes() {
        if matches!(*byte, b'"' | b'\\') {
            output.push(b'\\');
        }
        output.push(*byte);
    }
    output.push(b'"');
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn valid_open_unicode_string(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    if value.len() > max_bytes
        || (!allow_empty && value.is_empty())
        || !value.nfc().eq(value.chars())
    {
        return false;
    }
    value.chars().all(|scalar| {
        !matches!(scalar as u32, 0x00..=0x1f | 0x7f..=0x9f) && unicode15_1_assigned(scalar as u32)
    })
}

fn unicode15_1_assigned(code_point: u32) -> bool {
    UNICODE_15_1_ASSIGNED_RANGES_HEX
        .as_bytes()
        .chunks_exact(12)
        .any(|range| {
            let start = parse_hex_u32(&range[..6]);
            let end = parse_hex_u32(&range[6..]);
            code_point >= start && code_point <= end
        })
}

fn parse_hex_u32(value: &[u8]) -> u32 {
    value.iter().fold(0_u32, |result, byte| {
        (result << 4)
            | match byte {
                b'0'..=b'9' => u32::from(byte - b'0'),
                b'A'..=b'F' => u32::from(byte - b'A' + 10),
                _ => 0,
            }
    })
}

#[cfg(test)]
mod unreliable_message_tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn fsd2_header_and_domain_separated_aead_are_strict() {
        let session_prk = [0x31; 32];
        let h3 = [0x42; 32];
        let roots = derive_epoch_zero_v2(&session_prk, DirectionV2::ClientToServer).unwrap();
        let material =
            derive_unreliable_material_v2(&roots, &h3, DirectionV2::ClientToServer, 0).unwrap();
        let header = UnreliableHeaderV2 {
            epoch: 0,
            sequence: 7,
            expires_at_unix_ms: 2_000_000_000_000,
            ciphertext_length: (4 + AEAD_TAG_V2_SIZE) as u32,
        };
        let raw = header.encode().unwrap();
        assert_eq!(&raw[..4], b"FSD2");
        assert_eq!(raw[4], 2);
        assert_eq!(u16::from_be_bytes(raw[6..8].try_into().unwrap()), 32);
        assert_eq!(UnreliableHeaderV2::decode(&raw).unwrap(), header);

        let ciphertext = seal_unreliable_v2(
            CipherSuiteV2::ChaCha20Poly1305,
            &material,
            &h3,
            DirectionV2::ClientToServer,
            header,
            b"data",
        )
        .unwrap();
        assert_ne!(ciphertext, b"data");
        assert_eq!(
            open_unreliable_v2(
                CipherSuiteV2::ChaCha20Poly1305,
                &material,
                &h3,
                DirectionV2::ClientToServer,
                header,
                &ciphertext,
            )
            .unwrap(),
            b"data"
        );

        let peer_roots = derive_epoch_zero_v2(&session_prk, DirectionV2::ServerToClient).unwrap();
        let peer_material =
            derive_unreliable_material_v2(&peer_roots, &h3, DirectionV2::ServerToClient, 0)
                .unwrap();
        assert!(
            open_unreliable_v2(
                CipherSuiteV2::ChaCha20Poly1305,
                &peer_material,
                &h3,
                DirectionV2::ServerToClient,
                header,
                &ciphertext,
            )
            .is_err(),
            "unreliable keys must be direction-separated"
        );
        let mut altered_h3 = h3;
        altered_h3[0] ^= 1;
        assert!(
            open_unreliable_v2(
                CipherSuiteV2::ChaCha20Poly1305,
                &material,
                &altered_h3,
                DirectionV2::ClientToServer,
                header,
                &ciphertext,
            )
            .is_err(),
            "unreliable AAD must bind the FSH2 transcript"
        );
    }

    #[test]
    fn fsd2_rejects_empty_oversize_and_mutated_header_context() {
        let roots = derive_epoch_zero_v2(&[0x51; 32], DirectionV2::ClientToServer).unwrap();
        let material =
            derive_unreliable_material_v2(&roots, &[0x61; 32], DirectionV2::ClientToServer, 0)
                .unwrap();
        let header = UnreliableHeaderV2 {
            epoch: 0,
            sequence: 1,
            expires_at_unix_ms: 2_000_000_000_000,
            ciphertext_length: (1 + AEAD_TAG_V2_SIZE) as u32,
        };
        assert!(
            seal_unreliable_v2(
                CipherSuiteV2::Aes256Gcm,
                &material,
                &[0x61; 32],
                DirectionV2::ClientToServer,
                header,
                b"",
            )
            .is_err()
        );
        let mut invalid = header.encode().unwrap();
        invalid[5] = 1;
        assert!(UnreliableHeaderV2::decode(&invalid).is_err());
        let oversized = UnreliableHeaderV2 {
            ciphertext_length: (MAX_UNRELIABLE_PLAINTEXT_V2_BYTES + AEAD_TAG_V2_SIZE + 1) as u32,
            ..header
        };
        assert!(oversized.encode().is_err());
    }

    #[test]
    fn consumes_shared_fsd2_datagram_vectors() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../testdata/transport_v2/datagram_vectors.json"
        ))
        .unwrap();
        assert_eq!(fixture["schema_version"], 1);
        let vectors = fixture["vectors"].as_array().unwrap();
        assert!(!vectors.is_empty());
        for vector in vectors {
            let decode = |name: &str| {
                URL_SAFE_NO_PAD
                    .decode(vector[name].as_str().unwrap())
                    .unwrap()
            };
            let session_prk: [u8; 32] = decode("session_prk_b64u").try_into().unwrap();
            let h3: [u8; 32] = decode("h3_b64u").try_into().unwrap();
            let direction =
                DirectionV2::try_from(vector["direction"].as_u64().unwrap() as u8).unwrap();
            let epoch = vector["epoch"].as_u64().unwrap() as u32;
            let sequence = vector["sequence"].as_u64().unwrap();
            let plaintext = decode("plaintext_b64u");
            let suite = match vector["suite"].as_u64().unwrap() {
                1 => CipherSuiteV2::ChaCha20Poly1305,
                2 => CipherSuiteV2::Aes256Gcm,
                _ => panic!("unknown shared DATAGRAM suite"),
            };

            let mut roots = derive_epoch_zero_v2(&session_prk, direction).unwrap();
            for next_epoch in 1..=epoch {
                roots =
                    derive_next_epoch_v2(roots.rekey_root(), &h3, direction, next_epoch).unwrap();
            }
            assert_eq!(
                roots.epoch_secret().as_slice(),
                decode("epoch_secret_b64u").as_slice()
            );
            let root = expand_32(
                roots.epoch_secret(),
                &label_with(b"flowersec v2 unreliable root", &[]),
            )
            .unwrap();
            assert_eq!(root.as_slice(), decode("unreliable_root_b64u").as_slice());
            let secret = expand_32(
                &root,
                &label_with(
                    b"flowersec v2 unreliable",
                    &[&h3, &[direction as u8], &epoch.to_be_bytes()],
                ),
            )
            .unwrap();
            assert_eq!(secret.as_slice(), decode("material_secret_b64u").as_slice());
            let material = derive_unreliable_material_v2(&roots, &h3, direction, epoch).unwrap();
            assert_eq!(
                material.key.as_slice(),
                decode("record_key_b64u").as_slice()
            );
            assert_eq!(
                material.nonce_prefix.as_slice(),
                decode("nonce_prefix_b64u").as_slice()
            );
            assert_eq!(
                record_nonce(material.nonce_prefix, sequence),
                decode("nonce_b64u").as_slice()
            );
            let header = UnreliableHeaderV2 {
                epoch,
                sequence,
                expires_at_unix_ms: vector["expires_at_unix_ms"].as_u64().unwrap(),
                ciphertext_length: (plaintext.len() + AEAD_TAG_V2_SIZE) as u32,
            };
            let raw_header = header.encode().unwrap();
            assert_eq!(hex_lower(&raw_header), vector["header_hex"]);
            let aad = label_with(
                b"flowersec-v2-unreliable",
                &[&h3, &[direction as u8], &raw_header],
            );
            assert_eq!(aad, decode("aad_b64u"));
            let ciphertext =
                seal_unreliable_v2(suite, &material, &h3, direction, header, &plaintext).unwrap();
            assert_eq!(ciphertext, decode("ciphertext_b64u"));
            let mut wire = raw_header.to_vec();
            wire.extend_from_slice(&ciphertext);
            assert_eq!(wire, decode("wire_b64u"));
        }
    }

    fn hex_lower(raw: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut output = String::with_capacity(raw.len() * 2);
        for byte in raw {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
