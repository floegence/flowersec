import { gcm } from "@noble/ciphers/aes";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { expand } from "@noble/hashes/hkdf";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";

const encoder = new TextEncoder();
const MAX_UINT32 = 0xffffffff;
const MAX_UINT64 = (1n << 64n) - 1n;
const SETUP_PREFACE_BYTES = 56;
const RECORD_HEADER_BYTES = 24;
const INNER_HEADER_BYTES = 8;
const MAX_DATA_BYTES = 16_384;
const MAX_CIPHERTEXT_BYTES = INNER_HEADER_BYTES + MAX_DATA_BYTES + 16;
const OPEN_FIXED_PAYLOAD_BYTES = 46;
const MAX_OPEN_BYTES = 8_192;
const MAX_OPEN_KIND_BYTES = 128;
const MAX_OPEN_METADATA_BYTES = 4_096;
const MAX_OPEN_METADATA_DEPTH = 4;
const MAX_OPEN_METADATA_NODES = 64;
const MAX_OPEN_METADATA_KEYS = 64;
const MAX_OPEN_METADATA_ARRAY = 32;
const MAX_OPEN_METADATA_KEY_BYTES = 64;
const MAX_OPEN_METADATA_STRING_BYTES = 512;
const UNICODE_15_1_ASSIGNED_RANGES_HEX = [
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
].join("");
const UNICODE_15_1_ASSIGNED_RANGES = decodeUnicodeRanges(
  UNICODE_15_1_ASSIGNED_RANGES_HEX,
);
const strictDecoder = new TextDecoder("utf-8", { fatal: true });

export class ProtocolV2Error extends Error {}

export enum DirectionV2 {
  ClientToServer = 1,
  ServerToClient = 2,
}

export enum CipherSuiteV2 {
  ChaCha20Poly1305 = 1,
  AES256GCM = 2,
}

export type EpochRootsV2 = Readonly<{
  epochSecret: Uint8Array;
  controlRoot: Uint8Array;
  streamRoot: Uint8Array;
  setupRoot: Uint8Array;
  rekeyRoot: Uint8Array;
}>;

export type RecordMaterialV2 = Readonly<{
  secret: Uint8Array;
  recordKey: Uint8Array;
  noncePrefix: Uint8Array;
}>;

export type SetupPrefaceV2 = Readonly<{
  openerRole: 1 | 2;
  logicalStreamID: bigint;
  initialSendEpoch: number;
  setupMAC: Uint8Array;
}>;

export type RecordHeaderV2 = Readonly<{
  epoch: number;
  sequence: bigint;
  ciphertextLength: number;
}>;

export type OpenPayloadV2 = Readonly<{
  logicalStreamID: bigint;
  fss2Hash: Uint8Array;
  kind: string;
  metadata: Uint8Array;
}>;

export enum InnerTypeV2 {
  Open = 1,
  OpenACK = 2,
  OpenReject = 3,
  Data = 4,
  FIN = 5,
  StreamKeyUpdate = 6,
  SessionReady = 16,
  Ping = 17,
  Pong = 18,
  SessionKeyUpdate = 19,
  StreamReset = 20,
  GoAway = 21,
  SessionClose = 22,
  SessionReadyACK = 23,
  SessionKeyUpdateACK = 24,
  StreamKeyUpdateACK = 25,
}

export type InnerRecordV2 = Readonly<{
  type: InnerTypeV2;
  payload: Uint8Array;
}>;

export type OpenRejectV2 = Readonly<{
  openHash: Uint8Array;
  reason: number;
  knownReason: boolean;
}>;

export type StreamKeyUpdateACKV2 = Readonly<{
  logicalStreamID: bigint;
  transition: bigint;
  epoch: number;
}>;

export function deriveEpochZero(
  sessionPRK: Uint8Array,
  direction: DirectionV2,
): EpochRootsV2 {
  assertBytes("session PRK", sessionPRK, 32);
  assertDirection(direction);
  const epochSecret = expand32(
    sessionPRK,
    labelWith("flowersec v2 epoch zero", byte(direction)),
  );
  return deriveEpochRoots(epochSecret);
}

export function deriveEpochRoots(epochSecret: Uint8Array): EpochRootsV2 {
  assertBytes("epoch secret", epochSecret, 32);
  return {
    epochSecret: epochSecret.slice(),
    controlRoot: expand32(epochSecret, labelWith("flowersec v2 control root")),
    streamRoot: expand32(epochSecret, labelWith("flowersec v2 stream root")),
    setupRoot: expand32(epochSecret, labelWith("flowersec v2 setup root")),
    rekeyRoot: expand32(epochSecret, labelWith("flowersec v2 rekey root")),
  };
}

export function deriveNextEpoch(
  rekeyRoot: Uint8Array,
  h3: Uint8Array,
  direction: DirectionV2,
  nextEpoch: number,
): Uint8Array {
  assertBytes("rekey root", rekeyRoot, 32);
  assertBytes("H3", h3, 32);
  assertDirection(direction);
  assertU32("next epoch", nextEpoch);
  return expand32(
    rekeyRoot,
    labelWith("flowersec v2 next epoch", h3, byte(direction), u32be(nextEpoch)),
  );
}

export function deriveStreamMaterial(
  streamRoot: Uint8Array,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV2,
  epoch: number,
): RecordMaterialV2 {
  assertBytes("stream root", streamRoot, 32);
  assertBytes("H3", h3, 32);
  assertLogicalStreamID(logicalStreamID);
  assertDirection(direction);
  assertU32("epoch", epoch);
  const secret = expand32(
    streamRoot,
    labelWith(
      "flowersec v2 stream",
      h3,
      u64be(logicalStreamID),
      byte(direction),
      u32be(epoch),
    ),
  );
  return {
    secret,
    recordKey: expand32(secret, labelWith("flowersec v2 record key")),
    noncePrefix: expand(sha256, secret, labelWith("flowersec v2 nonce"), 4),
  };
}

export function deriveControlMaterial(
  controlRoot: Uint8Array,
  h3: Uint8Array,
  direction: DirectionV2,
  epoch: number,
): RecordMaterialV2 {
  assertBytes("control root", controlRoot, 32);
  assertBytes("H3", h3, 32);
  assertDirection(direction);
  assertU32("epoch", epoch);
  const secret = expand32(
    controlRoot,
    labelWith(
      "flowersec v2 control",
      h3,
      u64be(0n),
      byte(direction),
      u32be(epoch),
    ),
  );
  return {
    secret,
    recordKey: expand32(secret, labelWith("flowersec v2 record key")),
    noncePrefix: expand(sha256, secret, labelWith("flowersec v2 nonce"), 4),
  };
}

export function computeSetupMAC(
  setupRoot: Uint8Array,
  h3: Uint8Array,
  preface: SetupPrefaceV2,
): Uint8Array {
  assertBytes("setup root", setupRoot, 32);
  assertBytes("H3", h3, 32);
  const raw = encodeSetupPreface(preface);
  return hmac(
    sha256,
    setupRoot,
    labelWith("flowersec-v2-setup", h3, raw.subarray(0, 24)),
  );
}

export function encodeSetupPreface(preface: SetupPrefaceV2): Uint8Array {
  assertLogicalStreamID(preface.logicalStreamID);
  if (
    (preface.openerRole !== 1 && preface.openerRole !== 2) ||
    (preface.openerRole === 1 && (preface.logicalStreamID & 1n) !== 1n) ||
    (preface.openerRole === 2 && (preface.logicalStreamID & 1n) !== 0n)
  ) {
    throw new ProtocolV2Error("invalid FSS2 opener or logical stream ID");
  }
  assertU32("initial send epoch", preface.initialSendEpoch);
  assertBytes("setup MAC", preface.setupMAC, 32);
  const out = new Uint8Array(SETUP_PREFACE_BYTES);
  out.set(encoder.encode("FSS2"), 0);
  out[4] = 2;
  out[5] = preface.openerRole;
  out.set(u64be(preface.logicalStreamID), 8);
  out.set(u32be(preface.initialSendEpoch), 16);
  out.set(preface.setupMAC, 24);
  return out;
}

export function decodeSetupPrefaceV2(raw: Uint8Array): SetupPrefaceV2 {
  if (
    raw.length !== SETUP_PREFACE_BYTES ||
    raw[0] !== 0x46 || raw[1] !== 0x53 || raw[2] !== 0x53 || raw[3] !== 0x32 ||
    raw[4] !== 2 || raw[6] !== 0 || raw[7] !== 0 || readU32be(raw, 20) !== 0
  ) {
    throw new ProtocolV2Error("invalid FSS2 setup preface");
  }
  const openerRole = raw[5];
  const logicalStreamID = readU64be(raw, 8);
  if (
    (openerRole !== 1 && openerRole !== 2) ||
    logicalStreamID === 0n ||
    (openerRole === 1 && (logicalStreamID & 1n) !== 1n) ||
    (openerRole === 2 && (logicalStreamID & 1n) !== 0n)
  ) {
    throw new ProtocolV2Error("invalid FSS2 opener or logical stream ID");
  }
  return {
    openerRole,
    logicalStreamID,
    initialSendEpoch: readU32be(raw, 16),
    setupMAC: raw.slice(24, 56),
  };
}

export function verifySetupMAC(
  setupRoot: Uint8Array,
  h3: Uint8Array,
  preface: SetupPrefaceV2,
): boolean {
  const want = computeSetupMAC(setupRoot, h3, { ...preface, setupMAC: new Uint8Array(32) });
  return bytesEqual(want, preface.setupMAC);
}

export function computeFSS2HashV2(raw: Uint8Array): Uint8Array {
  decodeSetupPrefaceV2(raw);
  return sha256(raw);
}

export function encodeRecordHeader(header: RecordHeaderV2): Uint8Array {
  validateRecordHeader(header);
  const out = new Uint8Array(RECORD_HEADER_BYTES);
  out.set(encoder.encode("FSR2"), 0);
  out[4] = 2;
  out[5] = RECORD_HEADER_BYTES;
  out.set(u32be(header.epoch), 8);
  out.set(u64be(header.sequence), 12);
  out.set(u32be(header.ciphertextLength), 20);
  return out;
}

export function decodeRecordHeader(raw: Uint8Array): RecordHeaderV2 {
  if (
    raw.length !== RECORD_HEADER_BYTES ||
    raw[0] !== 0x46 ||
    raw[1] !== 0x53 ||
    raw[2] !== 0x52 ||
    raw[3] !== 0x32 ||
    raw[4] !== 2 ||
    raw[5] !== RECORD_HEADER_BYTES ||
    raw[6] !== 0 ||
    raw[7] !== 0
  ) {
    throw new ProtocolV2Error("invalid FSR2 header");
  }
  const header = {
    epoch: readU32be(raw, 8),
    sequence: readU64be(raw, 12),
    ciphertextLength: readU32be(raw, 20),
  };
  validateRecordHeader(header);
  return header;
}

export function buildDataInner(payload: Uint8Array): Uint8Array {
  if (payload.length < 1 || payload.length > MAX_DATA_BYTES) {
    throw new ProtocolV2Error("invalid v2 DATA payload length");
  }
  const out = new Uint8Array(INNER_HEADER_BYTES + payload.length);
  out[0] = 4;
  out.set(u32be(payload.length), 4);
  out.set(payload, INNER_HEADER_BYTES);
  return out;
}

export function encodeInnerRecordV2(type: InnerTypeV2, payload: Uint8Array): Uint8Array {
  validateInnerPayload(type, payload.length);
  const out = new Uint8Array(INNER_HEADER_BYTES + payload.length);
  out[0] = type;
  out.set(u32be(payload.length), 4);
  out.set(payload, INNER_HEADER_BYTES);
  return out;
}

export function decodeInnerRecordV2(raw: Uint8Array): InnerRecordV2 {
  if (raw.length < INNER_HEADER_BYTES || raw[1] !== 0 || raw[2] !== 0 || raw[3] !== 0) {
    throw new ProtocolV2Error("invalid FSR2 inner record");
  }
  const length = readU32be(raw, 4);
  if (raw.length !== INNER_HEADER_BYTES + length) {
    throw new ProtocolV2Error("invalid FSR2 inner record length");
  }
  const type = raw[0]! as InnerTypeV2;
  validateInnerPayload(type, length);
  return { type, payload: raw.slice(INNER_HEADER_BYTES) };
}

export function encodeOpenPayload(payload: OpenPayloadV2): Uint8Array {
  assertLogicalStreamID(payload.logicalStreamID);
  assertBytes("FSS2 hash", payload.fss2Hash, 32);
  const kind = validateOpenKind(payload.kind);
  const metadata = canonicalMetadata(payload.metadata, true);
  const total = OPEN_FIXED_PAYLOAD_BYTES + kind.length + metadata.length;
  if (total > MAX_OPEN_BYTES)
    throw new ProtocolV2Error("OPEN payload is too large");
  const out = new Uint8Array(total);
  out.set(u64be(payload.logicalStreamID), 0);
  out.set(payload.fss2Hash, 8);
  new DataView(out.buffer).setUint16(40, kind.length, false);
  new DataView(out.buffer).setUint32(42, metadata.length, false);
  out.set(kind, OPEN_FIXED_PAYLOAD_BYTES);
  out.set(metadata, OPEN_FIXED_PAYLOAD_BYTES + kind.length);
  return out;
}

export function decodeOpenPayload(raw: Uint8Array): OpenPayloadV2 {
  if (raw.length < OPEN_FIXED_PAYLOAD_BYTES || raw.length > MAX_OPEN_BYTES) {
    throw new ProtocolV2Error("invalid OPEN payload length");
  }
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const logicalStreamID = view.getBigUint64(0, false);
  assertLogicalStreamID(logicalStreamID);
  const kindLength = view.getUint16(40, false);
  const metadataLength = view.getUint32(42, false);
  if (OPEN_FIXED_PAYLOAD_BYTES + kindLength + metadataLength !== raw.length) {
    throw new ProtocolV2Error("invalid OPEN field lengths");
  }
  let kind: string;
  try {
    kind = strictDecoder.decode(
      raw.subarray(
        OPEN_FIXED_PAYLOAD_BYTES,
        OPEN_FIXED_PAYLOAD_BYTES + kindLength,
      ),
    );
  } catch {
    throw new ProtocolV2Error("OPEN kind is not valid UTF-8");
  }
  validateOpenKind(kind);
  const metadata = canonicalMetadata(
    raw.subarray(OPEN_FIXED_PAYLOAD_BYTES + kindLength),
    false,
  );
  return {
    logicalStreamID,
    fss2Hash: raw.slice(8, 40),
    kind,
    metadata,
  };
}

export function computeOpenHashV2(rawOpenPayload: Uint8Array): Uint8Array {
  decodeOpenPayload(rawOpenPayload);
  return sha256(concat(encoder.encode("flowersec-v2-open\0"), u32be(rawOpenPayload.length), rawOpenPayload));
}

export function encodeOpenACKV2(openHash: Uint8Array): Uint8Array {
  assertBytes("OPEN hash", openHash, 32);
  return openHash.slice();
}

export function decodeOpenACKV2(raw: Uint8Array): Uint8Array {
  assertBytes("OPEN ACK", raw, 32);
  return raw.slice();
}

export function encodeOpenRejectV2(openHash: Uint8Array, reason: number): Uint8Array {
  assertBytes("OPEN hash", openHash, 32);
  if (!Number.isInteger(reason) || reason < 1 || reason > 5) {
    throw new ProtocolV2Error("invalid OPEN reject reason");
  }
  const out = new Uint8Array(34);
  out.set(openHash);
  new DataView(out.buffer).setUint16(32, reason, false);
  return out;
}

export function decodeOpenRejectV2(raw: Uint8Array): OpenRejectV2 {
  if (raw.length !== 34) throw new ProtocolV2Error("invalid OPEN reject payload");
  const reason = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint16(32, false);
  if (reason === 0) throw new ProtocolV2Error("invalid OPEN reject reason");
  return { openHash: raw.slice(0, 32), reason, knownReason: reason >= 1 && reason <= 5 };
}

export function encodeStreamKeyUpdateACKV2(value: StreamKeyUpdateACKV2): Uint8Array {
  assertLogicalStreamID(value.logicalStreamID);
  assertU64("stream rekey transition", value.transition);
  if (value.transition === 0n) throw new ProtocolV2Error("stream rekey transition must be non-zero");
  assertU32("stream rekey epoch", value.epoch);
  return concat(u64be(value.logicalStreamID), u64be(value.transition), u32be(value.epoch));
}

export function decodeStreamKeyUpdateACKV2(raw: Uint8Array): StreamKeyUpdateACKV2 {
  if (raw.length !== 20) throw new ProtocolV2Error("invalid STREAM_KEY_UPDATE_ACK payload");
  const value = {
    logicalStreamID: readU64be(raw, 0),
    transition: readU64be(raw, 8),
    epoch: readU32be(raw, 16),
  } as const;
  assertLogicalStreamID(value.logicalStreamID);
  if (value.transition === 0n) throw new ProtocolV2Error("stream rekey transition must be non-zero");
  return value;
}

export function buildRecordAAD(
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV2,
  rawHeader: Uint8Array,
): Uint8Array {
  assertBytes("H3", h3, 32);
  assertU64("logical stream ID", logicalStreamID);
  assertDirection(direction);
  decodeRecordHeader(rawHeader);
  return labelWith(
    "flowersec-v2-record",
    h3,
    u64be(logicalStreamID),
    byte(direction),
    rawHeader,
  );
}

export function sealRecord(
  suite: CipherSuiteV2,
  material: RecordMaterialV2,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV2,
  header: RecordHeaderV2,
  plaintext: Uint8Array,
): Uint8Array {
  validateMaterial(material);
  if (plaintext.length + 16 !== header.ciphertextLength) {
    throw new ProtocolV2Error(
      "FSR2 plaintext length does not match the header",
    );
  }
  const rawHeader = encodeRecordHeader(header);
  const nonce = concat(material.noncePrefix, u64be(header.sequence));
  const aad = buildRecordAAD(h3, logicalStreamID, direction, rawHeader);
  return cipher(suite, material.recordKey, nonce, aad).encrypt(plaintext);
}

export function openRecord(
  suite: CipherSuiteV2,
  material: RecordMaterialV2,
  h3: Uint8Array,
  logicalStreamID: bigint,
  direction: DirectionV2,
  header: RecordHeaderV2,
  ciphertext: Uint8Array,
): Uint8Array {
  validateMaterial(material);
  if (ciphertext.length !== header.ciphertextLength) {
    throw new ProtocolV2Error(
      "FSR2 ciphertext length does not match the header",
    );
  }
  const rawHeader = encodeRecordHeader(header);
  const nonce = concat(material.noncePrefix, u64be(header.sequence));
  const aad = buildRecordAAD(h3, logicalStreamID, direction, rawHeader);
  try {
    return cipher(suite, material.recordKey, nonce, aad).decrypt(ciphertext);
  } catch {
    throw new ProtocolV2Error("v2 record authentication failed");
  }
}

function cipher(
  suite: CipherSuiteV2,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
) {
  switch (suite) {
    case CipherSuiteV2.ChaCha20Poly1305:
      return chacha20poly1305(key, nonce, aad);
    case CipherSuiteV2.AES256GCM:
      return gcm(key, nonce, aad);
    default:
      throw new ProtocolV2Error("invalid v2 cipher suite");
  }
}

function validateMaterial(material: RecordMaterialV2): void {
  assertBytes("record key", material.recordKey, 32);
  assertBytes("nonce prefix", material.noncePrefix, 4);
}

function validateRecordHeader(header: RecordHeaderV2): void {
  assertU32("record epoch", header.epoch);
  assertU64("record sequence", header.sequence);
  if (
    !Number.isInteger(header.ciphertextLength) ||
    header.ciphertextLength < 16 ||
    header.ciphertextLength > MAX_CIPHERTEXT_BYTES
  ) {
    throw new ProtocolV2Error("invalid FSR2 ciphertext length");
  }
}

function validateInnerPayload(type: InnerTypeV2, length: number): void {
  switch (type) {
    case InnerTypeV2.Open:
      if (length >= 1 && length <= MAX_OPEN_BYTES) return;
      break;
    case InnerTypeV2.Data:
      if (length >= 1 && length <= MAX_DATA_BYTES) return;
      break;
    case InnerTypeV2.FIN:
    case InnerTypeV2.SessionReady:
    case InnerTypeV2.SessionReadyACK:
      if (length === 0) return;
      break;
    case InnerTypeV2.OpenACK:
      if (length === 32) return;
      break;
    case InnerTypeV2.OpenReject:
      if (length === 34) return;
      break;
    case InnerTypeV2.StreamKeyUpdate:
      if (length === 12) return;
      break;
    case InnerTypeV2.Ping:
    case InnerTypeV2.Pong:
      if (length === 8) return;
      break;
    case InnerTypeV2.SessionKeyUpdate:
    case InnerTypeV2.SessionKeyUpdateACK:
    case InnerTypeV2.StreamKeyUpdateACK:
      if (length === 20) return;
      break;
    case InnerTypeV2.StreamReset:
    case InnerTypeV2.GoAway:
      if (length === 10) return;
      break;
    case InnerTypeV2.SessionClose:
      if (length === 2) return;
      break;
    default:
      throw new ProtocolV2Error(`unknown FSR2 inner type ${type}`);
  }
  throw new ProtocolV2Error(`invalid FSR2 inner payload length for type ${type}`);
}

function expand32(prk: Uint8Array, info: Uint8Array): Uint8Array {
  return expand(sha256, prk, info, 32);
}

function labelWith(label: string, ...parts: Uint8Array[]): Uint8Array {
  return concat(encoder.encode(label), byte(0), ...parts);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function byte(value: number): Uint8Array {
  return Uint8Array.of(value);
}

function u32be(value: number): Uint8Array {
  assertU32("uint32", value);
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

function u64be(value: bigint): Uint8Array {
  assertU64("uint64", value);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, false);
  return out;
}

function readU32be(value: Uint8Array, offset: number): number {
  return new DataView(
    value.buffer,
    value.byteOffset,
    value.byteLength,
  ).getUint32(offset, false);
}

function readU64be(value: Uint8Array, offset: number): bigint {
  return new DataView(
    value.buffer,
    value.byteOffset,
    value.byteLength,
  ).getBigUint64(offset, false);
}

function assertDirection(direction: DirectionV2): void {
  if (
    direction !== DirectionV2.ClientToServer &&
    direction !== DirectionV2.ServerToClient
  ) {
    throw new ProtocolV2Error("invalid v2 direction");
  }
}

function assertLogicalStreamID(value: bigint): void {
  assertU64("logical stream ID", value);
  if (value === 0n)
    throw new ProtocolV2Error("logical stream ID must be non-zero");
}

function assertU32(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > MAX_UINT32) {
    throw new ProtocolV2Error(`${name} must be uint32`);
  }
}

function assertU64(name: string, value: bigint): void {
  if (value < 0n || value > MAX_UINT64)
    throw new ProtocolV2Error(`${name} must be uint64`);
}

function assertBytes(name: string, value: Uint8Array, length: number): void {
  if (value.length !== length)
    throw new ProtocolV2Error(`${name} must be ${length} bytes`);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function validateOpenKind(value: string): Uint8Array {
  const encoded = encoder.encode(value);
  if (!validOpenUnicodeString(value, MAX_OPEN_KIND_BYTES, false)) {
    throw new ProtocolV2Error("invalid OPEN kind");
  }
  const scalars = Array.from(value);
  if (
    isUnicodeWhitespace(scalars[0]!.codePointAt(0)!) ||
    isUnicodeWhitespace(scalars.at(-1)!.codePointAt(0)!)
  ) {
    throw new ProtocolV2Error(
      "OPEN kind has leading or trailing Unicode whitespace",
    );
  }
  return encoded;
}

function canonicalMetadata(raw: Uint8Array, allowEmpty: boolean): Uint8Array {
  if (raw.length === 0 && allowEmpty) return encoder.encode("{}");
  if (raw.length === 0 || raw.length > MAX_OPEN_METADATA_BYTES) {
    throw new ProtocolV2Error("invalid OPEN metadata length");
  }
  let text: string;
  try {
    text = strictDecoder.decode(raw);
  } catch {
    throw new ProtocolV2Error("OPEN metadata is not valid UTF-8");
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new ProtocolV2Error("OPEN metadata is not valid JSON");
  }
  if (!isJSONObject(value))
    throw new ProtocolV2Error("OPEN metadata root must be an object");
  const state = { nodes: -1 };
  validateMetadataValue(value, 1, state);
  const canonical = canonicalJSONString(value);
  if (
    canonical !== text ||
    encoder.encode(canonical).length > MAX_OPEN_METADATA_BYTES
  ) {
    throw new ProtocolV2Error("OPEN metadata is not canonical JSON");
  }
  return encoder.encode(canonical);
}

function validateMetadataValue(
  value: unknown,
  depth: number,
  state: { nodes: number },
): void {
  if (depth > MAX_OPEN_METADATA_DEPTH)
    throw new ProtocolV2Error("OPEN metadata exceeds depth limit");
  state.nodes += 1;
  if (state.nodes > MAX_OPEN_METADATA_NODES)
    throw new ProtocolV2Error("OPEN metadata exceeds node limit");
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value))
      throw new ProtocolV2Error(
        "OPEN metadata number is not an I-JSON safe integer",
      );
    return;
  }
  if (typeof value === "string") {
    if (!validOpenUnicodeString(value, MAX_OPEN_METADATA_STRING_BYTES, true)) {
      throw new ProtocolV2Error("invalid OPEN metadata string");
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > MAX_OPEN_METADATA_ARRAY)
      throw new ProtocolV2Error("OPEN metadata array is too large");
    for (const item of value) validateMetadataValue(item, depth + 1, state);
    return;
  }
  if (!isJSONObject(value))
    throw new ProtocolV2Error("unsupported OPEN metadata value");
  const keys = Object.keys(value);
  if (keys.length > MAX_OPEN_METADATA_KEYS)
    throw new ProtocolV2Error("OPEN metadata object is too large");
  for (const key of keys) {
    if (!validOpenUnicodeString(key, MAX_OPEN_METADATA_KEY_BYTES, false)) {
      throw new ProtocolV2Error("invalid OPEN metadata key");
    }
    validateMetadataValue(value[key], depth + 1, state);
  }
}

function canonicalJSONString(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return value.toString(10);
  if (typeof value === "string") return quoteCanonicalJSONString(value);
  if (Array.isArray(value))
    return `[${value.map(canonicalJSONString).join(",")}]`;
  if (!isJSONObject(value))
    throw new ProtocolV2Error("unsupported OPEN metadata value");
  return `{${Object.keys(value)
    .sort()
    .map(
      (key) =>
        `${quoteCanonicalJSONString(key)}:${canonicalJSONString(value[key])}`,
    )
    .join(",")}}`;
}

function quoteCanonicalJSONString(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function validOpenUnicodeString(
  value: string,
  maxBytes: number,
  allowEmpty: boolean,
): boolean {
  const bytes = encoder.encode(value);
  if (
    bytes.length > maxBytes ||
    (!allowEmpty && bytes.length === 0) ||
    value.normalize("NFC") !== value
  )
    return false;
  for (const scalar of value) {
    const codePoint = scalar.codePointAt(0)!;
    if (
      (codePoint >= 0xd800 && codePoint <= 0xdfff) ||
      codePoint <= 0x1f ||
      (codePoint >= 0x7f && codePoint <= 0x9f) ||
      !unicode15_1Assigned(codePoint)
    ) {
      return false;
    }
  }
  return true;
}

function unicode15_1Assigned(codePoint: number): boolean {
  let low = 0;
  let high = UNICODE_15_1_ASSIGNED_RANGES.length - 1;
  while (low <= high) {
    const middle = (low + high) >>> 1;
    const [start, end] = UNICODE_15_1_ASSIGNED_RANGES[middle]!;
    if (codePoint < start) high = middle - 1;
    else if (codePoint > end) low = middle + 1;
    else return true;
  }
  return false;
}

function decodeUnicodeRanges(
  value: string,
): readonly (readonly [number, number])[] {
  if (value.length % 12 !== 0)
    throw new Error("invalid committed Unicode range table");
  const ranges: Array<readonly [number, number]> = [];
  for (let offset = 0; offset < value.length; offset += 12) {
    ranges.push([
      Number.parseInt(value.slice(offset, offset + 6), 16),
      Number.parseInt(value.slice(offset + 6, offset + 12), 16),
    ]);
  }
  return ranges;
}

function isUnicodeWhitespace(codePoint: number): boolean {
  return (
    (codePoint >= 0x0009 && codePoint <= 0x000d) ||
    codePoint === 0x0020 ||
    codePoint === 0x0085 ||
    codePoint === 0x00a0 ||
    codePoint === 0x1680 ||
    (codePoint >= 0x2000 && codePoint <= 0x200a) ||
    codePoint === 0x2028 ||
    codePoint === 0x2029 ||
    codePoint === 0x202f ||
    codePoint === 0x205f ||
    codePoint === 0x3000
  );
}

function isJSONObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
