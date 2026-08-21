import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const transportV3CommonReadmeLiterals = Object.freeze([]);

export const transportV3ReadmeContracts = Object.freeze({
  "README.md": "TLS trust policy is bound to every v3 transport candidate.",
  "flowersec-go/README.md": "Go enforces CA and pin policies",
  "flowersec-ts/README.md": "Browser WebTransport is capability-dependent on",
  "flowersec-rust/README.md": "The native Rust runtime uses WebSocket and raw QUIC for direct and relayed client sessions,",
  "flowersec-swift/README.md": "The Swift SDK supports direct and relayed WebSocket sessions on macOS and iOS.",
  "examples/README.md": "These examples show the public application workflow:",
});

// Locale-owned literals keep translated capability claims synchronized with the
// canonical English matrix without requiring language-specific parsing rules.
export const transportV3SemanticReadmeContracts = Object.freeze({
  "README.md": Object.freeze({
    webtransport_h4: "| WebTransport connections | Go H4 | Browser H3 client (when available) | No | No |",
    go_only_v3_issuer: "| Control-plane invitation issuance | Yes | No | No | No |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server and opaque tunnel runtime | None |",
    webtransport_server_counts: "Go H4 adds two WebTransport server tuples and two\npath-specific units.",
  }),
  "flowersec-go/README.md": Object.freeze({
    webtransport_path_selection: "and WebTransport are selected internally for either artifact-bound direct or\ntunnel path",
  }),
  "README.zh-CN.md": Object.freeze({
    webtransport_h4: "| WebTransport 连接 | Go H4 | Browser H3 client（浏览器 API 可用时） | 否 | 否 |",
    go_only_v3_issuer: "| 控制面签发连接邀请 | 是 | 否 | 否 | 否 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server 与 opaque tunnel runtime | 无 |",
    webtransport_server_counts: "Go H4 另增加 2 个 WebTransport 服务端 tuple 和 2 个特定路径单元。",
  }),
  "README.zh-TW.md": Object.freeze({
    webtransport_h4: "| WebTransport 連線 | Go H4 | Browser H3 client（瀏覽器 API 可用時） | 否 | 否 |",
    go_only_v3_issuer: "| 控制面簽發連線邀請 | 是 | 否 | 否 | 否 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server 與 opaque tunnel runtime | 無 |",
    webtransport_server_counts: "Go H4 另增加 2 個 WebTransport 伺服器 tuple 和 2 個特定路徑單元。",
  }),
  "README.ja-JP.md": Object.freeze({
    webtransport_h4: "| WebTransport 接続 | Go H4 | Browser H3 client（ブラウザー API が利用可能な場合） | 非対応 | 非対応 |",
    go_only_v3_issuer: "| コントロールプレーンでの接続招待発行 | 対応 | 非対応 | 非対応 | 非対応 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server と opaque tunnel runtime | なし |",
    webtransport_server_counts: "Go H4 は、WebTransport server tuple 2 個と path 固有 unit 2 個を追加します。",
  }),
  "README.ko-KR.md": Object.freeze({
    webtransport_h4: "| WebTransport 연결 | Go H4 | Browser H3 client(브라우저 API 사용 가능 시) | 미지원 | 미지원 |",
    go_only_v3_issuer: "| 제어 영역 연결 초대 발급 | 지원 | 미지원 | 미지원 | 미지원 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server 및 opaque tunnel runtime | 없음 |",
    webtransport_server_counts: "Go H4는 WebTransport server tuple 2개와 path별 unit 2개를 추가합니다.",
  }),
  "README.de-DE.md": Object.freeze({
    webtransport_h4: "| WebTransport-Verbindungen | Go H4 | Browser H3 client (wenn die WebTransport-API verfügbar ist) | Nein | Nein |",
    go_only_v3_issuer: "| Verbindungseinladungen der Control Plane | Ja | Nein | Nein | Nein |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport-Direktserver und opake Tunnellaufzeit | Keine |",
    webtransport_server_counts: "Go H4 fuegt zwei WebTransport-Server-Tupel und zwei pfadspezifische Einheiten hinzu.",
  }),
  "README.fr-FR.md": Object.freeze({
    webtransport_h4: "| Connexions WebTransport | Go H4 | Client Browser H3 (si l'API WebTransport du navigateur est disponible) | Non | Non |",
    go_only_v3_issuer: "| Émission d'invitations par le plan de contrôle | Oui | Non | Non | Non |",
    webtransport_server_profile: "| `webtransport-server` | Go | Serveur WebTransport direct et runtime de tunnel opaque | Aucune |",
    webtransport_server_counts: "Go H4 ajoute deux tuples serveur WebTransport et deux unités propres à un chemin.",
  }),
  "README.es-ES.md": Object.freeze({
    webtransport_h4: "| Conexiones WebTransport | Go H4 | Cliente Browser H3 (cuando la API WebTransport del navegador está disponible) | No | No |",
    go_only_v3_issuer: "| Emisión de invitaciones desde el plano de control | Sí | No | No | No |",
    webtransport_server_profile: "| `webtransport-server` | Go | Servidor WebTransport directo y runtime de tunel opaco | Ninguna |",
    webtransport_server_counts: "Go H4 añade dos tuplas de servidor WebTransport y dos unidades específicas de ruta.",
  }),
  "README.pt-BR.md": Object.freeze({
    webtransport_h4: "| Conexões WebTransport | Go H4 | Cliente Browser H3 (quando a API WebTransport do navegador está disponível) | Não | Não |",
    go_only_v3_issuer: "| Emissão de convites no plano de controle | Sim | Não | Não | Não |",
    webtransport_server_profile: "| `webtransport-server` | Go | Servidor WebTransport direto e runtime de tunel opaco | Nenhuma |",
    webtransport_server_counts: "O Go H4 adiciona duas tuplas de servidor WebTransport e duas unidades específicas de caminho.",
  }),
  "README.ru-RU.md": Object.freeze({
    webtransport_h4: "| Соединения WebTransport | Go H4 | Browser H3 client (при наличии API WebTransport в браузере) | Нет | Нет |",
    go_only_v3_issuer: "| Выпуск приглашений управляющей плоскостью | Да | Нет | Нет | Нет |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server и opaque tunnel runtime | Нет |",
    webtransport_server_counts: "Go H4 добавляет два серверных WebTransport tuple и две специфичные для пути единицы.",
  }),
});

export function validateTransportV3Readmes(repoRoot) {
  const errors = [];
  for (const [file, supportStatus] of Object.entries(transportV3ReadmeContracts)) {
    const readmePath = resolve(repoRoot, file);
    if (!existsSync(readmePath)) {
      errors.push(`${file}: missing README`);
      continue;
    }
    const content = readFileSync(readmePath, "utf8");
    for (const literal of transportV3CommonReadmeLiterals) {
      if (!content.includes(literal)) {
        errors.push(`${file}: missing shared README contract literal: ${literal}`);
      }
    }
    if (!content.includes(supportStatus)) {
      errors.push(`${file}: missing current user-facing support description`);
    }
  }
  for (const [file, contracts] of Object.entries(transportV3SemanticReadmeContracts)) {
    const readmePath = resolve(repoRoot, file);
    if (!existsSync(readmePath)) {
      errors.push(`${file}: missing README`);
      continue;
    }
    const content = readFileSync(readmePath, "utf8");
    for (const [contract, literal] of Object.entries(contracts)) {
      if (!content.includes(literal)) {
        errors.push(`${file}: missing current ${contract.replaceAll("_", " ")} semantics`);
      }
    }
  }
  return errors;
}
