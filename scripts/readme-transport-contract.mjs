import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

export const transportReadmeContracts = Object.freeze({
  "README.md": "TLS trust policy is bound to every v5 transport candidate.",
  "flowersec-go/README.md": "Go enforces CA and pin policies",
  "flowersec-ts/README.md": "Browsers support WSS and optional browser-owned WebTransport.",
  "flowersec-rust/README.md": "Rust supports direct and relayed WebSocket and raw QUIC connections.",
  "flowersec-swift/README.md": "Swift supports direct and relayed TLS 1.3 WebSocket sessions on macOS and iOS.",
  "examples/README.md": "These examples show the public application workflow:",
});

// Locale-owned literals keep translated capability claims synchronized with the
// canonical English matrix without requiring language-specific parsing rules.
export const transportSemanticReadmeContracts = Object.freeze({
  "README.md": Object.freeze({
    webtransport_h4: "the Browser profile uses the H3 WebTransport API when present.",
    draft02_scope: "support `draft02` for clients, direct listeners, and opaque\ntunnel listeners.",
    go_client_direction: "issue a raw QUIC route for Go clients dialing Rust or Node.js",
    go_only_issuer: "| Control-plane issuance and authorization | Yes | No | No | No |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server and opaque tunnel runtime | None |",
    webtransport_server_counts: "Go H4 adds two WebTransport server tuples and two\npath-specific units.",
  }),
  "flowersec-go/README.md": Object.freeze({
    webtransport_path_selection: "and WebTransport are selected internally for either artifact-bound direct or\ntunnel path",
  }),
  "flowersec-rust/README.md": Object.freeze({
    webtransport_client_profile: "`ConnectorOptions::with_webtransport_origin`",
    webtransport_direct_listener: "Acceptor::bind_webtransport",
    webtransport_tunnel_listener: "TunnelRuntime::bind_webtransport",
  }),
  "flowersec-ts/README.md": Object.freeze({
    node_webtransport_profile: 'pass `webTransport: true`',
  }),
  "README.zh-CN.md": Object.freeze({
    webtransport_h4: "Browser profile 在浏览器 WebTransport API 可用时使用 H3",
    draft02_scope: "直连监听器和不透明隧道监听器支持 `draft02`。",
    go_client_direction: "Rust 和 Node.js 客户端可以通过 WebTransport 连接 Go 监听器。反向连接时，Go 客户端必须使用显式签发的原生 QUIC 路由连接 Rust 或 Node.js，隧道入口也一样。这不属于 WebTransport 互通。",
    go_only_issuer: "| 控制面签发与授权 | 是 | 否 | 否 | 否 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server 与 opaque tunnel runtime | 无 |",
    webtransport_server_counts: "Go H4 另增加 2 个 WebTransport 服务端 tuple 和 2 个特定路径单元。",
  }),
  "README.zh-TW.md": Object.freeze({
    webtransport_h4: "Browser profile 會在瀏覽器 WebTransport API 可用時使用 H3",
    draft02_scope: "直連監聽器及不透明隧道監聽器支援 `draft02`。",
    go_client_direction: "Rust 與 Node.js 用戶端可透過 WebTransport 連線至 Go 監聽器。反向連線時，Go 用戶端必須使用明確指定的原生 QUIC 路由連線至 Rust 或 Node.js，隧道入口亦同。這不屬於 WebTransport 互通。",
    go_only_issuer: "| 控制平面簽發與授權 | 是 | 否 | 否 | 否 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server 與 opaque tunnel runtime | 無 |",
    webtransport_server_counts: "Go H4 另增加 2 個 WebTransport 伺服器 tuple 和 2 個特定路徑單元。",
  }),
  "README.ja-JP.md": Object.freeze({
    webtransport_h4: "Browser profile はブラウザーの WebTransport API が利用可能な場合に H3 を使用します",
    draft02_scope: "不透明トンネルのリスナーでは `draft02` を使用します。",
    go_client_direction: "Rust と Node.js のクライアントは WebTransport で Go に接続できます。逆方向では、トンネルの入口を含め、Go から Rust または Node.js への接続に raw QUIC の経路を明示的に指定します。これは WebTransport の相互運用には含まれません。",
    go_only_issuer: "| コントロールプレーンでの発行と認可 | 対応 | 非対応 | 非対応 | 非対応 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server と opaque tunnel runtime | なし |",
    webtransport_server_counts: "Go H4 は、WebTransport server tuple 2 個と path 固有 unit 2 個を追加します。",
  }),
  "README.ko-KR.md": Object.freeze({
    webtransport_h4: "Browser profile은 브라우저 WebTransport API를 사용할 수 있을 때 H3를 사용합니다",
    draft02_scope: "불투명 터널 리스너에서는 `draft02`를 사용합니다.",
    go_client_direction: "Rust와 Node.js 클라이언트는 WebTransport로 Go 리스너에 연결할 수 있습니다. 반대로 Go에서 Rust 또는 Node.js로 연결할 때는 터널 입구를 포함해 raw QUIC 경로를 명시해야 합니다. 이는 WebTransport 상호 운용에 해당하지 않습니다.",
    go_only_issuer: "| 제어 영역 발급 및 권한 부여 | 지원 | 미지원 | 미지원 | 미지원 |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server 및 opaque tunnel runtime | 없음 |",
    webtransport_server_counts: "Go H4는 WebTransport server tuple 2개와 path별 unit 2개를 추가합니다.",
  }),
  "README.de-DE.md": Object.freeze({
    webtransport_h4: "Browser-Profil verwendet H3, wenn die Browser-WebTransport-API verfügbar ist",
    draft02_scope: "unterstützen `draft02` für Clients, direkte Listener und opake Tunnel-Relays.",
    go_client_direction: "Rust- und Node.js-Clients können Go über WebTransport erreichen. In Gegenrichtung benötigen Go-Clients eine explizite Raw-QUIC-Route zu Rust oder Node.js, auch am Tunneleingang. Das ist keine WebTransport-Verbindung.",
    go_only_issuer: "| Ausgabe und Autorisierung der Control Plane | Ja | Nein | Nein | Nein |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport-Direktserver und opake Tunnellaufzeit | Keine |",
    webtransport_server_counts: "Go H4 fuegt zwei WebTransport-Server-Tupel und zwei pfadspezifische Einheiten hinzu.",
  }),
  "README.fr-FR.md": Object.freeze({
    webtransport_h4: "profil Browser utilise H3 lorsque l'API WebTransport du navigateur est disponible",
    draft02_scope: "proposent `draft02` pour les clients, les serveurs directs et les relais de tunnels opaques.",
    go_client_direction: "Les clients Rust et Node.js peuvent joindre Go via WebTransport. Dans le sens inverse, un client Go utilise une route QUIC native explicite vers Rust ou Node.js, y compris à l’entrée d’un tunnel. Il ne s’agit pas d’une connexion WebTransport.",
    go_only_issuer: "| Émission et autorisation par le plan de contrôle | Oui | Non | Non | Non |",
    webtransport_server_profile: "| `webtransport-server` | Go | Serveur WebTransport direct et runtime de tunnel opaque | Aucune |",
    webtransport_server_counts: "Go H4 ajoute deux tuples serveur WebTransport et deux unités propres à un chemin.",
  }),
  "README.es-ES.md": Object.freeze({
    webtransport_h4: "perfil Browser usa H3 cuando la API WebTransport del navegador está disponible",
    draft02_scope: "admiten `draft02` en clientes, servidores directos y relés de túneles opacos.",
    go_client_direction: "Los clientes Rust y Node.js pueden conectarse a Go mediante WebTransport. En sentido inverso, un cliente Go necesita una ruta QUIC nativa explícita hacia Rust o Node.js, incluso para entrar en un túnel. No es una conexión WebTransport.",
    go_only_issuer: "| Emisión y autorización del plano de control | Sí | No | No | No |",
    webtransport_server_profile: "| `webtransport-server` | Go | Servidor WebTransport directo y runtime de tunel opaco | Ninguna |",
    webtransport_server_counts: "Go H4 añade dos tuplas de servidor WebTransport y dos unidades específicas de ruta.",
  }),
  "README.pt-BR.md": Object.freeze({
    webtransport_h4: "perfil Browser usa H3 quando a API WebTransport do navegador está disponível",
    draft02_scope: "oferecem `draft02` para clientes, servidores diretos e relés de túneis opacos.",
    go_client_direction: "Clientes Rust e Node.js podem se conectar ao Go por WebTransport. No sentido inverso, um cliente Go precisa de uma rota QUIC nativa explícita para Rust ou Node.js, inclusive na entrada de um túnel. Essa conexão não usa WebTransport.",
    go_only_issuer: "| Emissão e autorização do plano de controle | Sim | Não | Não | Não |",
    webtransport_server_profile: "| `webtransport-server` | Go | Servidor WebTransport direto e runtime de tunel opaco | Nenhuma |",
    webtransport_server_counts: "O Go H4 adiciona duas tuplas de servidor WebTransport e duas unidades específicas de caminho.",
  }),
  "README.ru-RU.md": Object.freeze({
    webtransport_h4: "профиль Browser использует H3, если доступен API WebTransport браузера",
    draft02_scope: "профиль `draft02` доступен клиентам, серверам прямых соединений и ретрансляторам непрозрачных туннелей.",
    go_client_direction: "Клиенты Rust и Node.js могут подключаться к Go по WebTransport. В обратном направлении клиенту Go нужен явно заданный маршрут raw QUIC к Rust или Node.js, в том числе для входа в туннель. Такое соединение не использует WebTransport.",
    go_only_issuer: "| Выпуск и авторизация в управляющей плоскости | Да | Нет | Нет | Нет |",
    webtransport_server_profile: "| `webtransport-server` | Go | WebTransport direct server и opaque tunnel runtime | Нет |",
    webtransport_server_counts: "Go H4 добавляет два серверных WebTransport tuple и две специфичные для пути единицы.",
  }),
});

export function validateTransportReadmes(repoRoot) {
  const errors = [];
  for (const [file, supportStatus] of Object.entries(transportReadmeContracts)) {
    const readmePath = resolve(repoRoot, file);
    if (!existsSync(readmePath)) {
      errors.push(`${file}: missing README`);
      continue;
    }
    const content = readFileSync(readmePath, "utf8");
    if (!content.includes(supportStatus)) {
      errors.push(`${file}: missing current user-facing support description`);
    }
  }
  for (const [file, contracts] of Object.entries(transportSemanticReadmeContracts)) {
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
