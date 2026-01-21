# @floegence/flowersec-core

Flowersec core TypeScript library for building an end-to-end encrypted, multiplexed connection over WebSocket (browser-friendly).

Status: experimental; not audited.

## Install

```bash
npm install @floegence/flowersec-core
```

## Usage

Browser (recommended):

```ts
import { connectBrowser } from "@floegence/flowersec-core/browser";

const grant = await fetch("/api/flowersec/channel/init", { method: "POST" }).then((r) => r.json());
const client = await connectBrowser(grant);
await client.ping();
client.close();
```

Node.js (recommended):

```ts
import { connectNode } from "@floegence/flowersec-core/node";

const grant = JSON.parse(process.env.FLOWERSEC_GRANT_JSON ?? "{}");
const client = await connectNode(grant, { origin: "https://your-app.example" });
await client.ping();
client.close();
```

## Docs

- Frontend quickstart: `docs/FRONTEND_QUICKSTART.md`
- Integration guide: `docs/INTEGRATION_GUIDE.md`
- API surface contract: `docs/API_SURFACE.md`
- Error model: `docs/ERROR_MODEL.md`

