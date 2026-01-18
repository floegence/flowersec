import { createRequire } from "node:module";

import type { WebSocketLike } from "../ws-client/binaryTransport.js";

type EventType = "open" | "message" | "error" | "close";

type Listener = (ev: any) => void;

// createNodeWsFactory returns a wsFactory compatible with connectTunnel/connectDirect in Node.js.
//
// It uses the "ws" package to set the Origin header explicitly (browsers set Origin automatically).
export function createNodeWsFactory(): (url: string, origin: string) => WebSocketLike {
  const require = createRequire(import.meta.url);
  const wsMod = require("ws") as any;
  const WebSocketCtor = wsMod?.WebSocket ?? wsMod;

  return (url: string, origin: string): WebSocketLike => {
    const raw = new WebSocketCtor(url, { headers: { Origin: origin } });

    // Map (type -> user listener -> wrapped listener) so removeEventListener works.
    const listeners = new Map<EventType, Map<Listener, (...args: any[]) => void>>();

    const addEventListener = (type: EventType, listener: Listener): void => {
      const wrapped = (...args: any[]) => {
        if (type === "message") {
          listener({ data: args[0] });
          return;
        }
        if (type === "close") {
          const code = typeof args[0] === "number" ? args[0] : undefined;
          const reason =
            typeof args[1] === "string"
              ? args[1]
              : args[1] != null && typeof args[1].toString === "function"
                ? args[1].toString()
                : undefined;
          listener({ code, reason });
          return;
        }
        listener(args[0]);
      };

      let m = listeners.get(type);
      if (m == null) {
        m = new Map();
        listeners.set(type, m);
      }
      m.set(listener, wrapped);
      raw.on(type, wrapped);
    };

    const removeEventListener = (type: EventType, listener: Listener): void => {
      const m = listeners.get(type);
      const wrapped = m?.get(listener);
      if (wrapped == null) return;
      m!.delete(listener);
      raw.off(type, wrapped);
      if (m!.size === 0) listeners.delete(type);
    };

    return {
      get binaryType() {
        return raw.binaryType as unknown as string;
      },
      set binaryType(v: string) {
        raw.binaryType = v;
      },
      get readyState() {
        return raw.readyState as number;
      },
      send(data: string | ArrayBuffer | Uint8Array): void {
        raw.send(data);
      },
      close(code?: number, reason?: string): void {
        raw.close(code, reason);
      },
      addEventListener,
      removeEventListener,
    };
  };
}

