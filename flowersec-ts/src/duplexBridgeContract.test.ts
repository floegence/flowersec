import { describe, expect, it } from "vitest";
import { DuplexBridge, DuplexBridgeError } from "./facade.js";
import { DuplexBridge as NodeDuplexBridge, DuplexBridgeError as NodeDuplexBridgeError, DuplexTCPConnection, connectDuplexTCP } from "./node/index.js";
import { DuplexBridge as BrowserDuplexBridge, DuplexBridgeError as BrowserDuplexBridgeError } from "./browser/index.js";
import { DuplexBridge as ProxyDuplexBridge, DuplexBridgeError as ProxyDuplexBridgeError } from "./proxy/index.js";

describe("public DuplexBridge contract", () => {
  it("keeps Node native endpoint support local to the Node entrypoint", () => {
    expect(NodeDuplexBridge).not.toBe(DuplexBridge);
    expect(BrowserDuplexBridge).toBe(DuplexBridge);
    expect(ProxyDuplexBridge).toBe(DuplexBridge);
    expect(NodeDuplexBridgeError).toBe(DuplexBridgeError);
    expect(typeof DuplexTCPConnection).toBe("function"); expect(typeof connectDuplexTCP).toBe("function");
    expect(BrowserDuplexBridgeError).toBe(DuplexBridgeError);
    expect(ProxyDuplexBridgeError).toBe(DuplexBridgeError);
  });
});
