import type { IncomingMessage, ServerResponse } from "node:http";
import type { BrowserRunnerInstallation } from "../src/interop/browserRunner.js";

/** Original deployment installation and independent host history owner. */
export interface BrowserRunnerHost {
  setOrigin(origin: string): void;
  publishRuntime(observed: Readonly<{ engine: string; version: string; userAgent: string }>): Promise<void>;
  install(materialJSON: string, options?: Readonly<{ signal?: AbortSignal }>): Promise<BrowserRunnerInstallation>;
  handle(request: IncomingMessage, response: ServerResponse): Promise<boolean>;
  close(): Promise<void>;
}
export function createBrowserRunnerHost(manifestPath: string, historyDirectory: string): Promise<BrowserRunnerHost>;
export function provisionBrowserRunnerHistory(historyDirectory: string, identity: string): Promise<void>;
