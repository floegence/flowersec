import { describe, expect, test } from "vitest";

import { ConnectError } from "../public/connectError.js";
import { SessionError } from "./contract.js";
import {
  retryDispositionForConnectError,
  retryDispositionForSessionError,
} from "./retryDisposition.js";

describe("retry disposition", () => {
  test("retries only failures that require a fresh connection", () => {
    expect(retryDispositionForConnectError(new ConnectError("connection_failed"))).toEqual({ kind: "retryable" });
    expect(retryDispositionForConnectError(new ConnectError("invalid_options"))).toEqual({ kind: "terminal" });
    expect(retryDispositionForSessionError(new SessionError("going_away"))).toEqual({ kind: "retryable" });
    expect(retryDispositionForSessionError(new SessionError("canceled"))).toEqual({ kind: "terminal" });
  });
});
