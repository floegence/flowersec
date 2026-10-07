import type { DiagnosticFields, DiagnosticMetric } from "../diagnostics.js";
import { diagnosticDuration, diagnosticFailure, type DiagnosticCounters, type DiagnosticFailure } from "./diagnosticCounters.js";

/** Internal finite facts only. Implementations never call an application sink
 * on the producer's stack and cannot influence transport decisions. */
export interface DiagnosticOperation { emit(fields: Partial<DiagnosticFields>): void; close(): void; }
export interface DiagnosticObserver {
  readonly counters: DiagnosticCounters;
  begin(): DiagnosticOperation | undefined;
}

/** One original connection or application operation, independent of protocol
 * identities. The source owns its phase and closes this observation once. */
export class DiagnosticActivity {
  #observer: DiagnosticObserver | undefined;
  #operation: DiagnosticOperation | undefined;
  #phase: DiagnosticFields["phase"];
  readonly #attempt: DiagnosticFields["attempt_bucket"];
  readonly #started = performance.now();
  #closed = false;
  #failed = false;
  #publicationHeld = false;
  #closePending = false;
  constructor(observer: DiagnosticObserver | undefined, phase: DiagnosticFields["phase"], connection = false, attempt = 1n) {
    this.#attempt = attempt < 1n ? "other" : attempt === 1n ? "1" : attempt < 4n ? "2_3" : attempt < 8n ? "4_7" : "8_plus";
    this.#observer = observer; this.#phase = phase; this.#operation = observer?.begin();
    this.event({ state: "starting", phase }, connection ? "connection_attempt" : undefined);
  }
  phase(phase: DiagnosticFields["phase"]): void { this.#phase = phase; this.event({ state: "starting", phase }); }
  holdPublication(): void { if (!this.#closed) this.#publicationHeld = true; }
  finishPublication(): void { this.#publicationHeld = false; if (this.#closePending) this.close(); }
  event(fields: Partial<DiagnosticFields>, metric?: DiagnosticMetric): void {
    if (this.#closed) return;
    const value = { phase: this.#phase, attempt_bucket: this.#attempt, duration_bucket: diagnosticDuration(this.#started), ...fields };
    if (metric !== undefined) this.#observer?.counters.observe(metric, value);
    this.#operation?.emit(value);
  }
  failure(error: unknown, connection = false): void {
    if (this.#closed || this.#failed) return;
    this.failureFacts(diagnosticFailure(error), connection);
  }
  failureFacts(failure: DiagnosticFailure, connection = false): void {
    if (this.#closed || this.#failed) return;
    this.#failed = true;
    const fields = { state: "failed", code: failure.code, retry_disposition: "preserve_facts" } as const;
    // Resource, provider, store and consumer facts are counted by their
    // original owners. A propagated failure is one operation outcome, not a
    // second occurrence of each lower-level fact.
    if (failure.metric === "identity_rejection") this.#observer?.counters.observe("identity_rejection", {
      phase: this.#phase, attempt_bucket: this.#attempt, duration_bucket: diagnosticDuration(this.#started), ...fields,
    });
    this.event(fields, connection ? "connection_failure" : undefined); this.close();
  }
  close(): void {
    if (this.#closed) return;
    if (this.#publicationHeld) { this.#closePending = true; return; }
    this.event({ state: "closed" }); this.#closed = true;
    this.#operation?.close(); this.#operation = undefined; this.#observer = undefined;
  }
}
