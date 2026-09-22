import { validateApiResult } from "./transport-v4-api-results.mjs";

// Serial public-fixture model of one WriteRequest. Trusted callers supply
// acceptance/cleanup facts; this is not a queue, scheduler, clock or byte owner.
const MAX = (1n << 64n) - 1n;
const requireThat = (condition, code) => { if (!condition) throw new Error(code); };
const uint = value => typeof value === "bigint" && value >= 0n && value <= MAX;

export class WriteStateReference {
  #schema; #requested; #accepted = 0n; #ticketed = 0n; #deadline; #now;
  #phase = "prepared"; #reason = "none"; #senderClosed = false;
  #cleanup = { status: "pending", core_cleanup: "pending", pending_callbacks: 0n };

  constructor(schema, { requested_bytes, max_write_operation_bytes, prepared_at_ms, deadline_at_ms }) {
    requireThat([requested_bytes, max_write_operation_bytes, prepared_at_ms, deadline_at_ms].every(uint), "write_parameters");
    requireThat(max_write_operation_bytes > 0n && requested_bytes <= max_write_operation_bytes, "write_operation_capacity");
    requireThat(deadline_at_ms > prepared_at_ms, "write_deadline");
    this.#schema = schema; this.#requested = requested_bytes;
    this.#deadline = deadline_at_ms; this.#now = prepared_at_ms;
  }
  #end(reason) { if (this.#phase !== "terminal") { this.#phase = "terminal"; this.#reason = reason; } }
  observeTime(now) {
    requireThat(uint(now) && now >= this.#now, "write_time_continuity");
    this.#now = now;
    if (now >= this.#deadline) this.#end("deadline_exceeded");
    return this.progress();
  }
  start({ queue_available }) {
    requireThat(typeof queue_available === "boolean", "write_queue_fact");
    if (this.#phase === "prepared") {
      if (!queue_available) this.#end("queue_full");
      else if (this.#requested === 0n) this.#end("complete");
      else this.#phase = "running";
    }
    return this.progress();
  }
  accept(bytes) {
    requireThat(this.#phase === "running", "write_acceptance_closed");
    requireThat(uint(bytes) && bytes > 0n && bytes <= this.#requested - this.#accepted, "write_acceptance_bounds");
    this.#accepted += bytes;
    if (this.#accepted === this.#requested) this.#end("complete");
    return this.progress();
  }
  ticket(bytes) {
    // Sender responsibility for accepted bytes survives operation cancellation.
    requireThat(!this.#senderClosed, "write_sender_closed");
    requireThat(uint(bytes) && bytes > 0n && bytes <= this.#accepted - this.#ticketed, "write_ticket_bounds");
    this.#ticketed += bytes;
    return this.progress();
  }
  cancel() { this.#end("canceled"); return this.progress(); }
  fail(reason) {
    requireThat(["stream_terminated", "failed"].includes(reason), "write_failure");
    if (reason === "stream_terminated") this.#senderClosed = true;
    this.#end(reason); return this.progress();
  }
  wait({ canceled = false } = {}) {
    requireThat(typeof canceled === "boolean", "write_wait_parameters");
    return { wait_status: this.#phase === "terminal" ? "ready" : canceled ? "wait_canceled" : "blocked", progress: this.progress() };
  }
  cleanup(facts) {
    validateApiResult(this.#schema, "CleanupStatus", facts);
    requireThat(this.#phase === "terminal" || facts.status !== "complete", "write_live_cleanup");
    requireThat(this.#cleanup.core_cleanup !== "complete" || facts.core_cleanup === "complete", "write_cleanup_regression");
    requireThat(this.#cleanup.status !== "complete" || facts.status === "complete", "write_cleanup_regression");
    this.#cleanup = { ...facts }; return this.progress();
  }
  progress() {
    const result = { requested_bytes: this.#requested, accepted_bytes: this.#accepted, phase: this.#phase,
      terminal_reason: this.#reason, cleanup_status: { ...this.#cleanup } };
    validateApiResult(this.#schema, "WriteProgress", result);
    return result;
  }
}
