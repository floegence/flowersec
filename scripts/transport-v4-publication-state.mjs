import { decodeMap } from "./transport-v4-codec.mjs";
import { captureApplicationBytes } from "./transport-v4-application-headers.mjs";
import { validateApiResult } from "./transport-v4-api-results.mjs";

const MAX = 0xffffffffffffffffn;
const uint = value => typeof value === "bigint" && value >= 0n && value <= MAX;
const requireThat = (condition, code) => { if (!condition) throw new Error(code); };

// Serial original-publisher reference, not a provider or ResponsePublication
// runtime. The exact request/channel and actual original response final byte
// must already be attributed by trusted owners. Offset events are contiguous
// original-response prefixes in that same provider byte space, never tickets,
// another response, substituted bytes or a peer receipt. No test assertion
// establishes that attribution, actual time, transfer, cleanup or restart rights.
export class PublicationStateReference {
  #schema; #context; #timeout; #hardDeadline; #deadline; #now;
  #last; #accepted; #handoff;

  constructor(schema, { contract, createdAt, hardDeadline, providerFrontier }) {
    requireThat([createdAt, hardDeadline, providerFrontier].every(uint) && hardDeadline > createdAt, "publication_parameters");
    this.#schema = structuredClone(schema);
    const bytes = captureApplicationBytes(contract, schema.frame_maps.ServiceContract.max_encoded_bytes);
    const definition = decodeMap(this.#schema, "ServiceContract", bytes);
    const get = name => definition.get(BigInt(Object.entries(schema.frame_maps.ServiceContract.fields).find(([, entry]) => entry.name === name)[0]));
    this.#context = { applicable: get("restart_flush"), original_selected: false, provider_handoff_complete: false };
    this.#timeout = get("restart_flush_deadline_ms");
    this.#now = createdAt; this.#hardDeadline = hardDeadline;
    this.#accepted = this.#handoff = providerFrontier;
  }

  #pending() { return this.#context.applicable && !this.#context.provider_handoff_complete && this.#context.failure_cause === undefined; }
  state() {
    const state = !this.#context.applicable ? "not_applicable" : this.#context.provider_handoff_complete ? "flushed" : this.#context.failure_cause === undefined ? "pending" : "unknown";
    const result = { state, ...(this.#context.failure_cause === undefined ? {} : { cause: this.#context.failure_cause }) };
    validateApiResult(this.#schema, "ResponsePublicationStatus", result, this.#context);
    return Object.freeze(result);
  }

  observeTime(now) {
    requireThat(uint(now) && now >= this.#now, "publication_time_continuity");
    this.#now = now;
    if (this.#pending() && now >= (this.#deadline ?? this.#hardDeadline)) this.#context.failure_cause = "deadline";
    return this.state();
  }

  bindOriginalResponse(lastByteOffset) {
    requireThat(this.#pending() && this.#last === undefined, "publication_selection_closed");
    requireThat(uint(lastByteOffset) && lastByteOffset > this.#accepted, "publication_final_byte");
    this.#last = lastByteOffset; this.#context.original_selected = true;
    // The finite policy starts once the response enters this publisher, never
    // at handler entry or on a later waiter. BigInt addition cannot wrap; taking
    // the earlier finite hard deadline also bounds the final value to uint64.
    const policyDeadline = this.#now + this.#timeout;
    this.#deadline = policyDeadline < this.#hardDeadline ? policyDeadline : this.#hardDeadline;
    return this.state();
  }

  internalAcceptThrough(offset) {
    requireThat(this.#last !== undefined && uint(offset) && offset >= this.#accepted && offset <= this.#last, "publication_acceptance_frontier");
    this.#accepted = offset;
    // Complete internal acceptance may release the ReplySlot; it never flushes.
    return this.state();
  }

  providerHandoffThrough(offset) {
    requireThat(this.#last !== undefined && uint(offset) && offset >= this.#handoff && offset <= this.#accepted, "publication_provider_frontier");
    this.#handoff = offset;
    if (this.#pending() && offset === this.#last) this.#context.provider_handoff_complete = true;
    // A first terminal failure seals this observation. Late handoff or tail
    // failure belongs to real cleanup/transport state and cannot rewrite it.
    return this.state();
  }

  fail(cause) {
    requireThat(this.#schema.api_schema.types.ResponsePublicationCause.enum.includes(cause), "publication_failure_cause");
    if (this.#pending()) this.#context.failure_cause = cause;
    return this.state();
  }

  wait({ canceled = false } = {}) {
    requireThat(typeof canceled === "boolean", "publication_wait_parameters");
    const publication = this.state();
    return Object.freeze({ wait_status: publication.state !== "pending" ? "ready" : canceled ? "wait_canceled" : "blocked", publication });
  }

  snapshot() {
    return Object.freeze({ publication: this.state(), now: this.#now,
      publication_deadline: this.#deadline, hard_deadline: this.#hardDeadline,
      last_byte: this.#last, internally_accepted: this.#accepted, provider_handoff: this.#handoff });
  }
}
