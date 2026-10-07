import type { ConnectionAttemptFacts } from "../connectionDiagnostic.js";

/** Facts written by the original durable and authenticated owners. No gate or retry authority lives here. */
export class ConnectionFacts {
  #spend: ConnectionAttemptFacts["spendState"] = "unspent";
  #admission: ConnectionAttemptFacts["admissionState"] = "not_started";
  #ready: ConnectionAttemptFacts["networkReady"] = "not_started";
  #publication: ConnectionAttemptFacts["applicationPublish"] = "not_started";
  #source: ConnectionAttemptFacts["sourceProfile"];
  constructor(private readonly changed?: () => void) {}
  source(profile: NonNullable<ConnectionAttemptFacts["sourceProfile"]>): void {
    if (this.#source === profile) return;
    this.#source = profile; this.changed?.();
  }
  spendDispatched(): void {
    if (this.#spend !== "unspent") return;
    this.#spend = "unknown"; this.changed?.();
  }
  spent(): void {
    if (this.#spend === "spent") return;
    this.#spend = "spent"; this.changed?.();
  }
  /** Only the original durable owner's confirmed abort before COMMIT may call this. */
  unspent(): void {
    if (this.#spend !== "unknown") return;
    this.#spend = "unspent"; this.changed?.();
  }
  admissionDispatched(): void {
    if (this.#admission !== "not_started") return;
    this.#admission = "in_flight"; this.changed?.();
  }
  admitted(): void {
    if (this.#admission === "admitted") return;
    // The verified FSA4 is also positive evidence of the original spend.
    this.#spend = "spent"; this.#admission = "admitted"; this.changed?.();
  }
  ready(): void {
    if (this.#ready === "ready") return;
    // Fully authenticated dual READY is positive evidence of the original admission.
    this.#spend = "spent"; this.#admission = "admitted"; this.#ready = "ready"; this.changed?.();
  }
  published(): void {
    if (this.#publication === "published") return;
    this.#publication = "published"; this.changed?.();
  }
  publicationFailed(): void {
    if (this.#publication === "published" || this.#publication === "failed") return;
    this.#publication = "failed"; this.changed?.();
  }
  unavailable(): void {
    if (this.#spend !== "spent") this.#spend = "unknown";
    if (this.#admission !== "admitted") this.#admission = "unknown";
    if (this.#ready !== "ready") this.#ready = "unknown";
    if (this.#publication !== "published" && this.#publication !== "failed") this.#publication = "unknown";
    this.changed?.();
  }
  failed(): void {
    if (this.#admission !== "in_flight") return;
    this.#admission = "unknown"; this.changed?.();
  }
  snapshot(): ConnectionAttemptFacts {
    const phase = this.#ready === "ready" ? "ready" :
      this.#spend === "unknown" || this.#ready === "unknown" || this.#admission === "unknown" || this.#admission === "in_flight" ? "unknown" :
      this.#admission === "admitted" ? "admitted_not_ready" : this.#spend === "spent" ? "spent_not_admitted" : "not_started";
    return Object.freeze({ phase, spent: this.#spend === "unknown" ? "unknown" : this.#spend === "spent",
      spendState: this.#spend, admissionState: this.#admission, networkReady: this.#ready,
      applicationPublish: this.#publication, ...(this.#source === undefined ? {} : { sourceProfile: this.#source }),
      queryAvailability: "unavailable" });
  }
}

const sessionFacts = new WeakMap<object, ConnectionAttemptFacts>();
export function rememberConnectionFacts(session: object, facts: ConnectionAttemptFacts): void { sessionFacts.set(session, facts); }
export function observedConnectionFacts(session: object): ConnectionAttemptFacts | undefined { return sessionFacts.get(session); }
export function unknownConnectionFacts(): ConnectionAttemptFacts {
  const facts = new ConnectionFacts(); facts.unavailable(); return facts.snapshot();
}
