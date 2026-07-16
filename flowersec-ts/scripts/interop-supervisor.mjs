export class Supervisor {
  constructor(controller, onTaskError = () => {}) {
    this.controller = controller;
    this.onTaskError = onTaskError;
    this.tasks = new Set();
    this.errors = [];
    this.failure = new Promise((_, reject) => { this.rejectFailure = reject; });
  }

  run(task) {
    const supervised = Promise.resolve(task).catch((error) => {
      if (this.isCancellation(error)) return;
      this.errors.push(error);
      this.onTaskError(error);
      if (this.errors.length === 1) this.rejectFailure(error);
      if (!this.controller.signal.aborted) this.controller.abort(asError(error));
    }).finally(() => this.tasks.delete(supervised));
    this.tasks.add(supervised);
  }

  stop(reason) {
    if (!this.controller.signal.aborted) this.controller.abort(asError(reason));
  }

  waitForFailure() {
    return this.failure;
  }

  async finish() {
    await Promise.allSettled([...this.tasks]);
    if (this.errors.length === 1) throw this.errors[0];
    if (this.errors.length > 1) throw new AggregateError(this.errors, "supervised tasks failed");
  }

  isCancellation(error) {
    if (!this.controller.signal.aborted) return false;
    const reason = this.controller.signal.reason;
    for (let current = error; current != null; current = current instanceof Error ? current.cause : undefined) {
      if (current === reason) return true;
      if (typeof DOMException !== "undefined" && current instanceof DOMException && current.name === "AbortError") {
        return true;
      }
    }
    return false;
  }
}

function asError(value) {
  return value instanceof Error ? value : new Error(String(value));
}
