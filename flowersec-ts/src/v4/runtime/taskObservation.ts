/** Stop observing an original task without ending its ownership or refunding
 * its buffers. The caller retains resources until `actual` truly settles. */
const NativePromise = Promise;
class TaskObservation<T> {
  #observer: { resolve(value: T): void; reject(error: unknown): void; signal: AbortSignal; canceled(): unknown } | undefined;
  constructor(resolve: (value: T) => void, reject: (error: unknown) => void, signal: AbortSignal, canceled: () => unknown) {
    this.#observer = { resolve, reject, signal, canceled };
    signal.addEventListener("abort", this.abort, { once: true });
  }
  readonly abort = (): void => {
    const observer = this.#take();
    if (observer !== undefined) {
      try { observer.reject(observer.canceled()); } catch (error) { observer.reject(error); }
    }
  };
  #take() {
    const observer = this.#observer; this.#observer = undefined;
    observer?.signal.removeEventListener("abort", this.abort); return observer;
  }
  succeed(value: T): void {
    if (this.#observer?.signal.aborted) this.abort();
    this.#take()?.resolve(value);
  }
  fail(error: unknown): void { this.#take()?.reject(error); }
}
export function observeTask<T>(actual: Promise<T>, signal?: AbortSignal, canceled: () => unknown = () => new Error("canceled")): Promise<T> {
  if (signal === undefined) return actual;
  return new NativePromise<T>((resolve, reject) => {
    const observation = new TaskObservation(resolve, reject, signal, canceled);
    // Reactions outlive cancellation, but retain only an empty observation
    // cell. In particular they no longer retain the canceled async workflow.
    attachObservation(actual, observation);
    if (signal.aborted) observation.abort();
  });
}
function attachObservation<T>(actual: Promise<T>, observation: TaskObservation<T>): void {
  void actual.then(value => observation.succeed(value), error => observation.fail(error));
}
