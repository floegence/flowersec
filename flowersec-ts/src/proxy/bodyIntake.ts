export class BodyIntake {
  private count = 0;
  private bytes = 0;
  private readonly waiters = new Set<() => void>();

  constructor(private readonly slots: number, private readonly limit: number) {}

  begin() {
    if (this.count >= this.slots) return undefined;
    this.count++;
    let held = 0;
    const grow = (size: number) => {
      if (this.bytes + size > this.limit) return false;
      this.bytes += size;
      held += size;
      return true;
    };
    return {
      grow,
      waitForBudget: async (size: number, signal: AbortSignal): Promise<boolean> => {
        if (size > this.limit) return false;
        signal.throwIfAborted();
        if (grow(size)) return true;
        return await new Promise<boolean>((resolve, reject) => {
          const cleanup = () => {
            this.waiters.delete(wake);
            signal.removeEventListener("abort", abort);
          };
          const wake = () => {
            if (grow(size)) { cleanup(); resolve(true); }
          };
          const abort = () => { cleanup(); reject(signal.reason); };
          this.waiters.add(wake);
          signal.addEventListener("abort", abort, { once: true });
        });
      },
      release: () => {
        this.count--;
        this.bytes -= held;
        for (const wake of this.waiters) wake();
      },
    };
  }
}
