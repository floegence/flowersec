import type { ChildProcess } from "node:child_process";

export type ProcessExit = {
  code: number | null;
  signal: NodeJS.Signals | null;
};

// createExitPromise resolves once the process exits or is already exited.
export function createExitPromise(proc: ChildProcess): Promise<ProcessExit> {
  if (proc.exitCode != null || proc.signalCode != null) {
    return Promise.resolve({ code: proc.exitCode, signal: proc.signalCode });
  }
  return new Promise<ProcessExit>((resolve, reject) => {
    const onExit = (code: number | null, signal: NodeJS.Signals | null) => {
      cleanup();
      resolve({ code, signal });
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const cleanup = () => {
      proc.off("exit", onExit);
      proc.off("error", onError);
    };
    proc.once("exit", onExit);
    proc.once("error", onError);
  });
}
