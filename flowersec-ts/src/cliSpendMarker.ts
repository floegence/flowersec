import { closeSync, fsyncSync, openSync } from "node:fs";
import { dirname } from "node:path";

export function claimSpendMarker(path: string): void {
  let descriptor: number;
  try {
    descriptor = openSync(path, "wx", 0o600);
  } catch (error) {
    if (isErrnoException(error) && error.code === "EEXIST") {
      throw new Error(`spend marker already exists: ${path}`, { cause: error });
    }
    throw error;
  }
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  const directory = openSync(dirname(path), "r");
  try {
    fsyncSync(directory);
  } finally {
    closeSync(directory);
  }
}

function isErrnoException(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
