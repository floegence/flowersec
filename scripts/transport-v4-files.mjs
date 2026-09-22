import path from "node:path";
import { createHash } from "node:crypto";

// Lightweight binding checks must not import SDK or fixture dependencies.
export const repositoryRoot = path.resolve(import.meta.dirname, "..");
export const digest = bytes => createHash("sha256").update(bytes).digest("hex");
