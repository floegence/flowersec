export type E2EEHandshakeErrorCode =
  | "auth_tag_mismatch"
  | "invalid_suite"
  | "invalid_version"
  | "timestamp_after_init_exp"
  | "timestamp_out_of_skew";

export class E2EEHandshakeError extends Error {
  readonly code: E2EEHandshakeErrorCode;

  constructor(code: E2EEHandshakeErrorCode, message: string) {
    super(message);
    this.name = "E2EEHandshakeError";
    this.code = code;
  }
}
