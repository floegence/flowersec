/** Private provider facts. Neither signal is an authenticated terminal proof. */
export class NativeDirectionFailure extends Error {
  constructor(readonly code: "normal_drained" | "direction_reset") {
    super(code); this.name = "NativeDirectionFailure";
  }
}
