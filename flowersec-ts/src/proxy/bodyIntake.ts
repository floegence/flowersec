export class BodyIntake {
  private count = 0;
  private bytes = 0;

  constructor(private readonly slots: number, private readonly limit: number) {}

  begin() {
    if (this.count >= this.slots) return undefined;
    this.count++;
    let held = 0;
    return {
      grow: (size: number) => {
        if (this.bytes + size > this.limit) return false;
        this.bytes += size;
        held += size;
        return true;
      },
      release: () => { this.count--; this.bytes -= held; },
    };
  }
}
