export class AdmissionSessionV3Error extends Error {
  constructor(readonly reason: string, message: string) {
    super(message);
    this.name = "AdmissionSessionV3Error";
  }
}
