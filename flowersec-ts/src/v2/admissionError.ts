export class AdmissionSessionV2Error extends Error {
  constructor(readonly reason: string, message: string) {
    super(message);
    this.name = "AdmissionSessionV2Error";
  }
}
