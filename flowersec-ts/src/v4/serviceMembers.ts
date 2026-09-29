/** Single local member table for TS definition validation and generated service
 * clients. Names are local selectors only and never enter a wire digest. */
export const serviceClientMembers = Object.freeze([
  "then", "close", "info", "contract", "refresh", "cleanupStatus", "waitCleanup", "updateContract", "prepareOperation", "prepareAndSave", "call", "stream", "notify",
  "constructor", "prototype", "__proto__", "toString", "toJSON", "valueOf", "hasOwnProperty", "isPrototypeOf",
  "propertyIsEnumerable", "toLocaleString", "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__",
] as const);
const members = new Set<string>(serviceClientMembers);
export function checkServiceExportName(name: string): void {
  if (typeof name !== "string" || name.length < 1 || name.length > 128 || !/^[$A-Za-z_][$\w]*$/u.test(name) || members.has(name)) throw new Error("service_member_conflict");
}
