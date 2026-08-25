export * from "../facade.js";
export * as v2 from "./v2.js";
export {
  connectV3 as connect,
  createConnectionControllerV3 as createConnectionController,
} from "./connectSessionV3.js";
/** @deprecated Use connect and createConnectionController. */
export { connectV3, createConnectionControllerV3 } from "./connectSessionV3.js";
export type {
  ConnectionControllerOptionsV3 as ConnectionControllerOptions,
  SessionOptionsV3 as SessionOptions,
} from "./connectSessionV3.js";
/** @deprecated Use ConnectionControllerOptions and SessionOptions. */
export type { ConnectionControllerOptionsV3, SessionOptionsV3 } from "./connectSessionV3.js";
