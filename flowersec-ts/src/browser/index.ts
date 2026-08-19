export * from "../facade.js";
export * as v2 from "./v2.js";
export {
  connectV3 as connect,
  connectV3,
  createConnectionControllerV3 as createConnectionController,
  createConnectionControllerV3,
} from "./connectSessionV3.js";
export type {
  ConnectionControllerOptionsV3 as ConnectionControllerOptions,
  ConnectionControllerOptionsV3,
  SessionOptionsV3 as SessionOptions,
  SessionOptionsV3,
} from "./connectSessionV3.js";
