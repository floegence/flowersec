import type { Client } from "../client.js";

export type ClientTermination = Readonly<{ error: Error }>;

const clientTerminations = new WeakMap<Client, Promise<ClientTermination>>();

export function registerClientTermination(client: Client, termination: Promise<ClientTermination>): void {
  clientTerminations.set(client, termination);
}

export function getClientTermination(client: Client): Promise<ClientTermination> | undefined {
  return clientTerminations.get(client);
}
