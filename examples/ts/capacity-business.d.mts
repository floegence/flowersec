import type { Session } from '@floegence/flowersec-core/node';
import { ParityEndpoint } from './parity.mjs';

export const capacityFrameBytes: number;
export class CapacityParityEndpoint extends ParityEndpoint {}
export function runCapacityBusiness(client: Session, server: Session, operation: 'echo' | 'raw', size: number, deadline: AbortSignal): Promise<{
  operation: 'echo' | 'raw'; requestBytes: number; responseBytes: number; verified: boolean;
}>;
