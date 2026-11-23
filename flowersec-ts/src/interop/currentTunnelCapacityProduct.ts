import { serveCapacityDeployment } from './currentCapacityProduct.js';
import { CurrentTunnelCapacityWorker } from './currentTunnelCapacityWorker.js';

try { await serveCapacityDeployment(CurrentTunnelCapacityWorker.create); }
catch (error) { console.error(error); process.exitCode = 1; }
