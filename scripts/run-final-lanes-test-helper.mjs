#!/usr/bin/env node

import fs from "node:fs";

const contract = process.argv[2] ?? "";
if (contract.startsWith("fail:")) {
  setTimeout(() => process.exit(Number(contract.slice("fail:".length))), 100);
} else if (contract.startsWith("wait:")) {
  const marker = contract.slice("wait:".length);
  process.on("SIGTERM", () => {
    fs.writeFileSync(marker, "stopped\n");
    process.exit(0);
  });
  setInterval(() => {}, 1_000);
} else {
  process.exit(2);
}
