import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { build } from 'vite';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

await build({
  configFile: false,
  logLevel: 'error',
  build: {
    emptyOutDir: false,
    minify: false,
    target: 'es2022',
    lib: {
      entry: path.join(packageRoot, 'src', 'vendor', 'tr46.ts'),
      formats: ['es'],
      fileName: () => 'vendor/tr46.js',
    },
  },
});
