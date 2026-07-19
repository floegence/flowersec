import { promises as fs } from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export type BrowserModuleSite = Readonly<{
  origin: string;
  close: () => Promise<void>;
}>;

export async function startBrowserModuleSite(): Promise<BrowserModuleSite> {
  const distRoot = path.join(packageRoot, "dist");
  const nobleModulesRoot = path.join(packageRoot, "node_modules", "@noble");
  const server = http.createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname === "/") {
        response.writeHead(200, {
          "cache-control": "no-store",
          "content-type": "text/html; charset=utf-8",
        });
        response.end(browserPage());
        return;
      }
      if (url.pathname.startsWith("/dist/")) {
        const relative = decodeURIComponent(url.pathname.slice("/dist/".length));
        const file = path.resolve(distRoot, relative);
        if (!file.startsWith(distRoot + path.sep)) {
          response.writeHead(404).end();
          return;
        }
        const contents = await fs.readFile(file);
        response.writeHead(200, {
          "cache-control": "no-store",
          "content-type": file.endsWith(".json")
            ? "application/json; charset=utf-8"
            : "text/javascript; charset=utf-8",
        });
        response.end(contents);
        return;
      }
      if (url.pathname.startsWith("/node_modules/@noble/")) {
        const relative = decodeURIComponent(url.pathname.slice("/node_modules/@noble/".length));
        let file = path.resolve(nobleModulesRoot, relative);
        if (!file.startsWith(nobleModulesRoot + path.sep)) {
          response.writeHead(404).end();
          return;
        }
        let contents: Buffer;
        try {
          contents = await fs.readFile(file);
        } catch (error) {
          if (path.extname(file) !== "" || !isMissingFileError(error)) throw error;
          file += ".js";
          contents = await fs.readFile(file);
        }
        response.writeHead(200, {
          "cache-control": "no-store",
          "content-type": "text/javascript; charset=utf-8",
        });
        response.end(contents);
        return;
      }
      response.writeHead(404).end();
    } catch {
      response.writeHead(404).end();
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (address == null || typeof address === "string") {
    server.close();
    throw new Error("browser E2E server did not bind TCP");
  }

  let closePromise: Promise<void> | undefined;
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () => {
      closePromise ??= new Promise<void>((resolve, reject) => {
        server.close((error) => error == null ? resolve() : reject(error));
        server.closeAllConnections?.();
      });
      return closePromise;
    },
  };
}

function browserPage(): string {
  return `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Flowersec browser E2E</title>
    <script type="importmap">
      {
        "imports": {
          "@noble/ciphers/aes": "/node_modules/@noble/ciphers/esm/aes.js",
          "@noble/ciphers/crypto": "/node_modules/@noble/ciphers/esm/crypto.js",
          "@noble/ciphers/": "/node_modules/@noble/ciphers/esm/",
          "@noble/curves/ed25519": "/node_modules/@noble/curves/esm/ed25519.js",
          "@noble/curves/p256": "/node_modules/@noble/curves/esm/p256.js",
          "@noble/curves/": "/node_modules/@noble/curves/esm/",
          "@noble/hashes/hkdf": "/node_modules/@noble/hashes/esm/hkdf.js",
          "@noble/hashes/hmac": "/node_modules/@noble/hashes/esm/hmac.js",
          "@noble/hashes/sha256": "/node_modules/@noble/hashes/esm/sha256.js",
          "@noble/hashes/utils": "/node_modules/@noble/hashes/esm/utils.js",
          "@noble/hashes/": "/node_modules/@noble/hashes/esm/"
        }
      }
    </script>
  </head>
  <body></body>
</html>`;
}

function isMissingFileError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error && error.code === "ENOENT";
}
