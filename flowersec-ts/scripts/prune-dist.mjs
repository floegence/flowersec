import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import ts from "typescript";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = path.join(packageRoot, "dist");
const entrypoints = [
  "facade.js",
  "facade.d.ts",
  "browser/index.js",
  "browser/index.d.ts",
  "node/index.js",
  "node/index.d.ts",
].map((file) => path.join(distRoot, file));
const retained = new Set();
const pending = [...entrypoints];

while (pending.length > 0) {
  const file = pending.pop();
  if (file === undefined || retained.has(file)) continue;
  if (!fs.existsSync(file)) throw new Error(`missing package entrypoint ${path.relative(distRoot, file)}`);
  retained.add(file);
  const source = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
  for (const specifier of moduleSpecifiers(source)) {
    if (!specifier.startsWith(".")) continue;
    const dependency = resolveDependency(file, specifier);
    if (dependency !== undefined) pending.push(dependency);
  }
}

for (const file of walk(distRoot)) {
  if ((file.endsWith(".js") || file.endsWith(".d.ts")) && !retained.has(file)) fs.rmSync(file);
}
removeEmptyDirectories(distRoot);

function moduleSpecifiers(source) {
  const specifiers = [];
  const visit = (node) => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) &&
        node.moduleSpecifier !== undefined && ts.isStringLiteral(node.moduleSpecifier)) {
      specifiers.push(node.moduleSpecifier.text);
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword &&
               node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
      specifiers.push(node.arguments[0].text);
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return specifiers;
}

function resolveDependency(importer, specifier) {
  const resolved = path.resolve(path.dirname(importer), specifier);
  const candidates = importer.endsWith(".d.ts")
    ? [resolved.replace(/\.js$/, ".d.ts"), `${resolved}.d.ts`, resolved]
    : [resolved, `${resolved}.js`];
  return candidates.find((candidate) => fs.existsSync(candidate));
}

function walk(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const resolved = path.join(directory, entry.name);
    return entry.isDirectory() ? walk(resolved) : [resolved];
  });
}

function removeEmptyDirectories(directory) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) removeEmptyDirectories(path.join(directory, entry.name));
  }
  if (directory !== distRoot && fs.readdirSync(directory).length === 0) fs.rmdirSync(directory);
}
