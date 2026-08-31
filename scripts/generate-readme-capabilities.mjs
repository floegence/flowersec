#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const registryPath = path.join(root, "stability", "language_capabilities.json");
const localeManifestPath = path.join(root, "assets", "readme", "locales.json");
const labelsPath = path.join(root, "assets", "readme", "capability-labels.json");
const check = process.argv.includes("--check");
if (process.argv.length !== (check ? 3 : 2)) {
  throw new Error("usage: scripts/generate-readme-capabilities.mjs [--check]");
}

const registry = JSON.parse(fs.readFileSync(registryPath, "utf8"));
const localeManifest = JSON.parse(fs.readFileSync(localeManifestPath, "utf8"));
const translations = JSON.parse(fs.readFileSync(labelsPath, "utf8"));
const markerPattern = /<!-- capability-table:start -->[\s\S]*?<!-- capability-table:end -->/u;
const initialTablePattern = /\|[^\n]+\| Go \| TypeScript \| Swift \| Rust \|\n\| --- \| :---: \| :---: \| :---: \| :---: \|\n(?:\|[^\n]+\|\n?){16}/u;
let stale = false;

for (const locale of localeManifest.locales) {
  const translation = translations[locale.locale];
  if (translation === undefined) {
    throw new Error(`capability labels missing for ${locale.locale}`);
  }
  const rows = registry.portable_capabilities.map((capability) => {
    const label = translation.labels[capability.id];
    if (label === undefined) {
      throw new Error(`capability label missing for ${locale.locale}:${capability.id}`);
    }
    const cells = registry.languages.map((language) =>
      capability.implementations[language]?.status === "supported"
        ? translation.supported
        : translation.unsupported
    );
    return `| ${label} | ${cells.join(" | ")} |`;
  });
  const generated = [
    "<!-- capability-table:start -->",
    `| ${translation.header} | Go | TypeScript | Swift | Rust |`,
    "| --- | :---: | :---: | :---: | :---: |",
    ...rows,
    "<!-- capability-table:end -->",
  ].join("\n");
  const readmePath = path.join(root, locale.file);
  const source = fs.readFileSync(readmePath, "utf8");
  const pattern = markerPattern.test(source) ? markerPattern : initialTablePattern;
  if (!pattern.test(source)) {
    throw new Error(`${locale.file} capability table is missing`);
  }
  const updated = source.replace(pattern, generated);
  if (updated !== source) {
    stale = true;
    if (!check) fs.writeFileSync(readmePath, updated);
  }
}

if (check && stale) {
  throw new Error("localized README capability tables are stale");
}
process.stdout.write(
  `README capability tables ${check ? "verified" : "generated"}: `
    + `${registry.portable_capabilities.length} rows across ${localeManifest.locales.length} locales\n`,
);
