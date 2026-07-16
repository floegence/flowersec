#!/usr/bin/env node

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..");
const manifestPath = resolve(repoRoot, "assets/readme/locales.json");
const selectorStart = "<!-- readme-locales:start -->";
const selectorEnd = "<!-- readme-locales:end -->";

function fail(errors) {
  for (const error of errors) process.stderr.write(`readme localization: ${error}\n`);
  process.exit(1);
}

function stripSelector(content) {
  const start = content.indexOf(selectorStart);
  const end = content.indexOf(selectorEnd);
  if (start < 0 || end < start) return content;
  return `${content.slice(0, start)}${content.slice(end + selectorEnd.length)}`;
}

function extractSelectorEntries(content) {
  const start = content.indexOf(selectorStart);
  const end = content.indexOf(selectorEnd);
  if (start < 0 || end < start) return null;
  const block = content.slice(start + selectorStart.length, end);
  const entries = [];
  const pattern = /<a href="([^"]+)">([^<]+)<\/a>|<strong>([^<]+)<\/strong>/g;
  for (const match of block.matchAll(pattern)) {
    entries.push(match[1]
      ? { type: "link", file: match[1], name: match[2].trim() }
      : { type: "current", name: match[3].trim() });
  }
  return entries;
}

function extractCodeBlocks(content) {
  const blocks = [];
  const pattern = /```([^\n]*)\n([\s\S]*?)\n```/g;
  for (const match of stripSelector(content).matchAll(pattern)) {
    const info = match[1].trim();
    const body = info === "bash"
      ? match[2].split("\n").filter((line) => line.trim() !== "" && !/^\s*#/.test(line)).join("\n")
      : match[2];
    blocks.push({ info, body });
  }
  return blocks;
}

function extractLinkTargets(content) {
  const targets = [];
  const text = stripSelector(content);
  for (const match of text.matchAll(/!?\[[^\]]*\]\(([^)\s]+)(?:\s+["'][^"']*["'])?\)/g)) targets.push(match[1]);
  for (const match of text.matchAll(/\b(?:href|src)="([^"]+)"/g)) targets.push(match[1]);
  return targets.sort();
}

function extractHeadingLevels(content) {
  const levels = [];
  let fence = false;
  for (const line of content.replace(/\r\n/g, "\n").split("\n")) {
    if (/^```/.test(line)) {
      fence = !fence;
      continue;
    }
    if (fence) continue;
    const match = /^(#{1,6})\s+/.exec(line);
    if (match) levels.push(match[1].length);
  }
  return levels;
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const sourcePath = resolve(repoRoot, manifest.source.file);
const source = readFileSync(sourcePath, "utf8");
const sourceCodeBlocks = JSON.stringify(extractCodeBlocks(source));
const sourceLinks = JSON.stringify(extractLinkTargets(source));
const expectedHeadingLevels = JSON.stringify([1, ...manifest.sections.map((section) => section.level)]);
const errors = [];

const expectedRootReadmes = manifest.locales.map((locale) => locale.file).sort();
const actualRootReadmes = readdirSync(repoRoot).filter((name) => /^README(?:\.[A-Za-z-]+)?\.md$/.test(name)).sort();
if (JSON.stringify(actualRootReadmes) !== JSON.stringify(expectedRootReadmes)) {
  errors.push(`root README files are ${JSON.stringify(actualRootReadmes)}; expected ${JSON.stringify(expectedRootReadmes)}`);
}

for (const locale of manifest.locales) {
  const readmePath = resolve(repoRoot, locale.file);
  if (!existsSync(readmePath)) {
    errors.push(`${locale.locale}: missing ${locale.file}`);
    continue;
  }
  const content = readFileSync(readmePath, "utf8");
  const selector = extractSelectorEntries(content);
  if (!selector || selector.length !== manifest.locales.length) {
    errors.push(`${locale.locale}: language selector is missing or incomplete`);
  } else {
    manifest.locales.forEach((expected, index) => {
      const actual = selector[index];
      if (expected.locale === locale.locale) {
        if (actual.type !== "current" || actual.name !== expected.native_name) {
          errors.push(`${locale.locale}: selector must mark ${expected.native_name} as current`);
        }
      } else if (actual.type !== "link" || actual.file !== expected.file || actual.name !== expected.native_name) {
        errors.push(`${locale.locale}: selector entry ${index + 1} must link ${expected.native_name} to ${expected.file}`);
      }
    });
  }

  const markerIds = [...content.matchAll(/<!-- readme-section:([a-z0-9-]+) -->/g)].map((match) => match[1]);
  const expectedIds = manifest.sections.map((section) => section.id);
  if (JSON.stringify(markerIds) !== JSON.stringify(expectedIds)) {
    errors.push(`${locale.locale}: section markers differ from the canonical order`);
  }
  for (const section of manifest.sections) {
    const sectionPattern = new RegExp(`<!-- readme-section:${section.id} -->\\s*<a id="${section.id}"><\\/a>\\s*#{${section.level}}\\s+[^\\n]+`);
    if (!sectionPattern.test(content)) errors.push(`${locale.locale}: section ${section.id} is missing its fixed anchor or heading`);
  }
  if (JSON.stringify(extractHeadingLevels(content)) !== expectedHeadingLevels) {
    errors.push(`${locale.locale}: heading levels differ from README.md`);
  }
  if (JSON.stringify(extractCodeBlocks(content)) !== sourceCodeBlocks) {
    errors.push(`${locale.locale}: executable code blocks differ from README.md`);
  }
  if (JSON.stringify(extractLinkTargets(content)) !== sourceLinks) {
    errors.push(`${locale.locale}: link or image targets differ from README.md`);
  }
  for (const literal of manifest.required_literals) {
    if (!content.includes(literal)) errors.push(`${locale.locale}: required literal is missing: ${literal}`);
  }
  for (const target of extractLinkTargets(content)) {
    if (/^(?:https?:|mailto:|#)/.test(target)) continue;
    const clean = target.split("#", 1)[0].split("?", 1)[0];
    if (clean && !existsSync(resolve(dirname(readmePath), clean))) {
      errors.push(`${locale.locale}: local target does not exist: ${target}`);
    }
  }
}

if (errors.length > 0) fail(errors);
process.stdout.write(`README localizations OK: ${manifest.locales.length} locales\n`);
