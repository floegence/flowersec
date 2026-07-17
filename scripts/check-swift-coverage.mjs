import fs from "node:fs";
import path from "node:path";

const [coveragePath, linesRaw = "75", functionsRaw = "75"] = process.argv.slice(2);
if (!coveragePath) throw new Error("usage: check-swift-coverage.mjs <coverage.json> [min-lines] [min-functions]");

const minimumLines = Number(linesRaw);
const minimumFunctions = Number(functionsRaw);
const report = JSON.parse(fs.readFileSync(coveragePath, "utf8"));
const sourceSegment = `${path.sep}flowersec-swift${path.sep}Sources${path.sep}Flowersec${path.sep}`;
const files = (report.data?.[0]?.files ?? []).filter((file) => String(file.filename).includes(sourceSegment));
if (files.length === 0) throw new Error("Swift coverage report contains no Flowersec source files");

const totals = files.reduce((sum, file) => {
  sum.lines.count += Number(file.summary?.lines?.count ?? 0);
  sum.lines.covered += Number(file.summary?.lines?.covered ?? 0);
  sum.functions.count += Number(file.summary?.functions?.count ?? 0);
  sum.functions.covered += Number(file.summary?.functions?.covered ?? 0);
  return sum;
}, {
  lines: { count: 0, covered: 0 },
  functions: { count: 0, covered: 0 },
});

function percentage(metric) {
  return metric.count === 0 ? 100 : (metric.covered * 100) / metric.count;
}

const linePercent = percentage(totals.lines);
const functionPercent = percentage(totals.functions);
console.log(`Swift coverage: lines ${linePercent.toFixed(2)}%, functions ${functionPercent.toFixed(2)}% (${files.length} files)`);

if (linePercent < minimumLines || functionPercent < minimumFunctions) {
  throw new Error(`Swift coverage is below the required lines/functions thresholds (${minimumLines}%/${minimumFunctions}%)`);
}
