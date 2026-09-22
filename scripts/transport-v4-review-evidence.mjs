import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";

export const architectureReviewLanes = Object.freeze([
  "protocol", "crypto", "carriers", "resources", "sdk", "ledgers", "adversarial",
]);

// This checks declared provenance and integrity in independently obtained reports.
// The collecting agent must separately verify their actual reviewer-tool origin.
// It neither creates votes nor grants implementation or release qualification.
export function verifyArchitectureReviews(evidencePath, designSHA) {
  const evidence = JSON.parse(fs.readFileSync(evidencePath, "utf8"));
  assert.equal(evidence.format_version, 1, "unsupported review evidence format");
  assert.equal(evidence.design_sha256, designSHA, "reviewed design SHA differs");
  assert.equal(evidence.qualification, "architecture_only");
  assert.match(evidence.round, /^[a-z0-9][a-z0-9-]{0,63}$/u);
  assert.ok(Array.isArray(evidence.reviews), "missing review reports");
  assert.equal(evidence.reviews.length, architectureReviewLanes.length, "seven independent reviews required");
  assert.deepEqual(evidence.reviews.map((review) => review.lane).sort(), [...architectureReviewLanes].sort(), "review lane coverage differs");
  const reviewers = new Set(), reports = new Set(), reportHashes = new Set();
  for (const review of evidence.reviews) {
    assert.match(review.reviewer, /^\/root\/[a-z0-9_]+$/u, "reviewer identity required");
    assert.ok(!reviewers.has(review.reviewer), "reviewer reused across lanes");
    reviewers.add(review.reviewer);
    assert.equal(review.round, evidence.round, "review round differs");
    assert.equal(review.design_before_sha256, designSHA, "review before SHA differs");
    assert.equal(review.design_after_sha256, designSHA, "review after SHA differs");
    assert.equal(review.verdict, "SIGNABLE", `architecture blocker in ${review.lane}`);
    // Reports live beside the external index. Never resolve arbitrary paths.
    assert.match(review.path, /^[a-z0-9][a-z0-9-]*\.md$/u, "invalid external report path");
    assert.ok(!reports.has(review.path), "report reused across lanes");
    reports.add(review.path);
    assert.match(review.sha256, /^[a-f0-9]{64}$/u);
    assert.ok(!reportHashes.has(review.sha256), "report content reused across lanes");
    reportHashes.add(review.sha256);
    const file = path.join(path.dirname(evidencePath), review.path);
    assert.ok(fs.existsSync(file), `review report unavailable: ${review.path}`);
    const bytes = fs.readFileSync(file);
    assert.equal(createHash("sha256").update(bytes).digest("hex"), review.sha256, `review report SHA changed: ${review.path}`);
    const lines = bytes.toString("utf8").split(/\r?\n/u);
    for (const [prefix, expected] of [
      ["SIGNABLE ", designSHA], ["Before SHA: ", designSHA], ["After SHA: ", designSHA],
      ["Round: ", evidence.round], ["Reviewer: ", review.reviewer], ["Lane: ", review.lane],
    ]) {
      assert.deepEqual(lines.filter((line) => line.startsWith(prefix)), [prefix + expected], `missing or ambiguous ${prefix.trim()} in ${review.path}`);
    }
    assert.ok(!lines.some((line) => line.startsWith("NOT_SIGNABLE ")), `conflicting verdict in ${review.path}`);
  }
  return {round:evidence.round, reviews:evidence.reviews.length, qualification:evidence.qualification};
}
