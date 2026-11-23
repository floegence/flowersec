import { readFileSync } from "node:fs";
import { expect, test } from "vitest";

import { decodeArtifactV3JSON, encodeArtifactV3JSON } from "./artifact.js";

const vectors = JSON.parse(readFileSync(
  new URL("../../../testdata/transport_v5/artifact_vectors.json", import.meta.url), "utf8",
)) as { positive: { id: string; artifact_json: string }[] };

test.each(vectors.positive)("$id requires canonical input and validates the object supplied for encoding", (vector) => {
  const artifact = decodeArtifactV3JSON(vector.artifact_json);
  expect(new TextDecoder().decode(encodeArtifactV3JSON(artifact))).toBe(vector.artifact_json);
  expect(() => decodeArtifactV3JSON(` ${vector.artifact_json}`)).toThrowError(/non-canonical JCS/);
  expect(() => encodeArtifactV3JSON({
    ...artifact,
    session: { ...artifact.session, channel_id: `${artifact.session.channel_id}-changed` },
  })).toThrowError(/session contract hash/);
});
