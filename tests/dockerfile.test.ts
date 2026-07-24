import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("Docker production build context", () => {
  it("copies the build-time asset script and assets before npm run build", () => {
    const dockerfile = readFileSync("Dockerfile", "utf8");
    const buildCommandIndex = dockerfile.indexOf("RUN npm run build");
    const copyScriptIndex = dockerfile.indexOf("COPY scripts/copy-assets.mjs ./scripts/copy-assets.mjs");
    const copyAssetsIndex = dockerfile.indexOf("COPY assets ./assets");

    expect(buildCommandIndex).toBeGreaterThan(-1);
    expect(copyScriptIndex).toBeGreaterThan(-1);
    expect(copyAssetsIndex).toBeGreaterThan(-1);
    expect(copyScriptIndex).toBeLessThan(buildCommandIndex);
    expect(copyAssetsIndex).toBeLessThan(buildCommandIndex);
  });
});
