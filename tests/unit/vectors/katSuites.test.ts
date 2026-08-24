import { describe, it, expect } from "vitest";
import { allKnownAnswerVectors } from "../../../lib/testVectors";

describe("NIST & RFC Known-Answer Test Vector Suite Compliance", () => {
  it("verifies that all test vectors specify authoritative standard sources", () => {
    allKnownAnswerVectors.forEach((vector) => {
      expect(vector.standard).toBeDefined();
      expect(vector.standard.length).toBeGreaterThan(0);
      expect(vector.algorithm).toBeDefined();
    });
  });

  it("covers boundary edge cases across vector suites", () => {
    const emptyVectors = allKnownAnswerVectors.filter((v) => v.edgeCase === "EMPTY_INPUT");
    const multiblockVectors = allKnownAnswerVectors.filter((v) => v.edgeCase === "MULTI_BLOCK");
    const boundaryKeyVectors = allKnownAnswerVectors.filter((v) => v.edgeCase === "BOUNDARY_KEY");

    expect(emptyVectors.length).toBeGreaterThan(0);
    expect(multiblockVectors.length).toBeGreaterThan(0);
    expect(boundaryKeyVectors.length).toBeGreaterThan(0);
  });
});