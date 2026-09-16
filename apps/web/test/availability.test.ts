import { describe, expect, it } from "vitest";

import { genericAgentImportEnabled, gatewayEvidenceEnabled, agentJobsEnabled, agentRegistryEnabled, apiBoundaryEnabled, arcObservationEnabled, encryptedWorkspaceEnabled, workspaceSectionUsesNetwork } from "../src/app/availability.js";

describe("local agent import availability", () => {
  it("fails closed and never claims network activity", () => {
    for (const value of [undefined, "false", "TRUE", "1", false]) expect(genericAgentImportEnabled(value)).toBe(false);
    expect(genericAgentImportEnabled(true)).toBe(true);
    expect(genericAgentImportEnabled("true")).toBe(true);
    expect(workspaceSectionUsesNetwork("agent-reports-title", {
      apiBoundary: true, arcObservation: true, agentRegistry: true, agentJobs: true, gatewayEvidence: true,
    })).toBe(false);
  });
});

describe("encrypted workspace availability", () => {
  it("fails closed unless the build flag is exactly true", () => {
    expect(encryptedWorkspaceEnabled(undefined)).toBe(false);
    expect(encryptedWorkspaceEnabled("false")).toBe(false);
    expect(encryptedWorkspaceEnabled("TRUE")).toBe(false);
    expect(encryptedWorkspaceEnabled("1")).toBe(false);
    expect(encryptedWorkspaceEnabled("true")).toBe(true);
    expect(encryptedWorkspaceEnabled(true)).toBe(true);
  });
});

describe("API boundary availability", () => {
  it("fails closed unless the build flag is exactly true", () => {
    for (const value of [undefined, "false", "TRUE", "1", false]) expect(apiBoundaryEnabled(value)).toBe(false);
    expect(apiBoundaryEnabled("true")).toBe(true);
    expect(apiBoundaryEnabled(true)).toBe(true);
  });
});

describe("Arc observation availability", () => {
  it("fails closed unless the build flag is exactly true", () => {
    for (const value of [undefined, "false", "TRUE", "1", false]) expect(arcObservationEnabled(value)).toBe(false);
    expect(arcObservationEnabled("true")).toBe(true);
    expect(arcObservationEnabled(true)).toBe(true);
  });
});

describe("agent registry availability", () => {
  it("fails closed unless the build flag is exactly true", () => {
    for (const value of [undefined, "false", "TRUE", "1", false]) expect(agentRegistryEnabled(value)).toBe(false);
    expect(agentRegistryEnabled("true")).toBe(true);
    expect(agentRegistryEnabled(true)).toBe(true);
  });
});

describe("job evidence availability", () => {
  it("fails closed unless the build flag is exactly true", () => {
    for (const value of [undefined, "false", "TRUE", "1", false]) expect(agentJobsEnabled(value)).toBe(false);
    expect(agentJobsEnabled("true")).toBe(true);
    expect(agentJobsEnabled(true)).toBe(true);
  });
});

describe("workspace section network claims", () => {
  it("keeps Gateway disabled for malformed flags and incomplete prerequisites", () => {
    for (const value of [undefined, "false", "TRUE", "1", false]) expect(gatewayEvidenceEnabled(value)).toBe(false);
    expect(gatewayEvidenceEnabled("true")).toBe(true);
    expect(gatewayEvidenceEnabled(true)).toBe(true);
    for (const apiBoundary of [false, true]) for (const arcObservation of [false, true])
      for (const agentRegistry of [false, true]) for (const agentJobs of [false, true])
        for (const gatewayEvidence of [false, true]) {
          expect(workspaceSectionUsesNetwork("payments-title", { apiBoundary, arcObservation, agentRegistry, agentJobs, gatewayEvidence }))
            .toBe(apiBoundary && arcObservation && agentRegistry && agentJobs && gatewayEvidence);
        }
  });
  it("only describes lookups when every cumulative feature gate is enabled", () => {
    for (const apiBoundary of [false, true]) for (const arcObservation of [false, true])
      for (const agentRegistry of [false, true]) for (const agentJobs of [false, true]) {
        const flags = { apiBoundary, arcObservation, agentRegistry, agentJobs };
        expect(workspaceSectionUsesNetwork("sources-title", flags)).toBe(apiBoundary);
        expect(workspaceSectionUsesNetwork("activity-title", flags)).toBe(apiBoundary && arcObservation);
        expect(workspaceSectionUsesNetwork("agents-title", flags)).toBe(apiBoundary && arcObservation && agentRegistry);
        expect(workspaceSectionUsesNetwork("jobs-title", flags)).toBe(apiBoundary && arcObservation && agentRegistry && agentJobs);
        expect(workspaceSectionUsesNetwork("policies-title", flags)).toBe(false);
      }
  });
  /**
   * P04-06c. The purchase review reads the control API under the commerce
   * action gate, never an Arc source, so it claims lookups on exactly that
   * gate and never inherits the observation chain.
   */
  it("claims purchase lookups on the commerce gate alone, and never without the API boundary", () => {
    for (const apiBoundary of [false, true]) for (const arcObservation of [false, true])
      for (const agentRegistry of [false, true]) for (const purchaseReview of [false, true]) {
        const flags = { apiBoundary, arcObservation, agentRegistry, agentJobs: false, purchaseReview };
        expect(workspaceSectionUsesNetwork("purchases-title", flags)).toBe(apiBoundary && purchaseReview);
      }
    // An omitted flag is an absent capability, never an assumed one.
    expect(workspaceSectionUsesNetwork("purchases-title", {
      apiBoundary: true, arcObservation: true, agentRegistry: true, agentJobs: true,
    })).toBe(false);
  });
});
