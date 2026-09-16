export function encryptedWorkspaceEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_ENCRYPTED_WORKSPACE_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function investigationsEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_INVESTIGATIONS_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function genericAgentImportEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_GENERIC_AGENT_IMPORT_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function apiBoundaryEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_API_BOUNDARY_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function arcObservationEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_ARC_OBSERVATION_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function agentRegistryEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_AGENT_REGISTRY_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function agentJobsEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_AGENT_JOBS_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function gatewayEvidenceEnabled(
  value: string | boolean | undefined = import.meta.env.VITE_GATEWAY_EVIDENCE_ENABLED,
): boolean {
  return value === true || value === "true";
}

export function workspaceSectionUsesNetwork(id: string, flags: {
  apiBoundary: boolean; arcObservation: boolean; agentRegistry: boolean; agentJobs: boolean; gatewayEvidence?: boolean;
  /** P04-06c: the purchase review reads the control API, not an Arc source. */
  purchaseReview?: boolean;
}): boolean {
  if (!flags.apiBoundary) return false;
  if (id === "sources-title") return true;
  // The purchase review depends on the commerce-action gate, never on Arc
  // observation, so it is decided before the observation chain below.
  if (id === "purchases-title") return flags.purchaseReview === true;
  if (!flags.arcObservation) return false;
  if (id === "activity-title") return true;
  if (!flags.agentRegistry) return false;
  return id === "agents-title" || (id === "jobs-title" && flags.agentJobs) ||
    (id === "payments-title" && flags.agentJobs && flags.gatewayEvidence === true);
}
