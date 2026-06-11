import type { ProbeResult } from "../components/RedTeamPlaybook";

const PROBE_KEY_PREFIX = "aieye_probe_results_";

export function loadProbeResults(modelId: string): ProbeResult[] {
  try {
    const data = localStorage.getItem(PROBE_KEY_PREFIX + modelId);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export function saveProbeResults(modelId: string, results: ProbeResult[]) {
  localStorage.setItem(PROBE_KEY_PREFIX + modelId, JSON.stringify(results));
}
