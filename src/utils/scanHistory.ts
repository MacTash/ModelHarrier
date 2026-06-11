import type { Report } from "../App";

export interface ScanHistoryEntry {
  modelId: string;
  timestamp: string;
  severity: Report["severity"];
  overallScore: number;
  library: string;
  author: string;
}

const HISTORY_KEY = "aieye_scan_history";

export function loadScanHistory(): ScanHistoryEntry[] {
  try {
    const data = localStorage.getItem(HISTORY_KEY);
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export function saveScanHistory(entries: ScanHistoryEntry[]) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(-50)));
}

export function addToScanHistory(report: Report) {
  const entry: ScanHistoryEntry = {
    modelId: report.modelId,
    timestamp: new Date().toISOString(),
    severity: report.severity,
    overallScore: report.scores.overallScore,
    library: report.library,
    author: report.author,
  };
  const entries = loadScanHistory();
  const existing = entries.findIndex((e) => e.modelId === report.modelId);
  if (existing >= 0) entries.splice(existing, 1);
  entries.unshift(entry);
  saveScanHistory(entries);
}

export function clearScanHistory() {
  localStorage.removeItem(HISTORY_KEY);
}
