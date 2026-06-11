import React, { useState, useEffect, useCallback } from "react";
import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  FileText,
  Server,
  Moon,
  Sun,
  Lock,
  Unlock,
  Database,
  Code,
  AlertOctagon,
  Info,
  Terminal,
  Menu,
  Target,
  Cpu,
  Copy,
  Check,
  Clock,
} from "lucide-react";
import { Sidebar, SidebarTab } from './components/Sidebar';
import { exportReportAsPDF } from './utils/exportReport';
import { RedTeamPlaybook, ProbeResult } from './components/RedTeamPlaybook';
import { performStaticAnalysis, StaticAnalysisResult } from './utils/staticAnalysis';
import { detectSpaces, getKnownSpace } from './utils/spacesDetector';
import { VerificationDashboard } from './components/VerificationDashboard';
import { ReviewerMode, VerificationResult } from './components/ReviewerMode';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ToastContainer, ToastMessage } from './components/Toast';
import { addToScanHistory, loadScanHistory, clearScanHistory, ScanHistoryEntry } from './utils/scanHistory';
import { loadProbeResults, saveProbeResults } from './utils/probePersistence';

const RISKY_EXTENSIONS = [
  ".pickle", ".pkl", ".joblib", ".dill", ".exe", ".bin", ".dll",
];
const CODE_EXTENSIONS = [".py", ".sh", ".bash", ".js"];
const SAFE_EXTENSIONS = [
  ".safetensors", ".onnx", ".tflite", ".json", ".txt", ".md",
];
const SENSITIVE_DOMAINS = [
  "medical", "finance", "biometric", "legal", "surveillance",
];
const REDTEAM_KEYWORDS = [
  "uncensored", "no safety", "jailbreak", "do anything",
  "bypass restrictions", "no guardrails", "unrestricted",
  "unfiltered", "no ethics", "no censorship", "no limits",
];

export interface SecurityIssue {
  level: "Critical" | "High" | "Medium" | "Low" | "Info";
  type: string;
  message: string;
}
export interface ReportFiles {
  total: number;
  risky: string[];
  code: string[];
  safe: string[];
  unknown: string[];
}
export interface ReportScores {
  fileRisk: number;
  licenseRisk: number;
  vulnerabilityScore: number;
  overallScore: number;
}
export interface RedTeamInsights {
  score: number
  level: "Low" | "Medium" | "High"
  findings: string[]
}
export interface Report {
  modelId: string;
  author: string;
  downloads: number;
  likes: number;
  library: string;
  license: string;
  lastModified: string;
  files: ReportFiles;
  datasets: string[];
  securityIssues: SecurityIssue[];
  scores: ReportScores;
  severity: "Critical" | "High" | "Medium" | "Low";
  redTeamInsights?: RedTeamInsights;
  staticAnalysis?: StaticAnalysisResult;
  probeResults?: ProbeResult[];
}

const performSecurityScan = async (modelId: string): Promise<Report> => {
  try {
    const response = await fetch(
      `/api/scan?modelId=${encodeURIComponent(modelId)}`
    );

    if (!response.ok) {
      let errorMessage = `API Error: ${response.statusText || response.status}`;
      try {
        const errorData = await response.json();
        if (errorData.error) {
          errorMessage = errorData.error;
        }
      } catch {}
      throw new Error(errorMessage);
    }

    const data = await response.json();

    const report: Report = {
      modelId: data.modelId,
      author: data.author,
      downloads: data.downloads,
      likes: data.likes,
      library: data.library_name || "Unknown",
      license: data.cardData?.license || "Unknown",
      lastModified: data.lastModified,
      files: { total: 0, risky: [], code: [], safe: [], unknown: [] },
      datasets: data.cardData?.datasets || [],
      securityIssues: [],
      scores: { fileRisk: 0, licenseRisk: 0, vulnerabilityScore: 0, overallScore: 0 },
      severity: "Low",
    };

    if (data.siblings) {
      report.files.total = data.siblings.length;

      data.siblings.forEach((file: any) => {
        const filename = file.rfilename.toLowerCase();

        const risky = RISKY_EXTENSIONS.some((ext) => filename.endsWith(ext));
        const code = CODE_EXTENSIONS.some((ext) => filename.endsWith(ext));
        const safe = SAFE_EXTENSIONS.some((ext) => filename.endsWith(ext));

        if (risky) {
          report.files.risky.push(filename);
          report.securityIssues.push({
            level: "Critical",
            type: "Unsafe Serialization",
            message: `Unsafe file detected: ${filename}`,
          });
        } else if (code) {
          report.files.code.push(filename);
          report.securityIssues.push({
            level: "Medium",
            type: "Code Execution",
            message: `Executable code: ${filename}`,
          });
        } else if (safe) {
          report.files.safe.push(filename);
        } else {
          report.files.unknown.push(filename);
        }
      });
    }

    if (report.files.risky.length > 0) report.scores.fileRisk = 10;
    else if (report.files.code.length > 0) report.scores.fileRisk = 5;
    else report.scores.fileRisk = 1;

    const licenseText = report.license.toLowerCase();
    if (["unknown", "other"].includes(licenseText)) report.scores.licenseRisk = 7;
    else if (["mit", "apache", "openrail"].some((l) => licenseText.includes(l)))
      report.scores.licenseRisk = 0;
    else report.scores.licenseRisk = 4;

    const tags: string[] = data.tags || [];
    if (tags.some((tag) => SENSITIVE_DOMAINS.some((d) => tag.includes(d)))) {
      report.securityIssues.push({
        level: "Info",
        type: "Sensitive Domain",
        message: "Domain may require PII audit",
      });
    }

    const safetensors = report.files.safe.some((f) =>
      f.endsWith(".safetensors")
    );
    if (!safetensors && report.files.risky.length === 0) {
      report.securityIssues.push({
        level: "Low",
        type: "Modernization",
        message: "Consider converting model weights",
      });
    }

    const analyzeRedTeamRisk = (): RedTeamInsights => {
      const findings: string[] = [];
      let score = 0;
      const text = (data.cardData?.text || "").toLowerCase();
      const combined = text + " " + tags.join(" ");

      REDTEAM_KEYWORDS.forEach((k) => {
        if (combined.includes(k)) {
          findings.push(k);
          score += 15;
        }
      });

      if (combined.includes("bypass")) score += 25;
      if (combined.includes("uncensored")) score += 20;

      const level = score >= 60 ? "High" : score >= 30 ? "Medium" : "Low";
      if (findings.length === 0) findings.push("No signals detected");

      return { score, level, findings };
    };

    report.redTeamInsights = analyzeRedTeamRisk();

    const raw = report.scores.fileRisk * 6 + report.scores.licenseRisk * 2;
    report.scores.overallScore = Math.min(10, Math.ceil(raw / 8));

    if (report.scores.overallScore >= 8) report.severity = "Critical";
    else if (report.scores.overallScore >= 5) report.severity = "High";
    else if (report.scores.overallScore >= 3) report.severity = "Medium";

    return report;
  } catch (err) {
    console.error(err);
    throw err;
  }
};

interface HeaderProps {
  isDark: boolean;
  toggleTheme: () => void;
  onMenuClick: () => void;
  modelId?: string;
}

const Header: React.FC<HeaderProps> = ({ isDark, toggleTheme, onMenuClick, modelId }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (modelId) {
      await navigator.clipboard.writeText(modelId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <header className="flex justify-between items-center py-6 border-b border-gray-200 dark:border-gray-800 mb-8 transition-colors duration-300">
      <div className="flex items-center gap-3">
        <div className="bg-blue-600 p-2 rounded-lg">
          <Shield className="w-6 h-6 text-white" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-gray-900 dark:text-white">AI Eye</h1>
          <p className="text-xs text-gray-500 dark:text-gray-400">Model Security Scanner</p>
        </div>
      </div>
      <div className="flex items-center gap-3">
        {modelId && (
          <button
            onClick={handleCopy}
            className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 text-xs bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 rounded-lg transition-colors text-gray-600 dark:text-gray-300"
            title="Copy model ID"
          >
            {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
            {copied ? "Copied" : "Copy ID"}
          </button>
        )}
        <button
          onClick={onMenuClick}
          className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          title="Menu (Ctrl+K)"
          aria-label="Open menu"
        >
          <Menu className="w-5 h-5 text-gray-600 dark:text-gray-300" />
        </button>
        <button
          onClick={toggleTheme}
          className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          title="Toggle Theme"
          aria-label="Toggle theme"
        >
          {isDark ? <Sun className="w-5 h-5 text-yellow-400" /> : <Moon className="w-5 h-5 text-gray-600" />}
        </button>
      </div>
    </header>
  );
};

const SearchBar = ({ onScan, isLoading }: any) => {
  const [input, setInput] = useState("");
  const handleSubmit = (e: any) => {
    e.preventDefault();
    if (input.trim()) onScan(input.trim());
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-2xl mx-auto mb-6">
      <div className="relative flex items-center border border-gray-300 dark:border-gray-700 rounded-xl p-1 bg-white dark:bg-gray-900">
        <Search className="w-5 h-5 ml-4 text-gray-400" />

        <input
          type="text"
          className="w-full px-4 py-3 bg-transparent outline-none text-gray-900 dark:text-gray-100 placeholder-gray-400"
          placeholder="Enter HuggingFace model ID (e.g., 'gpt2', 'bert-base-uncased')"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          aria-label="Model ID"
        />

        <button
          type="submit"
          disabled={isLoading}
          className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg transition-all disabled:opacity-50"
        >
          {isLoading ? "Scanning..." : "Scan Model"}
        </button>
      </div>

      <div className="mt-3 flex gap-3 justify-center text-xs">
        <span className="cursor-pointer text-gray-500 hover:text-blue-500 dark:text-gray-400 dark:hover:text-blue-400" onClick={() => setInput('gpt2')}>Try: gpt2</span>
        <span className="text-gray-300 dark:text-gray-600">|</span>
        <span className="cursor-pointer text-gray-500 hover:text-blue-500 dark:text-gray-400 dark:hover:text-blue-400" onClick={() => setInput('runwayml/stable-diffusion-v1-5')}>Try: stable-diffusion-v1-5</span>
        <span className="text-gray-300 dark:text-gray-600">|</span>
        <span className="cursor-pointer text-gray-500 hover:text-blue-500 dark:text-gray-400 dark:hover:text-blue-400" onClick={() => setInput('bert-base-uncased')}>Try: bert-base-uncased</span>
      </div>
    </form>
  );
};

const ScanSkeleton = () => (
  <div className="animate-fade-in-up space-y-6">
    <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
        <div className="space-y-3 w-full">
          <div className="skeleton h-7 w-64 rounded-lg bg-gray-200 dark:bg-gray-700" />
          <div className="skeleton h-4 w-48 rounded bg-gray-200 dark:bg-gray-700" />
        </div>
        <div className="skeleton h-16 w-16 rounded-full bg-gray-200 dark:bg-gray-700" />
      </div>
    </div>
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {[1, 2, 3, 4].map((i) => (
        <div key={i} className="bg-white dark:bg-gray-800 p-5 rounded-xl border border-gray-200 dark:border-gray-700">
          <div className="skeleton h-10 w-10 rounded-lg bg-gray-200 dark:bg-gray-700 mb-3" />
          <div className="skeleton h-3 w-20 rounded bg-gray-200 dark:bg-gray-700 mb-2" />
          <div className="skeleton h-5 w-16 rounded bg-gray-200 dark:bg-gray-700" />
        </div>
      ))}
    </div>
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
      <div className="skeleton h-5 w-40 rounded bg-gray-200 dark:bg-gray-700 mb-4" />
      <div className="space-y-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="skeleton h-12 w-full rounded-lg bg-gray-200 dark:bg-gray-700" />
        ))}
      </div>
    </div>
  </div>
);

interface SeverityBadgeProps {
  level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
}

const SeverityBadge: React.FC<SeverityBadgeProps> = ({ level }) => {
  const colors = {
    'Critical': 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800',
    'High': 'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/30 dark:text-orange-400 dark:border-orange-800',
    'Medium': 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-800',
    'Low': 'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-400 dark:border-green-800',
    'Info': 'bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-400 dark:border-blue-800',
  };

  return (
    <span className={`px-3 py-1 rounded-full text-xs font-bold border ${colors[level] || colors['Info']}`}>
      {level.toUpperCase()}
    </span>
  );
};

interface StatCardProps {
  icon: React.ElementType;
  label: string;
  value: string | number;
  subtext?: string;
}

const StatCard: React.FC<StatCardProps> = ({ icon: Icon, label, value, subtext }) => (
  <div className="bg-white dark:bg-gray-800 p-5 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm flex items-start gap-4 transition-colors">
    <div className="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
      <Icon className="w-6 h-6 text-gray-600 dark:text-gray-300" />
    </div>
    <div>
      <p className="text-sm text-gray-500 dark:text-gray-400 font-medium">{label}</p>
      <h3 className="text-lg font-bold text-gray-900 dark:text-white mt-1">{value}</h3>
      {subtext && <p className="text-xs text-gray-400 mt-1">{subtext}</p>}
    </div>
  </div>
);

interface SecurityIssueRowProps {
  issue: SecurityIssue;
}

const SecurityIssueRow: React.FC<SecurityIssueRowProps> = ({ issue }) => {
  const icons = {
    'Critical': AlertOctagon,
    'High': AlertTriangle,
    'Medium': AlertTriangle,
    'Low': Info,
    'Info': Info
  };

  const Icon = icons[issue.level] || Info;

  return (
    <div className="flex gap-4 p-4 border-b border-gray-100 dark:border-gray-800 last:border-0 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors">
      <div className={`mt-1 flex-shrink-0`}>
        <Icon className={`w-5 h-5 ${issue.level === 'Critical' ? 'text-red-500' :
          issue.level === 'High' ? 'text-orange-500' :
            issue.level === 'Medium' ? 'text-yellow-500' : 'text-blue-500'
          }`} />
      </div>
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="font-semibold text-gray-900 dark:text-white text-sm">{issue.type}</span>
          <SeverityBadge level={issue.level} />
        </div>
        <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">{issue.message}</p>
      </div>
    </div>
  );
};

interface ReportDashboardProps {
  report: Report | null;
}

const ReportDashboard: React.FC<ReportDashboardProps> = ({ report }) => {
  if (!report) return null;

  return (
    <div id="scan-report" className="animate-fade-in-up space-y-6 pb-20">
      <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 p-6 shadow-sm">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{report.modelId}</h2>
              <a
                href={`https://huggingface.co/${report.modelId}`}
                target="_blank"
                rel="noreferrer"
                className="text-blue-500 hover:text-blue-600 text-xs"
              >
                View on HF ↗
              </a>
            </div>
            <div className="flex flex-wrap gap-4 text-sm text-gray-500 dark:text-gray-400">
              <span className="flex items-center gap-1"><Server className="w-4 h-4" /> {report.library}</span>
              <span className="flex items-center gap-1"><Database className="w-4 h-4" /> {report.downloads.toLocaleString()} downloads</span>
              <span className="flex items-center gap-1"><FileText className="w-4 h-4" /> {report.files.total} files</span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => {
                if (report) exportReportAsPDF(report);
              }}
              className="px-3 py-1 text-xs bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors"
              title="Export report as PDF"
            >
              Export PDF
            </button>
            <div className="bg-gray-50 dark:bg-gray-700/50 p-4 rounded-xl">
              <div className="text-right mb-2">
                <p className="text-sm text-gray-500 dark:text-gray-400 font-medium">Risk Score</p>
                <p className="text-xs text-gray-400">Based on heuristics</p>
              </div>
              <div className={`
                  flex items-center justify-center w-16 h-16 rounded-full border-4 text-xl font-bold
                  ${report.severity === 'Critical' ? 'border-red-500 text-red-600' :
                  report.severity === 'High' ? 'border-orange-500 text-orange-600' :
                    report.severity === 'Medium' ? 'border-yellow-400 text-yellow-600' : 'border-green-500 text-green-600'}
               `}>
                {report.scores.overallScore}/10
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          icon={FileText}
          label="File Security"
          value={report.files.risky.length > 0 ? "Risky Files" : "Clean"}
          subtext={`${report.files.risky.length} flagged, ${report.files.code.length} code files`}
        />
        <StatCard
          icon={report.license.toLowerCase().includes('openrail') || report.license.toLowerCase().includes('mit') ? Unlock : Lock}
          label="License Compliance"
          value={report.license === 'Unknown' ? 'Missing' : 'Present'}
          subtext={report.license}
        />
        <StatCard
          icon={Database}
          label="Linked Datasets"
          value={report.datasets.length}
          subtext={report.datasets.slice(0, 2).join(', ') + (report.datasets.length > 2 ? '...' : '')}
        />
        <StatCard
          icon={Code}
          label="Architecture"
          value={report.library}
          subtext="Model Library"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
          <div className="p-5 border-b border-gray-100 dark:border-gray-800 flex justify-between items-center">
            <h3 className="font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-500" />
              Security Findings
            </h3>
            <span className="text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-gray-600 dark:text-gray-300">
              {report.securityIssues.length} Issues
            </span>
          </div>

          {report.securityIssues.length === 0 ? (
            <div className="p-8 text-center text-gray-500">
              <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-3" />
              <p>No obvious security issues detected by automated scan.</p>
            </div>
          ) : (
            <div>
              {report.securityIssues.map((issue, idx) => (
                <SecurityIssueRow key={idx} issue={issue} />
              ))}
            </div>
          )}
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm h-fit">
          <div className="p-5 border-b border-gray-100 dark:border-gray-800">
            <h3 className="font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Terminal className="w-5 h-5 text-gray-500" />
              File Analysis
            </h3>
          </div>
          <div className="p-4">
            {report.files.risky.length > 0 && (
              <div className="mb-4">
                <p className="text-xs font-bold text-red-500 uppercase tracking-wide mb-2">Executables & Pickles</p>
                <div className="bg-red-50 dark:bg-red-900/20 rounded-lg p-3 space-y-2">
                  {report.files.risky.map(f => (
                    <div key={f} className="text-sm font-mono text-red-700 dark:text-red-400 flex items-center gap-2">
                      <AlertTriangle className="w-3 h-3" /> {f}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {report.files.code.length > 0 && (
              <div className="mb-4">
                <p className="text-xs font-bold text-yellow-500 uppercase tracking-wide mb-2">Source Code</p>
                <div className="bg-yellow-50 dark:bg-yellow-900/20 rounded-lg p-3 space-y-1">
                  {report.files.code.map(f => (
                    <div key={f} className="text-sm font-mono text-yellow-700 dark:text-yellow-400 truncate">
                      {f}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-3 mt-4">
              <div className="flex justify-between text-sm">
                <span className="text-gray-500">Safetensors/Weights</span>
                <span className="font-medium dark:text-gray-300">{report.files.safe.length}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-500">Total Files Scanned</span>
                <span className="font-medium dark:text-gray-300">{report.files.total}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

function LeaderboardTab({ history }: { history: ScanHistoryEntry[] }) {
  const sortedByRisk = [...history].sort((a, b) => b.overallScore - a.overallScore);
  const groups: Record<string, ScanHistoryEntry[]> = {};
  for (const entry of sortedByRisk) {
    const key = entry.modelId.split('/')[0] || 'unknown';
    if (!groups[key]) groups[key] = [];
    groups[key].push(entry);
  }

  return (
    <div className="space-y-4">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center justify-center gap-2">
          <Target className="w-6 h-6 text-blue-500" />
          Threat Intel Leaderboard
        </h2>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Riskiest models scanned - based on AI Eye heuristic scoring
        </p>
      </div>

      {history.length === 0 ? (
        <div className="text-center py-16">
          <Target className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No scans yet</h3>
          <p className="text-gray-500 dark:text-gray-400">Scan models to populate the leaderboard</p>
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 dark:bg-gray-900/50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-10">#</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Model</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk Score</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Library</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase hidden md:table-cell">Scanned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                {sortedByRisk.slice(0, 50).map((entry, idx) => (
                  <tr key={entry.modelId + entry.timestamp} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                    <td className="px-4 py-3 text-sm text-gray-500">{idx + 1}</td>
                    <td className="px-4 py-3">
                      <a
                        href={`https://huggingface.co/${entry.modelId}`}
                        target="_blank"
                        rel="noreferrer"
                        className="text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline"
                      >
                        {entry.modelId}
                      </a>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-sm font-bold ${
                        entry.overallScore >= 8 ? 'text-red-600' :
                        entry.overallScore >= 5 ? 'text-orange-600' :
                        entry.overallScore >= 3 ? 'text-yellow-600' : 'text-green-600'
                      }`}>
                        {entry.overallScore}/10
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge level={entry.severity} />
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">{entry.library}</td>
                    <td className="px-4 py-3 text-sm text-gray-400 hidden md:table-cell">
                      {new Date(entry.timestamp).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [isDark, setIsDark] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<SidebarTab>('dashboard');
  const [probeResults, setProbeResults] = useState<ProbeResult[]>([]);
  const [verificationResult, _setVerificationResult] = useState<VerificationResult | null>(null);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);

  useEffect(() => {
    if (window.matchMedia("(prefers-color-scheme: dark)").matches)
      setIsDark(true);
    setScanHistory(loadScanHistory());
  }, []);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSidebarOpen(true);
      }
      if (e.key === 'Escape' && sidebarOpen) {
        setSidebarOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [sidebarOpen]);

  useEffect(() => {
    setScanHistory(loadScanHistory());
  }, []);

  const addToast = useCallback((type: ToastMessage['type'], message: string) => {
    const id = Date.now().toString();
    setToasts((prev) => [...prev, { id, type, message }]);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toggleTheme = () => setIsDark(!isDark);

  const handleScan = async (id: string) => {
    setLoading(true);
    setError(null);
    setReport(null);
    setActiveTab('dashboard');
    setProbeResults([]);

    try {
      const baseReport = await performSecurityScan(id);

      const staticResult = performStaticAnalysis(
        id,
        {},
        [],
        undefined,
        undefined
      );

      let spacesUrl = getKnownSpace(id);
      if (!spacesUrl) {
        try {
          const spacesInfo = await detectSpaces(id);
          spacesUrl = spacesInfo.spacesUrl;
        } catch {}
      }
      staticResult.spacesUrl = spacesUrl;
      staticResult.hasSpaces = !!spacesUrl;

      for (const finding of staticResult.findings) {
        baseReport.securityIssues.push({
          level: staticResult.staticRiskLevel === 'critical' ? 'Critical' :
            staticResult.staticRiskLevel === 'high' ? 'High' :
              staticResult.staticRiskLevel === 'medium' ? 'Medium' : 'Low',
          type: 'Static Analysis',
          message: finding
        });
      }

      baseReport.staticAnalysis = staticResult;
      setReport(baseReport);
      addToScanHistory(baseReport);
      setScanHistory(loadScanHistory());

      const savedProbes = loadProbeResults(id);
      if (savedProbes.length > 0) {
        setProbeResults(savedProbes);
        baseReport.probeResults = savedProbes;
      }

      addToast('success', `Scan complete: ${baseReport.modelId}`);

    } catch (err: any) {
      setError(err.message || "Scan failed");
      addToast('error', err.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  };

  const handleHistorySelect = (modelId: string) => {
    setActiveTab('dashboard');
    handleScan(modelId);
  };

  const handleClearHistory = () => {
    clearScanHistory();
    setScanHistory([]);
  };

  const handleProbeResultsChange = (results: ProbeResult[]) => {
    setProbeResults(results);
    if (report) {
      const updated = { ...report, probeResults: results };
      setReport(updated);
      saveProbeResults(report.modelId, results);
    }
  };

  return (
    <ErrorBoundary>
      <div className={`min-h-screen transition-colors duration-300 ${isDark ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
        <Sidebar
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
          activeTab={activeTab}
          onTabChange={setActiveTab}
          hasScannedModel={!!report}
          scanHistory={scanHistory}
          onHistorySelect={handleHistorySelect}
          onClearHistory={handleClearHistory}
        />
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

          <Header isDark={isDark} toggleTheme={toggleTheme} onMenuClick={() => setSidebarOpen(true)} modelId={report?.modelId} />

          <ToastContainer toasts={toasts} onDismiss={dismissToast} />

          <main>
            {activeTab === 'dashboard' && (
              <>
                {!report && !loading && (
                  <div className="text-center mb-10">
                    <h2 className="text-3xl md:text-4xl font-extrabold text-gray-900 dark:text-white mb-4">
                      Secure your AI Supply Chain
                    </h2>
                    <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto mb-1">
                      Scan HuggingFace models for malicious code, unsafe serialization (pickles), and license compliance issues before you deploy.
                    </p>
                  </div>
                )}

                <SearchBar onScan={handleScan} isLoading={loading} />

                <p className="text-center text-sm text-gray-500 dark:text-gray-400 mb-8">
                  {report ? `Last scan: ${report.modelId}` : '© 2026 AI Eye.'}
                </p>

                {loading && <ScanSkeleton />}

                {error && !loading && (
                  <div className="max-w-lg mx-auto mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl text-center">
                    <AlertOctagon className="w-8 h-8 text-red-500 mx-auto mb-2" />
                    <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
                  </div>
                )}

                <ReportDashboard report={report} />

                {report?.staticAnalysis && (
                  <div className="mt-6 bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="bg-purple-100 dark:bg-purple-900/30 p-2 rounded-lg">
                        <Cpu className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                      </div>
                      <div>
                        <h3 className="font-bold text-gray-900 dark:text-white">Deep Static Analysis</h3>
                        <p className="text-xs text-gray-500">Model card, config, and training data inspection</p>
                      </div>
                      <div className="ml-auto">
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${report.staticAnalysis.staticRiskLevel === 'critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                          report.staticAnalysis.staticRiskLevel === 'high' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                            report.staticAnalysis.staticRiskLevel === 'medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                              'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                          }`}>
                          {report.staticAnalysis.staticRiskLevel.toUpperCase()} ({report.staticAnalysis.staticRiskScore}/100)
                        </span>
                      </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                      <div>
                        <span className="text-gray-500 dark:text-gray-400 block">Base Model</span>
                        <span className="text-gray-900 dark:text-white font-medium">
                          {report.staticAnalysis.baseModel || 'Unknown'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400 block">Architecture</span>
                        <span className="text-gray-900 dark:text-white font-medium">
                          {report.staticAnalysis.architectureType || 'Unknown'}
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400 block">Unsafe Keywords</span>
                        <span className={`font-medium ${report.staticAnalysis.unsafeKeywords.length > 0 ? 'text-red-600' : 'text-green-600'}`}>
                          {report.staticAnalysis.unsafeKeywords.length} detected
                        </span>
                      </div>
                      <div>
                        <span className="text-gray-500 dark:text-gray-400 block">Free Demo</span>
                        {report.staticAnalysis.hasSpaces ? (
                          <a
                            href={report.staticAnalysis.spacesUrl || '#'}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 dark:text-blue-400 font-medium hover:underline"
                          >
                            Available ↗
                          </a>
                        ) : (
                          <span className="text-gray-500">Not found</span>
                        )}
                      </div>
                    </div>

                    {report.staticAnalysis.unsafeKeywords.length > 0 && (
                      <div className="mt-4 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                        <span className="text-xs text-red-600 dark:text-red-400 font-bold">Detected Patterns: </span>
                        <span className="text-xs text-red-600 dark:text-red-400">
                          {report.staticAnalysis.unsafeKeywords.join(', ')}
                        </span>
                      </div>
                    )}

                    {report.staticAnalysis.hasSpaces && (
                      <div className="mt-4 flex items-center gap-2">
                        <Target className="w-4 h-4 text-purple-500" />
                        <button
                          onClick={() => setActiveTab('redteam')}
                          className="text-sm text-purple-600 dark:text-purple-400 font-medium hover:underline"
                        >
                          Open Red Team Playbook to test this model →
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}

            {activeTab === 'redteam' && report && (
              <RedTeamPlaybook
                modelId={report.modelId}
                spacesUrl={report.staticAnalysis?.spacesUrl || null}
                onResultsChange={handleProbeResultsChange}
                initialResults={probeResults}
              />
            )}

            {activeTab === 'about' && (
              <div className="max-w-2xl mx-auto">
                <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-8">
                  <div className="flex items-center gap-3 mb-6">
                    <div className="bg-blue-600 p-3 rounded-lg">
                      <Shield className="w-8 h-8 text-white" />
                    </div>
                    <div>
                      <h2 className="text-2xl font-bold text-gray-900 dark:text-white">AI Eye</h2>
                      <p className="text-gray-500 dark:text-gray-400">AI Model Security Scanner v1.0</p>
                    </div>
                  </div>

                  <div className="space-y-4 text-gray-600 dark:text-gray-300">
                    <p>
                      AI Eye helps you secure your AI supply chain by scanning HuggingFace models for:
                    </p>
                    <ul className="list-disc list-inside space-y-2 ml-4">
                      <li>Unsafe serialization formats (pickle, joblib, dill)</li>
                      <li>Executable files and code that could run on load</li>
                      <li>License compliance and legal issues</li>
                      <li>Known vulnerable or uncensored base models</li>
                      <li>Risky training data sources</li>
                    </ul>

                    <div className="border-t border-gray-200 dark:border-gray-700 pt-4 mt-6">
                      <h3 className="font-bold text-gray-900 dark:text-white mb-2">Keyboard Shortcuts</h3>
                      <div className="text-sm space-y-1">
                        <p><kbd className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono">Ctrl+K</kbd> Open menu</p>
                        <p><kbd className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs font-mono">Esc</kbd> Close menu</p>
                      </div>
                    </div>

                    <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                      <h3 className="font-bold text-gray-900 dark:text-white mb-2">Red Team Playbook</h3>
                      <p className="text-sm">
                        After scanning a model, use the Red Team Playbook to manually test for jailbreaks,
                        prompt injection, and other AI safety vulnerabilities. Copy probes and test them
                        against the model's demo (if available) or your own deployment.
                      </p>
                    </div>

                    <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                      <p className="text-sm text-gray-500">
                        Built for AI security research and red teaming. © 2026
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'leaderboard' && (
              <LeaderboardTab history={scanHistory} />
            )}

            {activeTab === 'verification' && (
              <VerificationDashboard />
            )}

            {activeTab === 'reviewer' && (
              <ReviewerMode
                result={verificationResult}
                onClose={() => setActiveTab('dashboard')}
              />
            )}

            {activeTab === 'history' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                    <Clock className="w-6 h-6 text-blue-500" />
                    Scan History
                  </h2>
                  {scanHistory.length > 0 && (
                    <button
                      onClick={handleClearHistory}
                      className="text-sm text-red-500 hover:text-red-600"
                    >
                      Clear all
                    </button>
                  )}
                </div>
                {scanHistory.length === 0 ? (
                  <div className="text-center py-16">
                    <Clock className="w-12 h-12 text-gray-300 dark:text-gray-600 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No scan history</h3>
                    <p className="text-gray-500 dark:text-gray-400">Scan a model to see it here</p>
                  </div>
                ) : (
                  <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
                    <div className="divide-y divide-gray-100 dark:divide-gray-700">
                      {scanHistory.map((entry) => (
                        <div
                          key={entry.modelId + entry.timestamp}
                          className="flex items-center justify-between p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                        >
                          <div className="flex-1 min-w-0">
                            <button
                              onClick={() => handleHistorySelect(entry.modelId)}
                              className="text-sm font-medium text-blue-600 dark:text-blue-400 hover:underline truncate block"
                            >
                              {entry.modelId}
                            </button>
                            <div className="flex items-center gap-2 mt-1">
                              <SeverityBadge level={entry.severity} />
                              <span className="text-xs text-gray-400">{entry.overallScore}/10</span>
                              <span className="text-xs text-gray-400">{entry.library}</span>
                            </div>
                          </div>
                          <div className="text-xs text-gray-400 ml-4 whitespace-nowrap">
                            {new Date(entry.timestamp).toLocaleDateString(undefined, {
                              month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
                            })}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </main>
        </div>
      </div>
    </ErrorBoundary>
  );
}
