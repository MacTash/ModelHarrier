import React, { useState, useEffect } from 'react';
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
  Terminal
} from 'lucide-react';

// --- CONSTANTS & CONFIGURATION ---

const RISKY_EXTENSIONS = ['.pickle', '.pkl', '.joblib', '.dill', '.exe', '.bin', '.dll'];
const CODE_EXTENSIONS = ['.py', '.sh', '.bash', '.js'];
const SAFE_EXTENSIONS = ['.safetensors', '.onnx', '.tflite', '.json', '.txt', '.md'];

const SENSITIVE_DOMAINS = ['medical', 'finance', 'biometric', 'legal', 'surveillance'];

const REDTEAM_KEYWORDS = [
  'uncensored', 'no safety', 'jailbreak', 'do anything',
  'bypass restrictions', 'no guardrails', 'unrestricted',
  'unfiltered', 'no ethics', 'no censorship', 'no limits'
];

// --- TYPES ---

interface SecurityIssue {
  level: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  type: string;
  message: string;
}

interface ReportFiles {
  total: number;
  risky: string[];
  code: string[];
  safe: string[];
  unknown: string[];
}

interface ReportScores {
  fileRisk: number;
  licenseRisk: number;
  vulnerabilityScore: number;
  overallScore: number;
}

interface RedTeamInsights {
  score: number;
  level: 'Low' | 'Medium' | 'High';
  findings: string[];
}

interface Report {
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
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  redTeamInsights?: RedTeamInsights;
}

// --- MOCK BACKEND LOGIC (Simulating api/scan.ts) ---

/**
 * In a Vercel deployment, this logic would live in /pages/api/scan.ts
 * Here it runs client-side to allow immediate preview.
 */
const performSecurityScan = async (modelId: string): Promise<Report> => {
  try {
    // 1. Fetch Model Metadata & Siblings (File List)
    const response = await fetch(`/api/scan?modelId=${encodeURIComponent(modelId)}`);

    if (!response.ok) {
      if (response.status === 404) throw new Error("Model not found on HuggingFace.");
      throw new Error(`API Error: ${response.statusText}`);
    }

    const data = await response.json();

    // 2. Initialize Report
    const report: Report = {
      modelId: data.modelId,
      author: data.author,
      downloads: data.downloads,
      likes: data.likes,
      library: data.library_name || 'Unknown',
      license: data.cardData?.license || 'Unknown',
      lastModified: data.lastModified,
      files: {
        total: 0,
        risky: [],
        code: [],
        safe: [],
        unknown: []
      },
      datasets: data.cardData?.datasets || [],
      securityIssues: [],
      scores: {
        fileRisk: 0,
        licenseRisk: 0,
        vulnerabilityScore: 0,
        overallScore: 0
      },
      severity: 'Low'
    };

    // 3. File Analysis
    if (data.siblings) {
      report.files.total = data.siblings.length;

      data.siblings.forEach((file: any) => {
        const filename = file.rfilename.toLowerCase();
        const isRisky = RISKY_EXTENSIONS.some(ext => filename.endsWith(ext));
        const isCode = CODE_EXTENSIONS.some(ext => filename.endsWith(ext));
        const isSafe = SAFE_EXTENSIONS.some(ext => filename.endsWith(ext));

        if (isRisky) {
          report.files.risky.push(filename);
          report.securityIssues.push({
            level: 'Critical',
            type: 'Unsafe Serialization',
            message: `Detected potentially unsafe file: ${filename}. Pickle-based files can execute arbitrary code.`
          });
        } else if (isCode) {
          report.files.code.push(filename);
          report.securityIssues.push({
            level: 'Medium',
            type: 'Code Execution',
            message: `Model contains executable code: ${filename}. Audit required.`
          });
        } else if (isSafe) {
          report.files.safe.push(filename);
        } else {
          report.files.unknown.push(filename);
        }
      });
    }

    // 4. Heuristic Scoring Logic

    // File Risk (0-10)
    if (report.files.risky.length > 0) report.scores.fileRisk = 10;
    else if (report.files.code.length > 0) report.scores.fileRisk = 5;
    else report.scores.fileRisk = 1;

    // License Risk (0-10)
    const knownOpenLicenses = ['mit', 'apache-2.0', 'openrail'];
    const lowerLicense = report.license.toLowerCase();
    if (['unknown', 'other'].includes(lowerLicense)) report.scores.licenseRisk = 7;
    else if (knownOpenLicenses.some(l => lowerLicense.includes(l))) report.scores.licenseRisk = 0;
    else report.scores.licenseRisk = 4; // Custom or restrictive

    // Dataset & Metadata checks
    const tags: string[] = data.tags || [];
    const hasSensitiveTag = tags.some(tag => SENSITIVE_DOMAINS.some(domain => tag.includes(domain)));
    if (hasSensitiveTag) {
      report.securityIssues.push({
        level: 'Info',
        type: 'Sensitive Domain',
        message: 'Model is tagged with categories (medical/finance/etc) that may require PII audit.'
      });
    }

    // Safetensors bonus
    const hasSafetensors = report.files.safe.some(f => f.endsWith('.safetensors'));
    if (!hasSafetensors && report.files.risky.length === 0) {
      report.securityIssues.push({
        level: 'Low',
        type: 'Modernization',
        message: 'Model does not use safetensors. Consider converting for better security.'
      });
    }

    // 5. RED TEAM ANALYSIS (NEW)
    const analyzeRedTeamRisk = (): RedTeamInsights => {
      const findings: string[] = [];
      let redTeamScore = 0;

      // Get model card text and tags
      const modelCard = (data.cardData?.text || '').toLowerCase();
      const tagsList = (data.tags || []).map((t: string) => t.toLowerCase());
      const combinedText = modelCard + ' ' + tagsList.join(' ');

      // Check for red team keywords
      const detectedKeywords: string[] = [];
      REDTEAM_KEYWORDS.forEach(keyword => {
        if (combinedText.includes(keyword)) {
          detectedKeywords.push(keyword);
          redTeamScore += 15;
        }
      });

      if (detectedKeywords.length > 0) {
        findings.push(`Detected ${detectedKeywords.length} risk keyword(s): ${detectedKeywords.slice(0, 3).join(', ')}`);
      }

      // Check for safety alignment indicators
      const safetyIndicators = ['safety', 'aligned', 'rlhf', 'constitutional'];
      const hasSafetyTag = safetyIndicators.some(indicator =>
        combinedText.includes(indicator)
      );

      if (!hasSafetyTag && detectedKeywords.length > 0) {
        findings.push('No safety alignment indicators found in model card');
        redTeamScore += 10;
      }

      // Check for explicit jailbreak or bypass mentions
      if (combinedText.includes('jailbreak') || combinedText.includes('bypass')) {
        findings.push('Explicit bypass/jailbreak terminology detected');
        redTeamScore += 25;
      }

      // Check for "uncensored" specific flag
      if (combinedText.includes('uncensored')) {
        findings.push('Model explicitly advertised as "uncensored"');
        redTeamScore += 20;
      }

      // Cap at 100
      redTeamScore = Math.min(100, redTeamScore);

      // Determine level
      const level: 'Low' | 'Medium' | 'High' =
        redTeamScore >= 60 ? 'High' :
          redTeamScore >= 30 ? 'Medium' : 'Low';

      // Add default message if no findings
      if (findings.length === 0) {
        findings.push('No red team risk indicators detected in metadata');
      }

      return { score: redTeamScore, level, findings };
    };

    report.redTeamInsights = analyzeRedTeamRisk();

    // Calculate Overall Risk
    // Weighted average: Files (60%) + License (20%) + Vuln/Other (20%)
    const rawScore = (report.scores.fileRisk * 6) + (report.scores.licenseRisk * 2);
    report.scores.overallScore = Math.min(10, Math.ceil(rawScore / 8)); // Normalize roughly to 1-10

    // Determine Severity Label
    if (report.scores.overallScore >= 8) report.severity = 'Critical';
    else if (report.scores.overallScore >= 5) report.severity = 'High';
    else if (report.scores.overallScore >= 3) report.severity = 'Medium';
    else report.severity = 'Low';

    return report;

  } catch (error) {
    console.error(error);
    throw error;
  }
};

// --- COMPONENTS ---

interface HeaderProps {
  isDark: boolean;
  toggleTheme: () => void;
}

const Header: React.FC<HeaderProps> = ({ isDark, toggleTheme }) => (
  <header className="flex justify-between items-center py-6 border-b border-gray-200 dark:border-gray-800 mb-8 transition-colors duration-300">
    <div className="flex items-center gap-3">
      <div className="bg-blue-600 p-2 rounded-lg">
        <Shield className="w-6 h-6 text-white" />
      </div>
      <div>
        <h1 className="text-xl font-bold text-gray-900 dark:text-white">AI GuardRails</h1>
        <p className="text-xs text-gray-500 dark:text-gray-400">Model Security Scanner</p>
      </div>
    </div>
    <button
      onClick={toggleTheme}
      className="p-2 rounded-full hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
    >
      {isDark ? <Sun className="w-5 h-5 text-yellow-400" /> : <Moon className="w-5 h-5 text-gray-600" />}
    </button>
  </header>
);

interface SearchBarProps {
  onScan: (modelId: string) => void;
  isLoading: boolean;
}

const SearchBar: React.FC<SearchBarProps> = ({ onScan, isLoading }) => {
  const [input, setInput] = useState('');

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (input.trim()) onScan(input.trim());
  };

  return (
    <form onSubmit={handleSubmit} className="relative max-w-2xl mx-auto mb-12">
      <div className="relative group">
        <div className="absolute inset-0 bg-blue-500 rounded-xl blur opacity-25 group-hover:opacity-40 transition duration-200"></div>
        <div className="relative flex items-center bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl shadow-sm overflow-hidden p-1">
          <Search className="w-5 h-5 ml-4 text-gray-400" />
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter HuggingFace ID (e.g., 'bert-base-uncased')"
            className="w-full px-4 py-3 bg-transparent outline-none text-gray-900 dark:text-gray-100 placeholder-gray-400"
          />
          <button
            type="submit"
            disabled={isLoading}
            className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isLoading ? (
              <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
            ) : (
              'Scan Model'
            )}
          </button>
        </div>
      </div>
      <div className="mt-3 flex gap-3 justify-center text-xs text-gray-500">
        <span className="cursor-pointer hover:text-blue-500" onClick={() => setInput('gpt2')}>Try: gpt2</span>
        <span className="cursor-pointer hover:text-blue-500" onClick={() => setInput('runwayml/stable-diffusion-v1-5')}>Try: stable-diffusion</span>
        <span className="cursor-pointer hover:text-blue-500" onClick={() => setInput('bert-base-uncased')}>Try: bert-base</span>
      </div>
    </form>
  );
};

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
  <div className="bg-white dark:bg-gray-800 p-5 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm flex items-start gap-4">
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

// NEW COMPONENT: Red Team Insights Card
interface RedTeamInsightsProps {
  insights?: RedTeamInsights;
}

const RedTeamInsightsCard: React.FC<RedTeamInsightsProps> = ({ insights }) => {
  if (!insights) return null;

  const getColorClass = (level: string) => {
    switch (level) {
      case 'High': return 'text-red-600 dark:text-red-400';
      case 'Medium': return 'text-yellow-600 dark:text-yellow-400';
      case 'Low': return 'text-green-600 dark:text-green-400';
      default: return 'text-gray-600';
    }
  };

  const getBgClass = (level: string) => {
    switch (level) {
      case 'High': return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
      case 'Medium': return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
      case 'Low': return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
      default: return 'bg-gray-50';
    }
  };

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm">
      <div className="p-5 border-b border-gray-100 dark:border-gray-800 flex justify-between items-center">
        <h3 className="font-bold text-gray-900 dark:text-white flex items-center gap-2">
          <AlertOctagon className="w-5 h-5 text-purple-500" />
          Red Team Insights
        </h3>
        <span className="text-xs text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
          Static Analysis
        </span>
      </div>

      <div className="p-5">
        {/* Score Display */}
        <div className={`${getBgClass(insights.level)} rounded-lg p-4 mb-4 flex items-center justify-between border`}>
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">Red Team Risk Score</p>
            <p className={`text-3xl font-bold ${getColorClass(insights.level)}`}>
              {insights.score}/100
            </p>
          </div>
          <div>
            <SeverityBadge level={insights.level} />
          </div>
        </div>

        {/* Findings List */}
        <div className="space-y-3">
          <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wide">
            Findings
          </p>
          {insights.findings.map((finding, idx) => (
            <div key={idx} className="flex items-start gap-2 text-sm text-gray-700 dark:text-gray-300">
              <span className="text-purple-500 mt-1">•</span>
              <span>{finding}</span>
            </div>
          ))}
        </div>

        {/* Info Note */}
        <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
          <p className="text-xs text-gray-500 dark:text-gray-400 italic">
            This analysis is based on model card text and tags. Active probing features coming soon.
          </p>
        </div>
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
    <div className="animate-fade-in-up space-y-6 pb-20">

      {/* Top Level Summary */}
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

          <div className="flex items-center gap-4 bg-gray-50 dark:bg-gray-700/50 p-4 rounded-xl">
            <div className="text-right">
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

      {/* Grid Stats */}
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

      {/* NEW: Red Team Insights Section */}
      {report.redTeamInsights && (
        <RedTeamInsightsCard insights={report.redTeamInsights} />
      )}

      {/* Main Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left Column: Security Issues */}
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

        {/* Right Column: File Breakdown */}
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden shadow-sm h-fit">
          <div className="p-5 border-b border-gray-100 dark:border-gray-800">
            <h3 className="font-bold text-gray-900 dark:text-white flex items-center gap-2">
              <Terminal className="w-5 h-5 text-gray-500" />
              File Analysis
            </h3>
          </div>
          <div className="p-4">
            {/* Risky Files */}
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

            {/* Code Files */}
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

            {/* Stats */}
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

// --- MAIN APP ---

export default function App() {
  const [isDark, setIsDark] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<Report | null>(null);

  // Initialize theme
  useEffect(() => {
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setIsDark(true);
    }
  }, []);

  const toggleTheme = () => setIsDark(!isDark);

  const handleScan = async (modelId: string) => {
    setLoading(true);
    setError(null);
    setReport(null);

    try {
      const result = await performSecurityScan(modelId);
      setReport(result);
    } catch (err) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`min-h-screen transition-colors duration-300 ${isDark ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">

        <Header isDark={isDark} toggleTheme={toggleTheme} />

        <main>
          <div className="text-center mb-10">
            <h2 className="text-3xl md:text-4xl font-extrabold text-gray-900 dark:text-white mb-4">
              Secure your AI Supply Chain
            </h2>
            <p className="text-lg text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
              Scan HuggingFace models for malicious code, unsafe serialization (pickles), and license compliance issues before you deploy.
            </p>
          </div>

          <SearchBar onScan={handleScan} isLoading={loading} />

          {error && (
            <div className="bg-red-50 dark:bg-red-900/30 border-l-4 border-red-500 p-4 mb-8 mx-auto max-w-2xl rounded-r-lg">
              <div className="flex">
                <div className="flex-shrink-0">
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                </div>
                <div className="ml-3">
                  <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
                </div>
              </div>
            </div>
          )}

          <ReportDashboard report={report} />

        </main>

        <footer className="py-8 text-center text-gray-400 dark:text-gray-600 text-sm">
          <p>© {new Date().getFullYear()} AI GuardRails Scanner. Local Preview Environment.</p>
        </footer>
      </div>
    </div>
  );
}