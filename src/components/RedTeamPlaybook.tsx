import React, { useState } from 'react';
import {
    PROBE_LIBRARY,
    PROBE_CATEGORIES,
    Probe,
    ProbeCategory,
    getProbesByCategory
} from '../data/probeLibrary';
import {
    Copy,
    Check,
    ChevronDown,
    ChevronRight,
    ExternalLink,
    AlertTriangle,
    AlertOctagon,
    Info,
    Shield,
    Target
} from 'lucide-react';

export interface ProbeResult {
    probeId: string;
    category: string;
    result: 'pass' | 'fail' | 'partial' | 'untested';
    notes?: string;
}

interface RedTeamPlaybookProps {
    modelId: string;
    spacesUrl: string | null;
    onResultsChange: (results: ProbeResult[]) => void;
    initialResults?: ProbeResult[];
}

export const RedTeamPlaybook: React.FC<RedTeamPlaybookProps> = ({
    modelId,
    spacesUrl,
    onResultsChange,
    initialResults = []
}) => {
    const [expandedCategory, setExpandedCategory] = useState<ProbeCategory | null>('jailbreak');
    const [copiedId, setCopiedId] = useState<string | null>(null);
    const [results, setResults] = useState<Record<string, ProbeResult['result']>>(
        Object.fromEntries(initialResults.map(r => [r.probeId, r.result]))
    );

    const handleCopy = async (probe: Probe) => {
        try {
            await navigator.clipboard.writeText(probe.prompt);
            setCopiedId(probe.id);
            setTimeout(() => setCopiedId(null), 2000);
        } catch (err) {
            console.error('Failed to copy:', err);
        }
    };

    const handleResultChange = (probeId: string, category: string, result: ProbeResult['result']) => {
        const newResults = { ...results, [probeId]: result };
        setResults(newResults);

        // Convert to array and notify parent
        const resultsArray: ProbeResult[] = Object.entries(newResults).map(([id, res]) => ({
            probeId: id,
            category: PROBE_LIBRARY.find(p => p.id === id)?.category || category,
            result: res
        }));
        onResultsChange(resultsArray);
    };

    const getSeverityIcon = (severity: Probe['severity']) => {
        switch (severity) {
            case 'critical': return <AlertOctagon className="w-4 h-4 text-red-500" />;
            case 'high': return <AlertTriangle className="w-4 h-4 text-orange-500" />;
            case 'medium': return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
            default: return <Info className="w-4 h-4 text-blue-500" />;
        }
    };

    const getResultColor = (result: ProbeResult['result'] | undefined) => {
        switch (result) {
            case 'pass': return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400';
            case 'fail': return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400';
            case 'partial': return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400';
            default: return 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400';
        }
    };

    const categories = Object.entries(PROBE_CATEGORIES) as [ProbeCategory, typeof PROBE_CATEGORIES[ProbeCategory]][];

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
                <div className="flex items-center gap-3 mb-4">
                    <div className="bg-red-100 dark:bg-red-900/30 p-2 rounded-lg">
                        <Target className="w-6 h-6 text-red-600 dark:text-red-400" />
                    </div>
                    <div>
                        <h2 className="text-xl font-bold text-gray-900 dark:text-white">Red Team Playbook</h2>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Manual testing probes for <span className="font-mono text-blue-500">{modelId}</span>
                        </p>
                    </div>
                </div>

                {/* Spaces Link */}
                {spacesUrl ? (
                    <a
                        href={spacesUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-lg p-3 hover:bg-green-100 dark:hover:bg-green-900/30 transition-colors"
                    >
                        <ExternalLink className="w-5 h-5 text-green-600 dark:text-green-400" />
                        <div>
                            <p className="text-sm font-semibold text-green-700 dark:text-green-300">
                                Free Demo Available
                            </p>
                            <p className="text-xs text-green-600 dark:text-green-400">
                                Open HuggingFace Spaces to test these probes live
                            </p>
                        </div>
                    </a>
                ) : (
                    <div className="flex items-center gap-2 bg-gray-50 dark:bg-gray-700/50 border border-gray-200 dark:border-gray-600 rounded-lg p-3">
                        <Info className="w-5 h-5 text-gray-400" />
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            No free demo detected. Use HuggingFace Inference API or local deployment to test.
                        </p>
                    </div>
                )}

                {/* Stats */}
                <div className="mt-4 flex gap-4 text-sm">
                    <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-gray-400" />
                        <span className="text-gray-600 dark:text-gray-400">{PROBE_LIBRARY.length} probes</span>
                    </div>
                    <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${getResultColor('pass')}`}>
                            {Object.values(results).filter(r => r === 'pass').length} passed
                        </span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${getResultColor('fail')}`}>
                            {Object.values(results).filter(r => r === 'fail').length} failed
                        </span>
                    </div>
                </div>
            </div>

            {/* Probe Categories */}
            <div className="space-y-3">
                {categories.map(([category, info]) => {
                    const probes = getProbesByCategory(category);
                    const isExpanded = expandedCategory === category;

                    return (
                        <div
                            key={category}
                            className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden"
                        >
                            {/* Category Header */}
                            <button
                                onClick={() => setExpandedCategory(isExpanded ? null : category)}
                                className="w-full flex items-center justify-between p-4 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
                            >
                                <div className="flex items-center gap-3">
                                    <span className="text-2xl">{info.icon}</span>
                                    <div className="text-left">
                                        <h3 className="font-semibold text-gray-900 dark:text-white">{info.name}</h3>
                                        <p className="text-xs text-gray-500 dark:text-gray-400">{info.description}</p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    <span className="text-xs bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded text-gray-600 dark:text-gray-300">
                                        {probes.length} probes
                                    </span>
                                    {isExpanded ? (
                                        <ChevronDown className="w-5 h-5 text-gray-400" />
                                    ) : (
                                        <ChevronRight className="w-5 h-5 text-gray-400" />
                                    )}
                                </div>
                            </button>

                            {/* Probes List */}
                            {isExpanded && (
                                <div className="border-t border-gray-100 dark:border-gray-700">
                                    {probes.map((probe) => (
                                        <div
                                            key={probe.id}
                                            className="p-4 border-b border-gray-100 dark:border-gray-700 last:border-0 hover:bg-gray-50 dark:hover:bg-gray-700/30"
                                        >
                                            {/* Probe Header */}
                                            <div className="flex items-start justify-between mb-2">
                                                <div className="flex items-center gap-2">
                                                    {getSeverityIcon(probe.severity)}
                                                    <h4 className="font-medium text-gray-900 dark:text-white">{probe.name}</h4>
                                                </div>
                                                <button
                                                    onClick={() => handleCopy(probe)}
                                                    className="flex items-center gap-1 px-3 py-1 text-xs bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 rounded-md hover:bg-blue-200 dark:hover:bg-blue-900/50 transition-colors"
                                                >
                                                    {copiedId === probe.id ? (
                                                        <>
                                                            <Check className="w-3 h-3" />
                                                            Copied!
                                                        </>
                                                    ) : (
                                                        <>
                                                            <Copy className="w-3 h-3" />
                                                            Copy Prompt
                                                        </>
                                                    )}
                                                </button>
                                            </div>

                                            {/* Description */}
                                            <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                                                {probe.description}
                                            </p>

                                            {/* Prompt Preview */}
                                            <div className="bg-gray-900 dark:bg-black rounded-lg p-3 mb-3 max-h-32 overflow-y-auto">
                                                <pre className="text-xs text-gray-300 whitespace-pre-wrap font-mono">
                                                    {probe.prompt.length > 300
                                                        ? probe.prompt.substring(0, 300) + '...'
                                                        : probe.prompt}
                                                </pre>
                                            </div>

                                            {/* Expected Response & Red Flags */}
                                            <div className="grid grid-cols-2 gap-3 mb-3 text-xs">
                                                <div>
                                                    <span className="text-gray-500 dark:text-gray-400 block mb-1">Expected Safe Response:</span>
                                                    <p className="text-green-600 dark:text-green-400">{probe.expectedSafeResponse}</p>
                                                </div>
                                                <div>
                                                    <span className="text-gray-500 dark:text-gray-400 block mb-1">Red Flags:</span>
                                                    <ul className="text-red-600 dark:text-red-400">
                                                        {probe.redFlags.map((flag, i) => (
                                                            <li key={i}>• {flag}</li>
                                                        ))}
                                                    </ul>
                                                </div>
                                            </div>

                                            {/* Result Buttons */}
                                            <div className="flex items-center gap-2">
                                                <span className="text-xs text-gray-500 dark:text-gray-400 mr-2">Result:</span>
                                                {(['pass', 'fail', 'partial', 'untested'] as const).map((status) => (
                                                    <button
                                                        key={status}
                                                        onClick={() => handleResultChange(probe.id, category, status)}
                                                        className={`px-3 py-1 text-xs rounded-md font-medium transition-colors
                              ${results[probe.id] === status
                                                                ? getResultColor(status) + ' ring-2 ring-offset-1 ring-gray-400'
                                                                : 'bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600'
                                                            }`}
                                                    >
                                                        {status.charAt(0).toUpperCase() + status.slice(1)}
                                                    </button>
                                                ))}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    );
                })}
            </div>
        </div>
    );
};

export default RedTeamPlaybook;
