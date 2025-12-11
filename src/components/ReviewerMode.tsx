/**
 * Reviewer Mode Component
 * 
 * Human-in-the-loop inspection view for detailed pickle analysis.
 * Shows opcode sequences, class references, suspicious strings,
 * and deserialization graph.
 */
import React, { useState } from 'react';
import {
    Eye,
    Code,
    AlertTriangle,
    CheckCircle,
    XCircle,
    Copy,
    ChevronDown,
    ChevronUp,
    FileCode,
    Cpu,
    Shield,
    Package,
} from 'lucide-react';

// Types for verification result (from API)
export interface VerificationResult {
    fileHash: string;
    fileSize: number;
    aieyeResult: string;
    aieyeScore: number;
    consensus: string | null;
    confidence: number;
    isFalsePositive: boolean;
    isFalseNegative: boolean;
    reasoning: string[];
    pickletools: {
        riskLevel: string;
        riskScore: number;
        hasReduce: boolean;
        hasGlobal: boolean;
        opcodeCounts: Record<string, number>;
        dangerousGlobals: Array<{ module: string; name: string; reason: string }>;
        disassembly: string;
    };
    fickling: {
        available: boolean;
        isSafe: boolean;
        findings: string[];
    };
    sandbox: {
        loadSucceeded: boolean;
        blockedImports: string[];
        loadedType: string | null;
        error: string | null;
    };
    peft: {
        isPeftAdapter: boolean;
        isTrainerOutput: boolean;
        matchedSignatures: string[];
        confidence: number;
    };
    opcodeVector: number[];
}

interface ReviewerModeProps {
    result: VerificationResult | null;
    onClose?: () => void;
}

// Collapsible section component
const Section: React.FC<{
    title: string;
    icon: React.ElementType;
    defaultOpen?: boolean;
    status?: 'safe' | 'warning' | 'danger' | 'info';
    children: React.ReactNode;
}> = ({ title, icon: Icon, defaultOpen = false, status = 'info', children }) => {
    const [isOpen, setIsOpen] = useState(defaultOpen);

    const statusColors = {
        safe: 'text-green-500 bg-green-100 dark:bg-green-900/30',
        warning: 'text-yellow-500 bg-yellow-100 dark:bg-yellow-900/30',
        danger: 'text-red-500 bg-red-100 dark:bg-red-900/30',
        info: 'text-blue-500 bg-blue-100 dark:bg-blue-900/30',
    };

    return (
        <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="w-full px-4 py-3 flex items-center justify-between bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            >
                <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${statusColors[status]}`}>
                        <Icon className="w-4 h-4" />
                    </div>
                    <span className="font-medium text-gray-900 dark:text-white">{title}</span>
                </div>
                {isOpen ? (
                    <ChevronUp className="w-5 h-5 text-gray-400" />
                ) : (
                    <ChevronDown className="w-5 h-5 text-gray-400" />
                )}
            </button>
            {isOpen && (
                <div className="px-4 py-4 bg-white dark:bg-gray-900 border-t border-gray-200 dark:border-gray-700">
                    {children}
                </div>
            )}
        </div>
    );
};

// Code block with copy button
const CodeBlock: React.FC<{ code: string; maxHeight?: string }> = ({ code, maxHeight = '300px' }) => {
    const [copied, setCopied] = useState(false);

    const handleCopy = () => {
        navigator.clipboard.writeText(code);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="relative">
            <button
                onClick={handleCopy}
                className="absolute top-2 right-2 p-2 bg-gray-700 hover:bg-gray-600 rounded text-gray-300 hover:text-white transition-colors"
            >
                {copied ? <CheckCircle className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            </button>
            <pre
                className="bg-gray-900 text-gray-100 p-4 rounded-lg text-xs font-mono overflow-auto"
                style={{ maxHeight }}
            >
                {code}
            </pre>
        </div>
    );
};

// Badge component
const Badge: React.FC<{ type: 'safe' | 'warning' | 'danger'; children: React.ReactNode }> = ({
    type,
    children,
}) => {
    const colors = {
        safe: 'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/30 dark:text-green-400 dark:border-green-800',
        warning: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-800',
        danger: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800',
    };

    return (
        <span className={`px-2 py-1 text-xs font-medium rounded-full border ${colors[type]}`}>
            {children}
        </span>
    );
};

export const ReviewerMode: React.FC<ReviewerModeProps> = ({ result, onClose }) => {
    if (!result) {
        return (
            <div className="text-center py-12">
                <Eye className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">No data to review</h3>
                <p className="text-gray-500 dark:text-gray-400 mt-1">
                    Verify a pickle file to see detailed analysis.
                </p>
            </div>
        );
    }

    const pt = result.pickletools;
    const consensus = result.consensus || result.aieyeResult;
    const isRisky = ['CRITICAL', 'HIGH'].includes(consensus);

    return (
        <div className="space-y-4">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                        <Eye className="w-6 h-6 text-purple-500" />
                        Reviewer Mode
                    </h2>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        Detailed inspection for manual verification
                    </p>
                </div>
                {onClose && (
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
                    >
                        <XCircle className="w-5 h-5 text-gray-400" />
                    </button>
                )}
            </div>

            {/* Summary Card */}
            <div className={`p-4 rounded-xl border-2 ${result.isFalsePositive ? 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-300 dark:border-yellow-700' :
                    result.isFalseNegative ? 'bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700' :
                        isRisky ? 'bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-700' :
                            'bg-green-50 dark:bg-green-900/20 border-green-300 dark:border-green-700'
                }`}>
                <div className="flex items-center justify-between">
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            {isRisky ? (
                                <AlertTriangle className="w-5 h-5 text-red-500" />
                            ) : (
                                <CheckCircle className="w-5 h-5 text-green-500" />
                            )}
                            <span className="font-bold text-lg text-gray-900 dark:text-white">
                                Consensus: {consensus}
                            </span>
                            {result.isFalsePositive && <Badge type="warning">Potential FP</Badge>}
                            {result.isFalseNegative && <Badge type="danger">Potential FN</Badge>}
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-300">
                            Confidence: {(result.confidence * 100).toFixed(0)}% •
                            Hash: <code className="text-xs">{result.fileHash.slice(0, 16)}...</code> •
                            Size: {result.fileSize} bytes
                        </p>
                    </div>
                    <div className="text-right">
                        <div className="text-sm text-gray-500">AIEye Score</div>
                        <div className="text-2xl font-bold text-gray-900 dark:text-white">
                            {result.aieyeScore}/100
                        </div>
                    </div>
                </div>

                {/* Reasoning */}
                {result.reasoning.length > 0 && (
                    <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                        <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Reasoning:</div>
                        <ul className="space-y-1">
                            {result.reasoning.map((r, i) => (
                                <li key={i} className="text-sm text-gray-600 dark:text-gray-400 flex items-start gap-2">
                                    <span className="text-gray-400">•</span>
                                    {r}
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>

            {/* Opcode Analysis */}
            <Section
                title="Opcode Sequence"
                icon={Code}
                defaultOpen={true}
                status={pt.hasReduce ? 'danger' : 'safe'}
            >
                <div className="space-y-4">
                    {/* Opcode flags */}
                    <div className="flex flex-wrap gap-2">
                        {pt.hasReduce && <Badge type="danger">REDUCE opcode</Badge>}
                        {pt.hasGlobal && <Badge type="warning">GLOBAL opcode</Badge>}
                        {!pt.hasReduce && !pt.hasGlobal && <Badge type="safe">No dangerous opcodes</Badge>}
                    </div>

                    {/* Opcode counts */}
                    <div>
                        <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Opcode Frequency:
                        </div>
                        <div className="flex flex-wrap gap-2">
                            {Object.entries(pt.opcodeCounts)
                                .sort(([, a], [, b]) => b - a)
                                .slice(0, 15)
                                .map(([opcode, count]) => (
                                    <span
                                        key={opcode}
                                        className={`px-2 py-1 text-xs rounded ${['REDUCE', 'GLOBAL', 'STACK_GLOBAL', 'INST', 'OBJ'].includes(opcode)
                                                ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'
                                                : 'bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300'
                                            }`}
                                    >
                                        {opcode}: {count}
                                    </span>
                                ))}
                        </div>
                    </div>

                    {/* Disassembly */}
                    <div>
                        <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Disassembly (pickletools):
                        </div>
                        <CodeBlock code={pt.disassembly || 'No disassembly available'} />
                    </div>
                </div>
            </Section>

            {/* Dangerous Globals */}
            {pt.dangerousGlobals.length > 0 && (
                <Section
                    title={`Dangerous GLOBAL References (${pt.dangerousGlobals.length})`}
                    icon={AlertTriangle}
                    defaultOpen={true}
                    status="danger"
                >
                    <div className="space-y-2">
                        {pt.dangerousGlobals.map((g, i) => (
                            <div
                                key={i}
                                className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-200 dark:border-red-800"
                            >
                                <code className="text-red-700 dark:text-red-400 font-medium">
                                    {g.module}.{g.name}
                                </code>
                                <p className="text-sm text-red-600 dark:text-red-300 mt-1">{g.reason}</p>
                            </div>
                        ))}
                    </div>
                </Section>
            )}

            {/* Fickling Results */}
            <Section
                title="Fickling Analysis"
                icon={Shield}
                status={!result.fickling.available ? 'info' : result.fickling.isSafe ? 'safe' : 'danger'}
            >
                {!result.fickling.available ? (
                    <p className="text-gray-500">Fickling not available on this server.</p>
                ) : (
                    <div className="space-y-3">
                        <div className="flex items-center gap-2">
                            {result.fickling.isSafe ? (
                                <>
                                    <CheckCircle className="w-5 h-5 text-green-500" />
                                    <span className="text-green-700 dark:text-green-400 font-medium">Safe</span>
                                </>
                            ) : (
                                <>
                                    <XCircle className="w-5 h-5 text-red-500" />
                                    <span className="text-red-700 dark:text-red-400 font-medium">Unsafe</span>
                                </>
                            )}
                        </div>
                        {result.fickling.findings.length > 0 && (
                            <div>
                                <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                    Findings:
                                </div>
                                <ul className="space-y-1">
                                    {result.fickling.findings.map((f, i) => (
                                        <li key={i} className="text-sm text-gray-600 dark:text-gray-400">
                                            • {f}
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        )}
                    </div>
                )}
            </Section>

            {/* Sandbox Results */}
            <Section
                title="Sandbox Load Test"
                icon={Cpu}
                status={result.sandbox.loadSucceeded ? 'safe' : result.sandbox.blockedImports.length > 0 ? 'danger' : 'warning'}
            >
                <div className="space-y-3">
                    {result.sandbox.loadSucceeded ? (
                        <div className="flex items-center gap-2">
                            <CheckCircle className="w-5 h-5 text-green-500" />
                            <span className="text-green-700 dark:text-green-400">
                                Loaded successfully as <code>{result.sandbox.loadedType}</code>
                            </span>
                        </div>
                    ) : (
                        <>
                            <div className="flex items-center gap-2">
                                <XCircle className="w-5 h-5 text-red-500" />
                                <span className="text-red-700 dark:text-red-400">Load blocked</span>
                            </div>
                            {result.sandbox.error && (
                                <p className="text-sm text-gray-600 dark:text-gray-400">
                                    Error: {result.sandbox.error}
                                </p>
                            )}
                        </>
                    )}

                    {result.sandbox.blockedImports.length > 0 && (
                        <div>
                            <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Blocked Imports:
                            </div>
                            <div className="flex flex-wrap gap-2">
                                {result.sandbox.blockedImports.map((imp, i) => (
                                    <code
                                        key={i}
                                        className="px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded text-xs"
                                    >
                                        {imp}
                                    </code>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </Section>

            {/* PEFT/Trainer Detection */}
            <Section
                title="Model Type Detection"
                icon={Package}
                status={result.peft.isPeftAdapter || result.peft.isTrainerOutput ? 'safe' : 'info'}
            >
                <div className="space-y-3">
                    <div className="flex flex-wrap gap-2">
                        {result.peft.isPeftAdapter && <Badge type="safe">PEFT Adapter</Badge>}
                        {result.peft.isTrainerOutput && <Badge type="safe">Trainer Output</Badge>}
                        {!result.peft.isPeftAdapter && !result.peft.isTrainerOutput && (
                            <Badge type="warning">Unknown Type</Badge>
                        )}
                    </div>

                    {result.peft.matchedSignatures.length > 0 && (
                        <div>
                            <div className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Matched Signatures:
                            </div>
                            <div className="flex flex-wrap gap-2">
                                {result.peft.matchedSignatures.map((sig, i) => (
                                    <code
                                        key={i}
                                        className="px-2 py-1 bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400 rounded text-xs"
                                    >
                                        {sig}
                                    </code>
                                ))}
                            </div>
                        </div>
                    )}

                    <p className="text-sm text-gray-500">
                        Confidence: {(result.peft.confidence * 100).toFixed(0)}%
                    </p>
                </div>
            </Section>

            {/* Raw Opcode Vector for debugging */}
            <Section title="Raw Opcode Vector" icon={FileCode}>
                <CodeBlock code={JSON.stringify(result.opcodeVector, null, 2)} maxHeight="200px" />
            </Section>
        </div>
    );
};

export default ReviewerMode;
