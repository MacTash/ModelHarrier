/**
 * Verification Dashboard Component
 * 
 * Displays scanner metrics, FP/FN rates, drift alerts, and confidence scores.
 */
import React, { useState, useEffect } from 'react';
import {
    Activity,
    AlertTriangle,
    CheckCircle,
    TrendingUp,
    TrendingDown,
    RefreshCw,
    Database,
    BarChart3,
    Target,
    Zap,
} from 'lucide-react';

// Types for telemetry data (stored in localStorage)
export interface TelemetryRecord {
    fileHash: string;
    timestamp: string;
    label: string;
    fileSize: number;
    aieyeScore: number;
    consensusScore?: number;
    isFalsePositive: boolean;
    isFalseNegative: boolean;
    hasReduce: boolean;
    hasGlobal: boolean;
    dangerousGlobals: number;
    opcodeVector: number[];
    modelType?: string;
    confidence: number;
}

export interface DashboardStats {
    totalScans: number;
    byLabel: Record<string, number>;
    fpCount: number;
    fnCount: number;
    fpRate: number;
    fnRate: number;
    avgConfidence: number;
    byModelType: Record<string, number>;
}

export interface DriftAlert {
    label: string;
    recentPct: number;
    historicalPct: number;
    shift: number;
    significant: boolean;
}

// Local storage key
const TELEMETRY_KEY = 'aieye_telemetry';

// Load telemetry from localStorage
export function loadTelemetry(): TelemetryRecord[] {
    try {
        const data = localStorage.getItem(TELEMETRY_KEY);
        return data ? JSON.parse(data) : [];
    } catch {
        return [];
    }
}

// Save telemetry to localStorage
export function saveTelemetry(records: TelemetryRecord[]) {
    // Keep last 1000 records
    const trimmed = records.slice(-1000);
    localStorage.setItem(TELEMETRY_KEY, JSON.stringify(trimmed));
}

// Add a new telemetry record
export function addTelemetryRecord(record: TelemetryRecord) {
    const records = loadTelemetry();
    records.push(record);
    saveTelemetry(records);
}

// Calculate dashboard stats
function calculateStats(records: TelemetryRecord[]): DashboardStats {
    const stats: DashboardStats = {
        totalScans: records.length,
        byLabel: {},
        fpCount: 0,
        fnCount: 0,
        fpRate: 0,
        fnRate: 0,
        avgConfidence: 0,
        byModelType: {},
    };

    if (records.length === 0) return stats;

    let totalConfidence = 0;

    for (const record of records) {
        // By label
        stats.byLabel[record.label] = (stats.byLabel[record.label] || 0) + 1;

        // FP/FN
        if (record.isFalsePositive) stats.fpCount++;
        if (record.isFalseNegative) stats.fnCount++;

        // Confidence
        totalConfidence += record.confidence;

        // Model type
        const type = record.modelType || 'Unknown';
        stats.byModelType[type] = (stats.byModelType[type] || 0) + 1;
    }

    // Calculate rates
    const risky = (stats.byLabel['CRITICAL'] || 0) + (stats.byLabel['HIGH'] || 0);
    const safe = (stats.byLabel['SAFE'] || 0) + (stats.byLabel['LOW'] || 0);

    stats.fpRate = risky > 0 ? stats.fpCount / risky : 0;
    stats.fnRate = safe > 0 ? stats.fnCount / safe : 0;
    stats.avgConfidence = totalConfidence / records.length;

    return stats;
}

// Detect distribution shift
function detectDrift(records: TelemetryRecord[], windowDays = 7): DriftAlert[] {
    const now = new Date();
    const windowStart = new Date(now.getTime() - windowDays * 24 * 60 * 60 * 1000);

    const recent = records.filter(r => new Date(r.timestamp) > windowStart);
    const historical = records.filter(r => new Date(r.timestamp) <= windowStart);

    if (historical.length < 10) return []; // Not enough history

    const recentLabels: Record<string, number> = {};
    const historicalLabels: Record<string, number> = {};

    recent.forEach(r => {
        recentLabels[r.label] = (recentLabels[r.label] || 0) + 1;
    });

    historical.forEach(r => {
        historicalLabels[r.label] = (historicalLabels[r.label] || 0) + 1;
    });

    const allLabels = new Set([...Object.keys(recentLabels), ...Object.keys(historicalLabels)]);
    const recentTotal = recent.length || 1;
    const historicalTotal = historical.length || 1;

    const alerts: DriftAlert[] = [];

    allLabels.forEach(label => {
        const recentPct = (recentLabels[label] || 0) / recentTotal * 100;
        const historicalPct = (historicalLabels[label] || 0) / historicalTotal * 100;
        const shift = recentPct - historicalPct;

        alerts.push({
            label,
            recentPct: Math.round(recentPct * 10) / 10,
            historicalPct: Math.round(historicalPct * 10) / 10,
            shift: Math.round(shift * 10) / 10,
            significant: Math.abs(shift) > 10,
        });
    });

    return alerts.sort((a, b) => Math.abs(b.shift) - Math.abs(a.shift));
}

// Stat card component
interface StatCardProps {
    icon: React.ElementType;
    label: string;
    value: string | number;
    subtext?: string;
    trend?: 'up' | 'down' | 'neutral';
    trendValue?: string;
    color?: 'blue' | 'green' | 'red' | 'yellow' | 'purple';
}

const StatCard: React.FC<StatCardProps> = ({
    icon: Icon,
    label,
    value,
    subtext,
    trend,
    trendValue,
    color = 'blue',
}) => {
    const colorClasses = {
        blue: 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400',
        green: 'bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400',
        red: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400',
        yellow: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400',
        purple: 'bg-purple-100 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400',
    };

    return (
        <div className="bg-white dark:bg-gray-800 p-5 rounded-xl border border-gray-200 dark:border-gray-700 shadow-sm">
            <div className="flex items-start justify-between">
                <div className={`p-3 rounded-lg ${colorClasses[color]}`}>
                    <Icon className="w-5 h-5" />
                </div>
                {trend && (
                    <div className={`flex items-center text-xs ${trend === 'up' ? 'text-green-500' : trend === 'down' ? 'text-red-500' : 'text-gray-400'
                        }`}>
                        {trend === 'up' ? <TrendingUp className="w-3 h-3 mr-1" /> :
                            trend === 'down' ? <TrendingDown className="w-3 h-3 mr-1" /> : null}
                        {trendValue}
                    </div>
                )}
            </div>
            <div className="mt-4">
                <p className="text-sm text-gray-500 dark:text-gray-400 font-medium">{label}</p>
                <h3 className="text-2xl font-bold text-gray-900 dark:text-white mt-1">{value}</h3>
                {subtext && <p className="text-xs text-gray-400 mt-1">{subtext}</p>}
            </div>
        </div>
    );
};

// Main Dashboard Component
export const VerificationDashboard: React.FC = () => {
    const [, setRecords] = useState<TelemetryRecord[]>([]);
    const [stats, setStats] = useState<DashboardStats | null>(null);
    const [driftAlerts, setDriftAlerts] = useState<DriftAlert[]>([]);
    const [isRefreshing, setIsRefreshing] = useState(false);

    const refresh = () => {
        setIsRefreshing(true);
        const data = loadTelemetry();
        setRecords(data);
        setStats(calculateStats(data));
        setDriftAlerts(detectDrift(data));
        setTimeout(() => setIsRefreshing(false), 500);
    };

    useEffect(() => {
        refresh();
    }, []);

    const significantDrift = driftAlerts.filter(d => d.significant);

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                        <Activity className="w-6 h-6 text-blue-500" />
                        Verification Dashboard
                    </h2>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                        Scanner metrics, drift detection, and confidence tracking
                    </p>
                </div>
                <button
                    onClick={refresh}
                    disabled={isRefreshing}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50"
                >
                    <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
                    Refresh
                </button>
            </div>

            {/* Drift Alert Banner */}
            {significantDrift.length > 0 && (
                <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-xl p-4">
                    <div className="flex items-start gap-3">
                        <AlertTriangle className="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0 mt-0.5" />
                        <div>
                            <h4 className="font-semibold text-yellow-800 dark:text-yellow-200">Distribution Drift Detected</h4>
                            <p className="text-sm text-yellow-700 dark:text-yellow-300 mt-1">
                                {significantDrift.map(d => (
                                    <span key={d.label} className="mr-3">
                                        {d.label}: {d.shift > 0 ? '+' : ''}{d.shift}%
                                    </span>
                                ))}
                            </p>
                        </div>
                    </div>
                </div>
            )}

            {/* Stats Grid */}
            {stats && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCard
                        icon={Database}
                        label="Total Scans"
                        value={stats.totalScans}
                        subtext="All time"
                        color="blue"
                    />
                    <StatCard
                        icon={AlertTriangle}
                        label="False Positives"
                        value={stats.fpCount}
                        subtext={`${(stats.fpRate * 100).toFixed(1)}% of risky flags`}
                        color={stats.fpRate > 0.1 ? 'red' : 'green'}
                    />
                    <StatCard
                        icon={Zap}
                        label="False Negatives"
                        value={stats.fnCount}
                        subtext={`${(stats.fnRate * 100).toFixed(1)}% of safe flags`}
                        color={stats.fnRate > 0.05 ? 'red' : 'green'}
                    />
                    <StatCard
                        icon={Target}
                        label="Avg Confidence"
                        value={`${(stats.avgConfidence * 100).toFixed(0)}%`}
                        subtext="Triangulation confidence"
                        color={stats.avgConfidence > 0.7 ? 'green' : 'yellow'}
                    />
                </div>
            )}

            {/* Label Distribution Table */}
            {stats && stats.totalScans > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
                    <div className="p-4 border-b border-gray-100 dark:border-gray-700">
                        <h3 className="font-bold text-gray-900 dark:text-white flex items-center gap-2">
                            <BarChart3 className="w-5 h-5 text-gray-500" />
                            Label Distribution
                        </h3>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead className="bg-gray-50 dark:bg-gray-900/50">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Label</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Count</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Percentage</th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Drift</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100 dark:divide-gray-700">
                                {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'].map(label => {
                                    const count = stats.byLabel[label] || 0;
                                    const pct = stats.totalScans > 0 ? (count / stats.totalScans * 100).toFixed(1) : '0';
                                    const drift = driftAlerts.find(d => d.label === label);

                                    return (
                                        <tr key={label} className="hover:bg-gray-50 dark:hover:bg-gray-700/50">
                                            <td className="px-4 py-3 text-sm font-medium text-gray-900 dark:text-white">
                                                <span className={`inline-flex items-center gap-2 ${label === 'CRITICAL' ? 'text-red-600' :
                                                    label === 'HIGH' ? 'text-orange-600' :
                                                        label === 'MEDIUM' ? 'text-yellow-600' :
                                                            label === 'LOW' ? 'text-blue-600' : 'text-green-600'
                                                    }`}>
                                                    {label === 'CRITICAL' || label === 'HIGH' ? (
                                                        <AlertTriangle className="w-3 h-3" />
                                                    ) : (
                                                        <CheckCircle className="w-3 h-3" />
                                                    )}
                                                    {label}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">{count}</td>
                                            <td className="px-4 py-3 text-sm text-gray-600 dark:text-gray-300">{pct}%</td>
                                            <td className="px-4 py-3 text-sm">
                                                {drift && (
                                                    <span className={`${drift.significant
                                                        ? drift.shift > 0 ? 'text-red-500' : 'text-green-500'
                                                        : 'text-gray-400'
                                                        }`}>
                                                        {drift.shift > 0 ? '+' : ''}{drift.shift}%
                                                    </span>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* Model Type Breakdown */}
            {stats && Object.keys(stats.byModelType).length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
                    <h3 className="font-bold text-gray-900 dark:text-white mb-4">Model Types Scanned</h3>
                    <div className="flex flex-wrap gap-2">
                        {Object.entries(stats.byModelType).map(([type, count]) => (
                            <span
                                key={type}
                                className="px-3 py-1 bg-gray-100 dark:bg-gray-700 rounded-full text-sm text-gray-600 dark:text-gray-300"
                            >
                                {type}: {count}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Empty State */}
            {stats && stats.totalScans === 0 && (
                <div className="text-center py-12">
                    <Database className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-gray-900 dark:text-white">No scan data yet</h3>
                    <p className="text-gray-500 dark:text-gray-400 mt-1">
                        Scan some models to start collecting telemetry data.
                    </p>
                </div>
            )}
        </div>
    );
};

export default VerificationDashboard;
