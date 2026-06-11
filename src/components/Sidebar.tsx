import React from 'react';
import { Home, BarChart2, Clock, Info, Target, X, Activity, Eye, Trash2 } from 'lucide-react';
import type { ScanHistoryEntry } from '../utils/scanHistory';

export type SidebarTab = 'dashboard' | 'leaderboard' | 'redteam' | 'verification' | 'reviewer' | 'history' | 'about';

interface SidebarProps {
    isOpen: boolean;
    onClose: () => void;
    activeTab: SidebarTab;
    onTabChange: (tab: SidebarTab) => void;
    hasScannedModel: boolean;
    scanHistory: ScanHistoryEntry[];
    onHistorySelect: (modelId: string) => void;
    onClearHistory: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
    isOpen,
    onClose,
    activeTab,
    onTabChange,
    hasScannedModel,
    scanHistory,
    onHistorySelect,
    onClearHistory,
}) => {
    const handleTabClick = (tab: SidebarTab) => {
        onTabChange(tab);
    };

    const getTabClasses = (tab: SidebarTab, disabled = false) => {
        const base = "flex items-center gap-3 w-full p-2 rounded-lg transition-colors";
        if (disabled) return `${base} opacity-50 cursor-not-allowed`;
        if (activeTab === tab) return `${base} bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400`;
        return `${base} hover:bg-gray-100 dark:hover:bg-gray-800`;
    };

    return (
        <div>
            {isOpen && (
                <div
                    className="fixed inset-0 bg-black/40 z-40"
                    onClick={onClose}
                />
            )}

            <aside
                className={`fixed top-0 left-0 h-full w-72 bg-white dark:bg-gray-900 shadow-lg z-50 transform transition-transform flex flex-col
        ${isOpen ? 'translate-x-0' : '-translate-x-full'}`}
            >
                <div className="p-6 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center">
                    <span className="font-bold text-gray-700 dark:text-gray-300">Menu</span>
                    <button
                        onClick={onClose}
                        className="p-1 hover:bg-gray-100 dark:hover:bg-gray-800 rounded"
                    >
                        <X className="w-5 h-5 text-gray-500" />
                    </button>
                </div>

                <nav className="p-4 space-y-2 text-gray-700 dark:text-gray-300 overflow-y-auto flex-1">
                    <button
                        onClick={() => handleTabClick('dashboard')}
                        className={getTabClasses('dashboard')}
                    >
                        <Home className="w-5 h-5" />
                        Dashboard
                    </button>

                    <button
                        onClick={() => hasScannedModel && handleTabClick('redteam')}
                        className={getTabClasses('redteam', !hasScannedModel)}
                        title={hasScannedModel ? 'Red Team Testing' : 'Scan a model first'}
                    >
                        <Target className="w-5 h-5" />
                        Red Team
                        {!hasScannedModel && (
                            <span className="text-xs bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded ml-auto">
                                Scan first
                            </span>
                        )}
                    </button>

                    <button
                        onClick={() => handleTabClick('verification')}
                        className={getTabClasses('verification')}
                    >
                        <Activity className="w-5 h-5" />
                        Verification
                        <span className="text-xs bg-green-100 dark:bg-green-900/30 text-green-600 dark:text-green-400 px-1.5 py-0.5 rounded ml-auto">
                            New
                        </span>
                    </button>

                    <button
                        onClick={() => hasScannedModel && handleTabClick('reviewer')}
                        className={getTabClasses('reviewer', !hasScannedModel)}
                        title={hasScannedModel ? 'Review scan details' : 'Scan a model first'}
                    >
                        <Eye className="w-5 h-5" />
                        Reviewer Mode
                        {!hasScannedModel && (
                            <span className="text-xs bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded ml-auto">
                                Scan first
                            </span>
                        )}
                    </button>

                    <button
                        onClick={() => handleTabClick('leaderboard')}
                        className={getTabClasses('leaderboard')}
                    >
                        <BarChart2 className="w-5 h-5" />
                        Threat Intel Leaderboard
                    </button>

                    <button
                        onClick={() => handleTabClick('history')}
                        className={getTabClasses('history')}
                    >
                        <Clock className="w-5 h-5" />
                        Scan History
                        {scanHistory.length > 0 && (
                            <span className="text-xs bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded ml-auto">
                                {scanHistory.length}
                            </span>
                        )}
                    </button>

                    <button
                        onClick={() => handleTabClick('about')}
                        className={getTabClasses('about')}
                    >
                        <Info className="w-5 h-5" />
                        About
                    </button>
                </nav>

                {activeTab === 'history' && scanHistory.length > 0 && (
                    <div className="border-t border-gray-200 dark:border-gray-800 p-4">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-medium text-gray-500 dark:text-gray-400">Recent scans</span>
                            <button
                                onClick={onClearHistory}
                                className="text-xs text-red-500 hover:text-red-600 flex items-center gap-1"
                            >
                                <Trash2 className="w-3 h-3" />
                                Clear
                            </button>
                        </div>
                        <div className="space-y-1 max-h-48 overflow-y-auto">
                            {scanHistory.map((entry) => (
                                <button
                                    key={entry.modelId + entry.timestamp}
                                    onClick={() => {
                                        onHistorySelect(entry.modelId);
                                        onClose();
                                    }}
                                    className="w-full text-left p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                                >
                                    <div className="text-xs font-medium text-gray-900 dark:text-white truncate">
                                        {entry.modelId}
                                    </div>
                                    <div className="flex items-center gap-2 mt-0.5">
                                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${
                                            entry.severity === 'Critical' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
                                            entry.severity === 'High' ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' :
                                            entry.severity === 'Medium' ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400' :
                                            'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                                        }`}>
                                            {entry.severity}
                                        </span>
                                        <span className="text-[10px] text-gray-400">{entry.overallScore}/10</span>
                                    </div>
                                </button>
                            ))}
                        </div>
                    </div>
                )}
            </aside>
        </div>
    );
};
