import React from 'react';
import { Home, BarChart2, Clock, Info, Target, X } from 'lucide-react';

export type SidebarTab = 'dashboard' | 'leaderboard' | 'redteam' | 'history' | 'about';

interface SidebarProps {
    isOpen: boolean;
    onClose: () => void;
    activeTab: SidebarTab;
    onTabChange: (tab: SidebarTab) => void;
    hasScannedModel: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
    isOpen,
    onClose,
    activeTab,
    onTabChange,
    hasScannedModel
}) => {
    const handleTabClick = (tab: SidebarTab) => {
        onTabChange(tab);
        onClose();
    };

    const getTabClasses = (tab: SidebarTab, disabled = false) => {
        const base = "flex items-center gap-3 w-full p-2 rounded-lg transition-colors";
        if (disabled) return `${base} opacity-50 cursor-not-allowed`;
        if (activeTab === tab) return `${base} bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-400`;
        return `${base} hover:bg-gray-100 dark:hover:bg-gray-800`;
    };

    return (
        <div>
            {/* Sidebar backdrop */}
            {isOpen && (
                <div
                    className="fixed inset-0 bg-black/40 z-40"
                    onClick={onClose}
                />
            )}

            {/* Sidebar panel */}
            <aside
                className={`fixed top-0 left-0 h-full w-64 bg-white dark:bg-gray-900 shadow-lg z-50 transform transition-transform
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

                <nav className="p-4 space-y-2 text-gray-700 dark:text-gray-300">
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
                        onClick={() => handleTabClick('leaderboard')}
                        className={getTabClasses('leaderboard')}
                    >
                        <BarChart2 className="w-5 h-5" />
                        Threat Intel Leaderboard
                    </button>

                    <button
                        className={getTabClasses('history', true)}
                        title="Coming soon"
                    >
                        <Clock className="w-5 h-5" />
                        Scan History
                        <span className="text-xs bg-gray-200 dark:bg-gray-700 px-1.5 py-0.5 rounded ml-auto">
                            Soon
                        </span>
                    </button>

                    <button
                        onClick={() => handleTabClick('about')}
                        className={getTabClasses('about')}
                    >
                        <Info className="w-5 h-5" />
                        About
                    </button>
                </nav>
            </aside>
        </div>
    );
};

