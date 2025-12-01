import React from 'react';
import { Home, BarChart2, Clock, Info } from 'lucide-react';

interface SidebarProps {
    isOpen: boolean;
    onClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
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
                <div className="p-6 border-b border-gray-200 dark:border-gray-800 font-bold text-gray-700 dark:text-gray-300">
                    Menu
                </div>

                <nav className="p-4 space-y-3 text-gray-700 dark:text-gray-300">
                    <button className="flex items-center gap-3 w-full p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
                        <Home className="w-5 h-5" />
                        Dashboard
                    </button>

                    <button className="flex items-center gap-3 w-full p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
                        <BarChart2 className="w-5 h-5" />
                        Threat Intel Leaderboard
                    </button>

                    <button
                        className="flex items-center gap-3 w-full p-2 opacity-50 cursor-not-allowed rounded-lg"
                        title="Coming soon"
                    >
                        <Clock className="w-5 h-5" />
                        Scan History
                    </button>



                    <button className="flex items-center gap-3 w-full p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg">
                        <Info className="w-5 h-5" />
                        About
                    </button>
                </nav>
            </aside>
        </div>
    );
};
