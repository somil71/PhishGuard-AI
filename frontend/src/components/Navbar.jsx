import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Layers, 
  BarChart3, 
  ListFilter, 
  Cpu, 
  Radio, 
  Activity,
  Terminal,
  Code
} from 'lucide-react';

export default function Navbar({ activeTab, setActiveTab, healthStatus, onRefreshHealth }) {
  const navItems = [
    { id: 'scanner', label: 'URL Threat Scanner', icon: ShieldAlert, badge: 'Live' },
    { id: 'batch', label: 'Batch SOC Triage', icon: ListFilter, badge: 'Bulk' },
    { id: 'metrics', label: 'Model Metrics & XAI', icon: BarChart3, badge: '99.9%' },
    { id: 'architecture', label: '34-Feature Heuristics', icon: Cpu, badge: 'Core' }
  ];

  const isOnline = healthStatus?.status === 'online';

  return (
    <header className="sticky top-0 z-50 backdrop-blur-md bg-slate-950/85 border-b border-slate-800/80">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand Identity */}
          <div className="flex items-center space-x-3 cursor-pointer" onClick={() => setActiveTab('scanner')}>
            <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/30 border border-cyan-500/40 glow-cyan">
              <ShieldCheck className="w-5 h-5 text-cyan-400 animate-pulse" />
              <span className="absolute -top-0.5 -right-0.5 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-lg font-bold tracking-tight text-white font-mono">
                  PHISHGUARD<span className="text-cyan-400">-AI</span>
                </span>
                <span className="px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-cyan-300 bg-cyan-950/80 border border-cyan-800/60 rounded">
                  v1.0 SOC
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Ensemble ML & SHAP Explainable Phishing Intelligence
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center space-x-1 lg:space-x-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`relative flex items-center space-x-2 px-3 py-2 rounded-lg text-xs lg:text-sm font-medium transition-all duration-150 ${
                    isActive
                      ? 'bg-slate-800 text-cyan-300 border border-cyan-500/30 shadow-sm shadow-cyan-950/50'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60 border border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span>{item.label}</span>
                  {item.badge && (
                    <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                      isActive ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/50' : 'bg-slate-800/70 text-slate-400'
                    }`}>
                      {item.badge}
                    </span>
                  )}
                  {isActive && (
                    <span className="absolute bottom-0 left-2 right-2 h-0.5 bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full" />
                  )}
                </button>
              );
            })}
          </nav>

          {/* SOC Status & External Links */}
          <div className="flex items-center space-x-3">
            {/* Live Backend Heartbeat */}
            <div 
              onClick={onRefreshHealth}
              title={isOnline ? "Backend ML Inference Engine Online" : "Checking Backend Status..."}
              className="flex items-center space-x-2 px-2.5 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs cursor-pointer hover:border-slate-700 transition-colors"
            >
              <div className="relative flex items-center justify-center">
                <span className={`h-2 w-2 rounded-full ${isOnline ? 'bg-emerald-400' : 'bg-amber-400'} animate-pulse`} />
                {isOnline && (
                  <span className="animate-ping absolute h-3.5 w-3.5 rounded-full bg-emerald-400/30" />
                )}
              </div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-300 hidden sm:inline">
                {isOnline ? 'SOC CORE ONLINE' : 'CONNECTING'}
              </span>
            </div>

            {/* GitHub / Repo Badge */}
            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              className="p-2 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-slate-800 transition-colors"
              title="PhishGuard-AI Source"
            >
              <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
            </a>
          </div>
        </div>

        {/* Mobile Navigation bar */}
        <div className="flex md:hidden overflow-x-auto py-2 space-x-1 border-t border-slate-800/60 custom-scrollbar">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                className={`flex items-center space-x-1 px-2.5 py-1.5 rounded-md text-xs whitespace-nowrap ${
                  isActive
                    ? 'bg-slate-800 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:bg-slate-900'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
}
