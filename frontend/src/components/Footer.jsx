import React from 'react';
import { ShieldCheck, Cpu, Terminal, Heart, ExternalLink } from 'lucide-react';

export default function Footer({ healthStatus }) {
  const engine = healthStatus?.engine || 'LightGBM + XGBoost + Random Forest Ensemble with SHAP XAI';

  return (
    <footer className="mt-16 border-t border-slate-800/80 bg-slate-950/60 text-slate-400 py-8 text-xs font-mono">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          {/* Engine & Defense Details */}
          <div className="flex items-center space-x-2 text-center md:text-left">
            <ShieldCheck className="w-4 h-4 text-cyan-400 flex-shrink-0" />
            <span>
              PhishGuard-AI SOC Intelligence Platform <span className="text-slate-600">|</span> v1.0.0 Production Core
            </span>
          </div>

          {/* Architecture credit */}
          <div className="flex items-center space-x-2 text-slate-400 text-center">
            <Cpu className="w-3.5 h-3.5 text-slate-500" />
            <span className="truncate max-w-md">{engine}</span>
          </div>

          {/* Status Indicator */}
          <div className="flex items-center space-x-2">
            <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span className="text-slate-300">ML Pipeline Active</span>
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-slate-900 text-center text-slate-400 text-[11px] flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>&copy; {new Date().getFullYear()} PhishGuard-AI. Built for Security Operations Centers and Cyber Analysts.</span>
          <div className="flex items-center space-x-4">
            <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="hover:text-cyan-400 transition-colors flex items-center gap-1">
              <span>FastAPI Docs</span>
              <ExternalLink className="w-3 h-3" />
            </a>
            <a href="http://localhost:8000/api/health" target="_blank" rel="noreferrer" className="hover:text-cyan-400 transition-colors flex items-center gap-1">
              <span>Health Endpoint</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
