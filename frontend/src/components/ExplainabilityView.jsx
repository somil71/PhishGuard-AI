import React, { useState } from 'react';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  Cell, 
  ReferenceLine 
} from 'recharts';
import { Sparkles, TrendingUp, TrendingDown, HelpCircle, Info, ChevronDown, ChevronUp } from 'lucide-react';

export default function ExplainabilityView({ attributions = [] }) {
  const [viewMode, setViewMode] = useState('chart'); // 'chart' or 'cards'
  const [expandedIndex, setExpandedIndex] = useState(null);

  if (!attributions || attributions.length === 0) {
    return (
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 text-center">
        <Sparkles className="w-8 h-8 text-cyan-500/50 mx-auto mb-2" />
        <p className="text-sm text-slate-400">SHAP feature attributions not generated for this scan.</p>
      </div>
    );
  }

  // Format data for Recharts
  const chartData = attributions.map((item) => ({
    name: item.feature.replace(/_/g, ' '),
    rawFeature: item.feature,
    shapValue: Number(item.shap_value.toFixed(4)),
    absShap: Math.abs(item.shap_value),
    direction: item.direction,
    value: item.value,
    description: item.description,
    explanation: item.explanation
  }));

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      const isRisk = data.shapValue > 0;
      return (
        <div className="p-3 bg-slate-950 border border-slate-700 rounded-xl shadow-xl max-w-xs font-sans text-xs">
          <div className="flex items-center justify-between font-mono font-bold mb-1">
            <span className="text-white capitalize">{data.name}</span>
            <span className={isRisk ? 'text-rose-400' : 'text-emerald-400'}>
              {isRisk ? `+${data.shapValue}` : data.shapValue}
            </span>
          </div>
          <div className="text-slate-400 mb-1">
            Feature Value: <span className="text-cyan-300 font-mono font-semibold">{data.value}</span>
          </div>
          <div className="text-slate-300 text-[11px] leading-relaxed">
            {data.explanation}
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div>
          <div className="flex items-center space-x-2">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-semibold text-white">
              SHAP Explainable AI (XAI) Attributions
            </h3>
            <span className="px-2 py-0.5 text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800 rounded">
              TreeSHAP
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Exact mathematical contribution of top features driving the ensemble's verdict.
          </p>
        </div>

        {/* View Toggle */}
        <div className="flex items-center space-x-1 p-1 bg-slate-950/80 rounded-lg border border-slate-800 text-xs">
          <button
            onClick={() => setViewMode('chart')}
            className={`px-3 py-1 rounded-md font-medium transition-colors ${
              viewMode === 'chart' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Chart View
          </button>
          <button
            onClick={() => setViewMode('cards')}
            className={`px-3 py-1 rounded-md font-medium transition-colors ${
              viewMode === 'cards' ? 'bg-cyan-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Detailed Ledger
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center space-x-6 text-xs text-slate-400 mb-4 pb-3 border-b border-slate-800/80">
        <div className="flex items-center space-x-2">
          <span className="w-3 h-3 rounded bg-rose-500 inline-block" />
          <span>Increases Phishing Threat (+SHAP)</span>
        </div>
        <div className="flex items-center space-x-2">
          <span className="w-3 h-3 rounded bg-emerald-500 inline-block" />
          <span>Supports Benign Classification (-SHAP)</span>
        </div>
      </div>

      {/* Recharts Bar Chart */}
      {viewMode === 'chart' ? (
        <div className="w-full h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={chartData}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 95, bottom: 5 }}
            >
              <XAxis
                type="number"
                stroke="#64748b"
                fontSize={11}
                tickFormatter={(val) => val.toFixed(2)}
              />
              <YAxis
                type="category"
                dataKey="name"
                stroke="#94a3b8"
                fontSize={11}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <ReferenceLine x={0} stroke="#475569" strokeDasharray="3 3" />
              <Bar dataKey="shapValue" radius={[4, 4, 4, 4]}>
                {chartData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.shapValue > 0 ? '#f43f5e' : '#10b981'}
                    opacity={0.9}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      ) : (
        /* Detailed List / Cards View */
        <div className="space-y-2.5 max-h-96 overflow-y-auto pr-1 custom-scrollbar">
          {attributions.map((attr, idx) => {
            const isDanger = attr.shap_value > 0;
            const isExpanded = expandedIndex === idx;
            return (
              <div
                key={idx}
                className={`p-3.5 rounded-xl border transition-all ${
                  isDanger
                    ? 'bg-rose-950/20 border-rose-900/40 hover:border-rose-700/60'
                    : 'bg-emerald-950/20 border-emerald-900/40 hover:border-emerald-700/60'
                }`}
              >
                <div 
                  className="flex items-center justify-between cursor-pointer"
                  onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                >
                  <div className="flex items-center space-x-2.5">
                    {isDanger ? (
                      <TrendingUp className="w-4 h-4 text-rose-400 flex-shrink-0" />
                    ) : (
                      <TrendingDown className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                    )}
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-sm font-semibold text-slate-100">
                          {attr.feature}
                        </span>
                        <span className="text-xs px-2 py-0.2 rounded font-mono bg-slate-800 text-cyan-300">
                          val: {attr.value}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5 line-clamp-1">
                        {attr.description}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <span className={`font-mono text-xs font-bold px-2 py-1 rounded ${
                      isDanger ? 'bg-rose-900/40 text-rose-300' : 'bg-emerald-900/40 text-emerald-300'
                    }`}>
                      {isDanger ? `+${attr.shap_value.toFixed(4)}` : attr.shap_value.toFixed(4)}
                    </span>
                    {isExpanded ? (
                      <ChevronUp className="w-4 h-4 text-slate-500" />
                    ) : (
                      <ChevronDown className="w-4 h-4 text-slate-500" />
                    )}
                  </div>
                </div>

                {isExpanded && (
                  <div className="mt-3 pt-3 border-t border-slate-800 text-xs text-slate-300 bg-slate-950/50 p-2.5 rounded-lg">
                    <div className="font-semibold text-cyan-400 mb-1 flex items-center gap-1">
                      <Info className="w-3.5 h-3.5" /> SOC Analyst Explanation:
                    </div>
                    {attr.explanation}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
