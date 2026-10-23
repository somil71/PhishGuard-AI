import React, { useState, useEffect } from 'react';
import { 
  Cpu, 
  Layers, 
  Binary, 
  Lock, 
  Award, 
  Search, 
  BookOpen, 
  Code2, 
  Hash, 
  RefreshCw,
  Sigma,
  ShieldAlert
} from 'lucide-react';
import { getFeatureMetadata } from '../services/api';

const FEATURE_CATEGORIES = [
  {
    id: 'lexical',
    name: 'Lexical & Structural',
    icon: Hash,
    description: 'Syntactic, positional, and delimiter counts in URL components',
    features: [
      'url_length', 'domain_length', 'path_length', 'query_length', 
      'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes', 
      'num_question_marks', 'num_equals', 'num_at_symbols', 'num_ampersands', 
      'num_exclamations', 'num_percent', 'num_digits', 'digit_ratio', 
      'num_subdomains', 'consecutive_char_repeat', 'vowel_to_consonant_ratio'
    ]
  },
  {
    id: 'entropy',
    name: 'Entropy & Obfuscation',
    icon: Binary,
    description: 'Information entropy calculations revealing randomized hashes and payload packaging',
    features: ['url_entropy', 'domain_entropy', 'path_entropy', 'has_punycode'],
    formula: 'H(X) = - \\sum_{i=1}^n P(x_i) \\log_2 P(x_i)',
    formulaName: 'Shannon Information Entropy'
  },
  {
    id: 'security',
    name: 'Security & Transport',
    icon: Lock,
    description: 'Protocol encryption, non-standard network ports, open redirect indicators',
    features: ['has_ip', 'is_https', 'has_shortener', 'suspicious_tld', 'double_slash_in_path', 'has_port_in_url', 'prefix_suffix_hyphen']
  },
  {
    id: 'brand',
    name: 'Brand & Deception',
    icon: ShieldAlert,
    description: 'Typosquatting detection via string metrics and credential keyword analysis',
    features: ['sensitive_keywords_count', 'brand_impersonation', 'normalized_brand_dist', 'tld_in_subdomain'],
    formula: 'd_{i,j} = \\min(d_{i-1,j}+1, d_{i,j-1}+1, d_{i-1,j-1} + \\mathbb{I}(s_i \\neq t_j))',
    formulaName: 'Normalized Levenshtein Edit Distance'
  }
];

export default function ArchitectureExplorer() {
  const [activeCategory, setActiveCategory] = useState('lexical');
  const [searchTerm, setSearchTerm] = useState('');
  const [metadata, setMetadata] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchMetadata() {
      try {
        setLoading(true);
        const data = await getFeatureMetadata();
        setMetadata(data);
      } catch (err) {
        console.warn('Could not load remote feature metadata:', err);
      } finally {
        setLoading(false);
      }
    }
    fetchMetadata();
  }, []);

  const currentCategory = FEATURE_CATEGORIES.find(c => c.id === activeCategory);
  const descriptions = metadata?.descriptions || {};
  const statistics = metadata?.statistics || {};

  // Filter features based on search or category
  const filteredFeatures = currentCategory?.features.filter(f => 
    f.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (descriptions[f] || '').toLowerCase().includes(searchTerm.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <Cpu className="w-6 h-6 text-cyan-400" />
              <h2 className="text-xl font-bold text-white">
                34-Dimensional Feature Engineering Taxonomy
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Every URL is transformed into an analytical feature vector evaluated by tree ensemble models.
            </p>
          </div>
          <div className="flex items-center space-x-2">
            <span className="px-3 py-1 rounded-lg text-xs font-mono bg-cyan-950 text-cyan-300 border border-cyan-800">
              Feature Vector Dimension: 34
            </span>
          </div>
        </div>

        {/* Category Navigation Pills */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-6">
          {FEATURE_CATEGORIES.map((cat) => {
            const Icon = cat.icon;
            const isActive = activeCategory === cat.id;
            return (
              <button
                key={cat.id}
                onClick={() => setActiveCategory(cat.id)}
                className={`p-3 rounded-xl border text-left transition-all ${
                  isActive
                    ? 'bg-slate-800 border-cyan-500/50 shadow-md shadow-cyan-950/40 text-cyan-300'
                    : 'bg-slate-950/50 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-900 text-slate-300">
                    {cat.features.length}
                  </span>
                </div>
                <div className="text-xs font-semibold">{cat.name}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Math Formula Card if applicable */}
      {currentCategory?.formula && (
        <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-900/50 flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-900/40 text-cyan-300">
              <Sigma className="w-5 h-5" />
            </div>
            <div>
              <div className="text-xs font-mono font-bold text-cyan-300 uppercase tracking-wider">
                Mathematical Foundation: {currentCategory.formulaName}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Quantifies randomness or distance from ground-truth brand lexicons.
              </p>
            </div>
          </div>
          <div className="px-4 py-2 rounded-lg bg-slate-950 border border-cyan-900 font-mono text-xs text-cyan-300 tracking-wider">
            {currentCategory.formula}
          </div>
        </div>
      )}

      {/* Feature Catalog Grid */}
      <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
          <div>
            <h3 className="text-base font-semibold text-white">
              {currentCategory?.name} Specification
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              {currentCategory?.description}
            </p>
          </div>

          <div className="w-full sm:w-64">
            <div className="relative">
              <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-500" />
              <input
                type="text"
                placeholder="Search category features..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredFeatures.map((featKey) => {
            const desc = descriptions[featKey] || 'Custom engineered cyber telemetry indicator.';
            const stat = statistics[featKey];

            return (
              <div
                key={featKey}
                className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-cyan-500/40 transition-colors flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-cyan-300">
                      {featKey}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400">
                      {stat ? (stat.min === 0 && stat.max === 1 ? 'Boolean' : 'Float') : 'Numeric'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed mb-3">
                    {desc}
                  </p>
                </div>

                {stat && (
                  <div className="pt-2 border-t border-slate-800/80 text-[11px] font-mono grid grid-cols-3 gap-1 text-slate-400">
                    <div>
                      <span className="text-slate-500 block text-[9px]">MEAN</span>
                      <span className="text-slate-200">{stat.mean?.toFixed(2) ?? 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[9px]">STD</span>
                      <span className="text-slate-200">{stat.std?.toFixed(2) ?? 'N/A'}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[9px]">RANGE</span>
                      <span className="text-cyan-400">[{stat.min}, {stat.max}]</span>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
