import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  FileCode, FolderSearch, Zap, CheckCircle2, AlertTriangle,
  ChevronDown, ChevronUp, ExternalLink, Cpu, Package, GitCompare,
  Terminal, Layers, Sparkles
} from 'lucide-react';
import axios from 'axios';
import { API_BASE, TOKEN_KEY } from '../lib/api.js';

const SCAN_MODES = [
  { id: 'ast', label: 'STATIC (AST)', icon: FileCode, endpoint: '/scan/source', paramKey: 'target_path', placeholder: 'e.g. ./app/engines/sample_target.py or ./src', desc: 'AST-based Python / JS AST discovery' },
  { id: 'semgrep', label: 'SEMGREP (RULES)', icon: Terminal, endpoint: '/scan/semgrep', paramKey: 'target_path', placeholder: 'e.g. ./app or ./sample_target.py', desc: 'OWASP crypto.yml ruleset analyzer' },
  { id: 'container', label: 'CONTAINER (SYFT)', icon: Package, endpoint: '/scan/container', paramKey: 'image_or_path', placeholder: 'e.g. nginx:1.24-alpine or python:3.9-slim', desc: 'Syft & container layer cryptographic SBOM inspector' },
  { id: 'binary', label: 'BINARY (LIEF)', icon: Cpu, endpoint: '/scan/binary', paramKey: 'filepath', placeholder: 'Path to ELF/PE or type "SAMPLE" for ML-KEM demo', desc: 'LIEF reverse-engineering & ML-KEM NTT constants detection' },
];

const RISK_COLOR = (score) =>
  score < 30 ? 'text-red-400' : score < 60 ? 'text-amber-400' : 'text-emerald-400';

const RISK_BG = (score) =>
  score < 30 ? 'bg-red-900/30 border-red-700/40' : score < 60 ? 'bg-amber-900/30 border-amber-700/40' : 'bg-emerald-900/30 border-emerald-700/40';

const FindingCard = ({ finding }) => {
  const [open, setOpen] = useState(false);
  const loc = finding.file || finding.offset || finding.evidence || '';
  return (
    <div className={`rounded-lg border ${RISK_BG(finding.qtri_score)} p-3 transition-all`}>
      <button
        className="w-full text-left flex items-center justify-between gap-2"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2 min-w-0">
          <AlertTriangle size={12} className={RISK_COLOR(finding.qtri_score)} />
          <span className="font-black text-slate-200 text-xs font-mono truncate">{finding.algorithm}</span>
          {loc && (
            <span className="text-[9px] text-slate-500 font-mono shrink-0">
              {String(loc).split(/[\\/]/).pop()}
              {finding.line ? `:${finding.line}` : ''}
            </span>
          )}
          {finding.is_pqc && (
            <span className="text-[8px] font-black font-mono text-emerald-300 bg-emerald-950/60 border border-emerald-700/50 px-1 rounded">
              PQC NTT
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-[10px] font-black font-mono ${RISK_COLOR(finding.qtri_score)}`}>
            QTRI {finding.qtri_score}
          </span>
          {open ? <ChevronUp size={12} className="text-slate-500" /> : <ChevronDown size={12} className="text-slate-500" />}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.18 }}
            className="overflow-hidden"
          >
            <div className="mt-3 pt-3 border-t border-slate-700/50 space-y-1.5 text-[10px] font-mono text-slate-400">
              {finding.rule_id && <div><span className="text-slate-500">Identifier: </span>{finding.rule_id}</div>}
              {finding.evidence && <div><span className="text-slate-500">Evidence: </span>{finding.evidence}</div>}
              {finding.offset && <div><span className="text-slate-500">Byte Offset: </span>{finding.offset}</div>}
              {finding.file && <div className="truncate" title={finding.file}><span className="text-slate-500">Target: </span>{finding.file}</div>}
              {finding.recommendation && (
                <div className="text-cyan-400 mt-1 bg-cyan-900/20 border border-cyan-800/30 rounded px-2 py-1">
                  {'\u2192'} {finding.recommendation}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

const SourceScanner = ({ onScanComplete }) => {
  const token = localStorage.getItem(TOKEN_KEY);
  const [activeTab, setActiveTab] = useState('ast');
  const [inputVal, setInputVal] = useState('');
  const [loading, setLoading] = useState(false);
  const [reconciling, setReconciling] = useState(false);
  const [result, setResult] = useState(null);
  const [reconcileResult, setReconcileResult] = useState(null);
  const [error, setError] = useState('');

  const currentMode = SCAN_MODES.find(m => m.id === activeTab) || SCAN_MODES[0];

  const runScan = async () => {
    const val = inputVal.trim();
    if (!val && activeTab !== 'binary') {
      setError(`Please enter a valid target for ${currentMode.label}.`);
      return;
    }
    const finalVal = (!val && activeTab === 'binary') ? 'SAMPLE' : val;

    setLoading(true);
    setError('');
    setResult(null);
    try {
      const payload = { [currentMode.paramKey]: finalVal };
      const res = await axios.post(
        `${API_BASE}${currentMode.endpoint}`,
        payload,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setResult(res.data);
      if (onScanComplete) onScanComplete();
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  const runReconcile = async () => {
    setReconciling(true);
    setError('');
    try {
      const res = await axios.post(
        `${API_BASE}/cbom/reconcile`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setReconcileResult(res.data);
      if (onScanComplete) onScanComplete();
    } catch (e) {
      setError(e.response?.data?.detail || e.message || 'Reconciliation failed.');
    } finally {
      setReconciling(false);
    }
  };

  const criticalCount = result?.findings_summary?.filter(f => f.qtri_score < 30).length ?? 0;
  const warnCount    = result?.findings_summary?.filter(f => f.qtri_score >= 30 && f.qtri_score < 60).length ?? 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="glass-card border border-slate-800/80 overflow-hidden"
    >
      {/* Header with Mode Tabs */}
      <div className="bg-slate-950/90 border-b border-slate-800 px-5 pt-4 pb-0">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3">
          <div className="flex items-center gap-2.5">
            <Layers size={18} className="text-violet-400" />
            <div>
              <h3 className="text-violet-400 font-black text-xs tracking-widest font-mono">
                MULTI-SOURCE CRYPTO DISCOVERY PLATFORM
              </h3>
              <p className="text-[10px] text-slate-400 mt-0.5 font-mono">
                {currentMode.desc}
              </p>
            </div>
          </div>

          {/* Quick Reconcile Button */}
          <button
            onClick={runReconcile}
            disabled={reconciling}
            className="flex items-center gap-1.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 text-[10px] font-black tracking-widest px-3 py-1.5 rounded-lg transition-all active:scale-95 font-mono whitespace-nowrap self-start sm:self-auto"
          >
            {reconciling
              ? <span className="w-2.5 h-2.5 border-2 border-amber-400/30 border-t-amber-400 rounded-full animate-spin" />
              : <GitCompare size={12} />
            }
            {reconciling ? 'CORRELATING...' : 'RECONCILE CBOM'}
          </button>
        </div>

        {/* Scan Vector Selector Tabs */}
        <div className="flex gap-1 overflow-x-auto border-t border-slate-800/80 pt-2 scrollbar-none">
          {SCAN_MODES.map(mode => {
            const Icon = mode.icon;
            const active = activeTab === mode.id;
            return (
              <button
                key={mode.id}
                onClick={() => {
                  setActiveTab(mode.id);
                  setResult(null);
                  setError('');
                }}
                className={`flex items-center gap-1.5 px-3 py-2 text-[10px] font-black font-mono tracking-wider transition-all border-b-2 whitespace-nowrap ${
                  active
                    ? 'text-violet-300 border-violet-500 bg-violet-950/20'
                    : 'text-slate-500 border-transparent hover:text-slate-300'
                }`}
              >
                <Icon size={12} />
                {mode.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Input Form */}
      <div className="p-5 space-y-3">
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <FolderSearch size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              id="multi-scan-input"
              type="text"
              value={inputVal}
              onChange={e => setInputVal(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runScan()}
              placeholder={currentMode.placeholder}
              className="w-full bg-slate-900/80 border border-slate-700 rounded-lg pl-9 pr-4 py-2.5 text-[11px] font-mono text-slate-300 placeholder-slate-600 focus:outline-none focus:border-violet-600/70 transition-colors"
            />
          </div>

          {activeTab === 'binary' && (
            <button
              onClick={() => { setInputVal('SAMPLE'); }}
              type="button"
              className="hidden sm:flex items-center gap-1 bg-cyan-950/50 border border-cyan-700/50 text-cyan-300 hover:bg-cyan-900/60 font-mono text-[9px] font-black px-3 rounded-lg"
              title="Load synthesized ML-KEM NTT binary test fixture"
            >
              <Sparkles size={11} /> DEMO FIXTURE
            </button>
          )}

          <button
            id="multi-scan-run-btn"
            onClick={runScan}
            disabled={loading}
            className="flex items-center gap-2 bg-violet-700 hover:bg-violet-600 disabled:bg-slate-700 text-white font-black text-[10px] tracking-widest px-5 py-2.5 rounded-lg transition-all active:scale-95 font-mono whitespace-nowrap"
          >
            {loading
              ? <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              : <Zap size={12} />
            }
            {loading ? 'SCANNING…' : 'SCAN'}
          </button>
        </div>

        {error && (
          <div className="text-[11px] text-red-400 font-mono bg-red-900/20 border border-red-700/30 rounded px-3 py-2">
            {'\u26a0'} {error}
          </div>
        )}
      </div>

      {/* Reconciliation Drawer / Results */}
      <AnimatePresence>
        {reconcileResult && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mx-5 mb-4 p-4 bg-amber-950/20 border border-amber-600/40 rounded-xl space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-black font-mono text-amber-300 flex items-center gap-2">
                <GitCompare size={14} /> MULTI-SOURCE RECONCILIATION REPORT
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-900/40 border border-amber-600/40 text-amber-200">
                {reconcileResult.maturity_label}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center">
              <div className="bg-slate-900/60 p-2 rounded border border-slate-800">
                <div className="text-[9px] text-slate-500 font-mono">Evaluated</div>
                <div className="text-sm font-bold text-slate-200 font-mono">{reconcileResult.total_evaluated}</div>
              </div>
              <div className="bg-slate-900/60 p-2 rounded border border-slate-800">
                <div className="text-[9px] text-slate-500 font-mono">Divergences</div>
                <div className="text-sm font-bold text-red-400 font-mono">{reconcileResult.divergence_count}</div>
              </div>
              <div className="bg-slate-900/60 p-2 rounded border border-slate-800">
                <div className="text-[9px] text-slate-500 font-mono">Updated DB</div>
                <div className="text-sm font-bold text-cyan-400 font-mono">{reconcileResult.updated_records}</div>
              </div>
              <div className="bg-slate-900/60 p-2 rounded border border-slate-800">
                <div className="text-[9px] text-slate-500 font-mono">Maturity</div>
                <div className="text-sm font-bold text-emerald-400 font-mono">{reconcileResult.crypto_agility_score}/5</div>
              </div>
            </div>

            {reconcileResult.divergences?.length > 0 && (
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {reconcileResult.divergences.map((div, i) => (
                  <div key={i} className="bg-slate-900/90 border border-red-800/40 rounded p-2 text-[10px] font-mono space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="text-red-400 font-bold">{div.divergence_flag}</span>
                      <span className="text-[8px] bg-red-950 text-red-300 border border-red-800 px-1 rounded">{div.severity}</span>
                    </div>
                    <div className="text-slate-400"><span className="text-slate-500">Target: </span>{div.target}</div>
                    <div className="text-slate-300"><span className="text-slate-500">Declared: </span>{div.declared}</div>
                    <div className="text-amber-300"><span className="text-slate-500">Actual: </span>{div.actual}</div>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Discovery Scan Results */}
      <AnimatePresence>
        {result && (
          <motion.div
            key="results"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="px-5 pb-5 space-y-4"
          >
            {/* Summary bar */}
            <div className="bg-slate-900/60 rounded-xl border border-slate-800 p-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">Assets Found</span>
                <span className="text-xl font-black text-slate-100 font-mono">{result.assets_found}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">Critical Risk</span>
                <span className="text-xl font-black text-red-400 font-mono">{criticalCount}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">Warning</span>
                <span className="text-xl font-black text-amber-400 font-mono">{warnCount}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-0.5">CBOM Spec</span>
                <span className="text-sm font-black text-cyan-400 font-mono flex items-center gap-1">
                  <CheckCircle2 size={12} /> {result.cbom_spec_version}
                </span>
              </div>
            </div>

            {/* Findings list */}
            {result.findings_summary?.length > 0 ? (
              <div className="space-y-2 max-h-72 overflow-y-auto pr-1 scrollbar-thin">
                <div className="text-[9px] text-slate-500 uppercase tracking-widest font-mono mb-1 flex items-center gap-2">
                  <ExternalLink size={9} /> Discovered Cryptographic Primitives
                </div>
                {result.findings_summary.map((f, i) => (
                  <FindingCard key={i} finding={f} />
                ))}
              </div>
            ) : (
              <div className="text-center py-6 text-slate-500 text-xs font-mono">
                <CheckCircle2 size={24} className="mx-auto mb-2 text-emerald-500" />
                No weak cryptographic primitives detected.
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
};

export default SourceScanner;
