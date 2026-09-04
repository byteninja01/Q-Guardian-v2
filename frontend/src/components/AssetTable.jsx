import { motion } from 'framer-motion';
import { ShieldCheck, Clock, Globe, FileCode, Package, Cloud, Cpu, Wifi, AlertTriangle, CheckCircle, XCircle } from 'lucide-react';

const SOURCE_BADGE = {
  static_code:   { label: 'AST',     icon: FileCode, color: 'bg-violet-900/60 text-violet-300 border-violet-700/40' },
  binary:        { label: 'BINARY',  icon: Cpu,      color: 'bg-orange-900/60 text-orange-300 border-orange-700/40' },
  container:     { label: 'DOCKER',  icon: Package,  color: 'bg-sky-900/60    text-sky-300    border-sky-700/40'    },
  cloud_kms:     { label: 'KMS',     icon: Cloud,    color: 'bg-emerald-900/60 text-emerald-300 border-emerald-700/40' },
  network_live:  { label: 'LIVE',    icon: Wifi,     color: 'bg-indigo-900/60 text-indigo-300 border-indigo-700/40'  },
};

const RISK_COLOR = {
  CRITICAL: 'text-red-400 animate-pulse',
  WARNING:  'text-amber-400',
  MONITOR:  'text-yellow-400',
  SAFE:     'text-emerald-400',
};

const QTRI_BAR_COLOR = (score) =>
  score > 70 ? 'bg-emerald-500' : score > 40 ? 'bg-amber-500' : 'bg-red-500';

const SourceBadge = ({ sourceType }) => {
  const cfg = SOURCE_BADGE[sourceType] || SOURCE_BADGE.network_live;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1 text-[9px] font-black uppercase px-1.5 py-0.5 rounded border ${cfg.color} tracking-widest font-mono`}>
      <Icon size={9} /> {cfg.label}
    </span>
  );
};

const AssetTable = ({ assets, onPlaybook }) => {
  if (!assets || assets.length === 0) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="glass-card p-16 flex flex-col items-center justify-center text-center"
      >
        <Cpu size={40} className="text-slate-700 mb-4" />
        <p className="text-slate-400 font-bold text-sm">No assets discovered yet.</p>
        <p className="text-slate-600 text-xs mt-1">Run a Network Scan or Static Source Scan to populate the inventory.</p>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="glass-card overflow-hidden border border-slate-800/80"
    >
      {/* Header */}
      <div className="bg-slate-950/80 border-b border-slate-800 p-4 flex justify-between items-center">
        <h3 className="text-indigo-400 font-black text-xs tracking-widest flex items-center gap-2 font-mono">
          <span className="w-1.5 h-4 bg-indigo-500 inline-block rounded-sm" />
          CRYPTOGRAPHIC ASSET INVENTORY
        </h3>
        <div className="flex items-center gap-3">
          <span className="text-[10px] font-bold text-slate-500 font-mono">
            {assets.filter(a => a.source_type === 'static_code').length} AST
          </span>
          <span className="text-slate-700">|</span>
          <span className="text-[10px] font-bold text-slate-500 font-mono">
            {assets.filter(a => a.source_type === 'network_live' || !a.source_type).length} LIVE
          </span>
          <span className="text-slate-700">|</span>
          <span className="text-[10px] font-black text-cyan-400 bg-cyan-900/30 border border-cyan-800/40 px-2 py-1 rounded font-mono">
            TOTAL: {assets.length}
          </span>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="bg-slate-900/60 text-[10px] font-black uppercase text-slate-500 tracking-wider border-b border-slate-800/80">
              <th className="px-5 py-3.5 whitespace-nowrap">Asset / Evidence</th>
              <th className="px-5 py-3.5 whitespace-nowrap">Source</th>
              <th className="px-5 py-3.5 whitespace-nowrap">Algorithm</th>
              <th className="px-5 py-3.5 whitespace-nowrap hidden sm:table-cell">QTRI Score</th>
              <th className="px-5 py-3.5 whitespace-nowrap hidden lg:table-cell">Risk Window</th>
              <th className="px-5 py-3.5 whitespace-nowrap hidden md:table-cell">Compliance</th>
              <th className="px-5 py-3.5 whitespace-nowrap text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset, idx) => {
              const mosca = asset.mosca || {};
              const riskState = mosca.risk_state || 'SAFE';
              const isStatic = asset.source_type === 'static_code';

              return (
                <motion.tr
                  key={asset.id || idx}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: Math.min(idx * 0.04, 0.8) }}
                  className="hover:bg-slate-800/30 transition-colors border-b border-slate-800/40 group"
                >
                  {/* Asset / Evidence */}
                  <td className="px-5 py-4 max-w-[260px]">
                    <div className="font-black text-slate-100 text-xs tracking-tight font-mono truncate">
                      {asset.hostname?.toUpperCase()}
                    </div>
                    {isStatic && asset.evidence_file && (
                      <div className="text-[10px] text-violet-400 font-mono mt-0.5 truncate" title={asset.evidence_file}>
                        {'\u{1F4C4}'} {asset.evidence_file.split(/[\\/]/).slice(-2).join('/')}:{asset.evidence_line}
                      </div>
                    )}
                    <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                      <span className="text-[9px] text-slate-500 font-bold tracking-widest uppercase font-mono">
                        Tier: {asset.sensitivity_tier}
                      </span>
                      {asset.discovered_endpoints_data && JSON.parse(asset.discovered_endpoints_data || '[]').length > 0 && (
                        <div className="relative group/ep">
                          <span className="text-[9px] bg-indigo-900/40 text-indigo-300 px-1.5 py-0.5 rounded border border-indigo-700/30 font-black flex items-center gap-1 cursor-help font-mono">
                            <Globe size={8} /> {JSON.parse(asset.discovered_endpoints_data).length} PATHS
                          </span>
                          <div className="absolute top-full left-0 mt-1 w-56 bg-slate-900 border border-slate-700 shadow-xl rounded-lg p-2 z-50 hidden group-hover/ep:block">
                            <div className="text-[9px] text-indigo-400 font-black mb-1 uppercase tracking-widest">Active Surface</div>
                            <ul className="max-h-28 overflow-y-auto space-y-0.5">
                              {JSON.parse(asset.discovered_endpoints_data).slice(0, 6).map((path, pIdx) => (
                                <li key={pIdx} className="text-[10px] font-mono text-slate-400 truncate">{path}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      )}
                    </div>
                  </td>

                  {/* Source Badge */}
                  <td className="px-5 py-4">
                    <SourceBadge sourceType={asset.source_type || 'network_live'} />
                  </td>

                  {/* Algorithm */}
                  <td className="px-5 py-4">
                    <div className="flex flex-col gap-0.5">
                      <span className="font-bold text-slate-200 text-xs flex items-center gap-1.5">
                        {asset.is_pqc
                          ? <ShieldCheck size={12} className="text-emerald-400" />
                          : <AlertTriangle size={12} className="text-amber-500" />
                        }
                        {asset.algorithm}
                      </span>
                      <span className="text-[9px] text-slate-500 font-bold uppercase tracking-wider font-mono">
                        {asset.tls_version !== 'N/A' ? `TLS ${asset.tls_version} \u00b7 ` : ''}{asset.key_size}b
                      </span>
                      {asset.is_pqc
                        ? <span className="text-[9px] text-emerald-400 font-black font-mono">{'\u2713'} PQC READY</span>
                        : <span className="text-[9px] text-red-400 font-black font-mono">{'\u2717'} QUANTUM VULNERABLE</span>
                      }
                    </div>
                  </td>

                  {/* QTRI Score */}
                  <td className="px-5 py-4 hidden sm:table-cell">
                    <div className="flex items-center gap-2">
                      <span className="font-black text-xs text-slate-300 w-6 text-right font-mono">{asset.qtri_score}</span>
                      <div className="w-14 h-1.5 bg-slate-800 rounded-full overflow-hidden shrink-0 border border-slate-700">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${asset.qtri_score}%` }}
                          transition={{ duration: 0.8, delay: idx * 0.04 }}
                          className={`h-full rounded-full ${QTRI_BAR_COLOR(asset.qtri_score)}`}
                        />
                      </div>
                    </div>
                  </td>

                  {/* Risk Window */}
                  <td className="px-5 py-4 hidden lg:table-cell">
                    <span className={`font-black text-[11px] flex items-center gap-1.5 font-mono ${RISK_COLOR[riskState] || RISK_COLOR.SAFE}`}>
                      <Clock size={11} />
                      {riskState === 'CRITICAL' || riskState === 'WARNING'
                        ? `${mosca.days_remaining_worst ?? '\u2014'} DAYS`
                        : riskState
                      }
                    </span>
                  </td>

                  {/* Compliance */}
                  <td className="px-5 py-4 hidden md:table-cell">
                    {asset.policy_compliant
                      ? <span className="flex items-center gap-1 text-emerald-400 text-[10px] font-black font-mono"><CheckCircle size={11} /> OK</span>
                      : <span className="flex items-center gap-1 text-red-400 text-[10px] font-black font-mono"><XCircle size={11} /> FAIL</span>
                    }
                  </td>

                  {/* Action */}
                  <td className="px-5 py-4 text-right">
                    <button
                      onClick={() => onPlaybook(asset)}
                      className="text-[9px] font-black uppercase text-indigo-400 hover:bg-indigo-600 hover:text-white border border-indigo-600/50 px-3 py-1.5 rounded-lg transition-all active:scale-95 tracking-widest font-mono whitespace-nowrap"
                    >
                      PLAYBOOK
                    </button>
                  </td>
                </motion.tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </motion.div>
  );
};

export default AssetTable;
