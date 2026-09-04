import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Activity, ShieldAlert } from 'lucide-react';

const HNDLSimulator = ({ assets }) => {
  const hndlAssets = (Array.isArray(assets) ? assets : []).filter(a => a?.hndl);
  
  if (hndlAssets.length === 0) {
    return (
      <div className="glass-card p-12 text-center">
        <div className="flex justify-center mb-4 text-green-600"><ShieldAlert size={48} /></div>
        <h3 className="text-pnb-maroon font-black text-xl mb-2">NO HNDL EXPOSURE DETECTED</h3>
        <p className="text-slate-500 text-sm">All discovered assets utilize Perfect Forward Secrecy (PFS), mitigating Harvest-Now-Decrypt-Later threats.</p>
      </div>
    );
  }

  // Generate timeline data for the chart
  const data = [
    { year: 2023, exposure: 0 },
    { year: 2024, exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0) * 0.2, 0) },
    { year: 2025, exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0) * 0.5, 0) },
    { year: 2026, exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0), 0) },
    { year: 2027, exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0) * 1.5, 0) },
    { year: 2028, exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0) * 2.2, 0) },
    { year: 2029, exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0) * 3.1, 0) },
    { year: 2030, exposure: hndlAssets.reduce((sum, a) => sum + (a?.hndl?.hndl_risk_score ?? 0) * 4.5, 0) },
  ];

  return (
    <div className="space-y-6">
      <div className="glass-card p-6 border-l-4 border-red-600">
        <h3 className="text-pnb-maroon font-black text-sm mb-4 flex items-center gap-2">
          <Activity size={18} /> HARVEST-NOW-DECRYPT-LATER (HNDL) EXPOSURE TIMELINE
        </h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="colorExposure" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#dc2626" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#dc2626" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="year" fontSize={10} fontWeight="bold" />
              <YAxis fontSize={10} />
              <Tooltip />
              <Area type="monotone" dataKey="exposure" stroke="#dc2626" fillOpacity={1} fill="url(#colorExposure)" strokeWidth={3} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
         {hndlAssets.slice(0, 4).map(asset => (
           <div key={asset.id} className="glass-card p-4 border-l-4 border-amber-500">
              <div className="text-[10px] font-black text-slate-400 uppercase">{asset.hostname}</div>
              <div className="flex justify-between items-end mt-2">
                <div>
                    <div className="text-2xl font-black text-slate-800">{asset.hndl.total_gb_at_risk} GB</div>
                    <div className="text-[10px] font-bold text-red-600">TOTAL DATA AT RISK</div>
                </div>
                <div className="text-right">
                    <div className="text-sm font-bold text-slate-600">Score: {asset.hndl.hndl_risk_score}</div>
                    <div className="text-[10px] text-slate-400 italic">
                      Since {new Date(asset.hndl.harvest_start_date).toLocaleDateString(undefined, { month: 'short', year: 'numeric' })}
                    </div>
                </div>
              </div>
              <div className="mt-2 pt-2 border-t border-slate-100 flex items-center gap-1">
                <ShieldAlert size={10} className="text-slate-400" />
                <span className="text-[9px] text-slate-400 uppercase tracking-tighter">
                  {asset.hndl.methodology_note || "RBI Tier-Aligned Conservative Baseline"}
                </span>
              </div>
           </div>
         ))}
      </div>

      <div className="bg-amber-50 border border-amber-200 rounded-lg p-4 mt-8 shadow-sm">
        <div className="flex items-center gap-2 mb-2 text-amber-700 font-black text-[10px] uppercase tracking-widest">
            <ShieldAlert size={14} /> HNDL SIMULATION GROUNDING ADVISORY
        </div>
        <p className="text-[11px] text-amber-800 leading-relaxed font-medium">
            <strong>Disclaimer:</strong> This HNDL Simulation is <strong>Weakly Grounded</strong>. In the absence of real-time traffic logs, packet capture (PCAP) data, or integrated network telemetry, the reported exposure volumes (GB) are calculated using RBI-tiered conservative baselines and historical trajectory modeling. These figures represent potential exposure risk based on architectural patterns rather than exact measured data exfiltration. Application security analysts should treat these metrics as a theoretical risk ceiling.
        </p>
      </div>
    </div>
  );
};

export default HNDLSimulator;
