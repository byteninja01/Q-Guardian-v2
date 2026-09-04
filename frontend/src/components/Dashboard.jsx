import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from 'recharts';
import { ShieldCheck, Clock, AlertTriangle, FileText, Activity, Database, CheckCircle2, Radar, TimerReset, Waypoints } from 'lucide-react';

import { motion } from 'framer-motion';
import { API_BASE } from '../lib/api.js';

const Dashboard = ({ assets, rating }) => {
  const [intel, setIntel] = useState([]);
  const safeAssets = Array.isArray(assets) ? assets : [];
  const safeRating = rating && typeof rating === 'object'
    ? rating
    : { score: 0, status: 'N/A', asset_count: 0 };

useEffect(() => {
    axios.get(`${API_BASE}/threat-intel`)
      .then(res => setIntel(Array.isArray(res.data) ? res.data : []))
      .catch(err => console.error("Failed to fetch threat intel", err));
  }, []);

  if (!rating && safeAssets.length === 0) return <AnalystWarmupPanel />;

  if (safeAssets.length === 0) {
      return (
          <div className="glass-card p-12 flex flex-col items-center justify-center border-2 border-dashed border-slate-300 min-h-[50vh] text-center bg-white/50 animate-in zoom-in-95 duration-500">
              <ShieldCheck size={64} className="text-slate-300 mb-6" />
              <h2 className="text-2xl font-black text-slate-800 mb-2 tracking-tighter">PLATFORM READY</h2>
              <p className="text-sm text-slate-500 max-w-lg mb-8 font-medium">
                  Welcome to the **Q-Guardian** Posture Dashboard. There are currently no scanned assets in your inventory. Enter a sector domain (e.g., manipurrural.bank.in) in the header above and trigger a **Global Sector Scan** to begin risk analysis.
              </p>
              <div className="flex gap-4 opacity-60 pointer-events-none grayscale">
                 {/* Preview of core dashboard metrics — shown in greyed state until scan is complete */}
                 <StatCard title="PQC Ready" value="-" icon={<ShieldCheck size={20}/>} color="#059669" />
                 <StatCard title="Critical Risks" value="-" icon={<AlertTriangle size={20}/>} color="#dc2626" />
              </div>
          </div>
      );
  }

  const handleDownloadBrief = () => {
    window.location.href = `${API_BASE}/reports/board-brief`;
  };

  const pqcReadyCount = safeAssets.filter(a => a?.is_pqc).length;
  const criticalCount = safeAssets.filter(a => a?.mosca?.risk_state === 'CRITICAL').length;
  const warningCount = safeAssets.filter(a => a?.mosca?.risk_state === 'WARNING').length;
  const stableCount = safeAssets.filter(a => !a?.mosca || !['CRITICAL', 'WARNING'].includes(a.mosca.risk_state)).length;

  const data = [
    { name: 'Stable', value: stableCount, color: '#10b981' },
    { name: 'Warning', value: warningCount, color: '#f59e0b' },
    { name: 'Critical', value: criticalCount, color: '#dc2626' },
    { name: 'PQC Ready', value: pqcReadyCount, color: '#0f766e' },
  ];

  return (
    <motion.div 
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="grid grid-cols-1 md:grid-cols-3 gap-6"
    >
      <motion.div 
        whileHover={{ scale: 1.01 }}
        className="md:col-span-1 glass-card p-6 flex flex-col items-center justify-center bg-gradient-to-b from-white to-slate-50 border-t-4 border-pnb-maroon relative overflow-hidden group"
      >
        <div className="absolute -right-10 -top-10 text-pnb-maroon/5 group-hover:text-pnb-maroon/10 transition-colors pointer-events-none">
            <ShieldCheck size={200} />
        </div>
        <h3 className="text-pnb-maroon font-black text-[10px] tracking-widest mb-6 z-10 w-full text-center border-b border-pnb-maroon/10 pb-2 uppercase">ENTERPRISE CYBER RATING</h3>
        <div className="relative flex items-center justify-center my-4 z-10">
            <motion.div 
                initial={{ scale: 0.8 }}
                animate={{ scale: 1 }}
                key={safeRating.score}
                className={`text-8xl font-black tracking-tighter drop-shadow-sm ${safeRating.score > 700 ? 'text-green-600' : safeRating.score > 400 ? 'text-blue-600' : 'text-pnb-maroon'}`}
            >
                {safeRating.score}
            </motion.div>
        </div>
        <div className={`mt-2 px-6 py-1.5 rounded-full bg-pnb-maroon text-white text-[10px] font-black uppercase tracking-widest z-10 shadow-lg border-2 border-white/20`}>{safeRating.status}</div>
        
        <button 
          onClick={handleDownloadBrief}
          className="mt-10 group/btn bg-white text-slate-800 font-extrabold text-[10px] uppercase tracking-[0.15em] border-2 border-slate-200 px-8 py-3 rounded-xl hover:bg-slate-900 hover:text-white hover:border-slate-900 transition-all flex items-center gap-3 z-10 shadow-sm hover:shadow-xl"
        >
          <FileText size={16} className="group-hover/btn:scale-110 transition-transform" /> EXPORT BOARD BRIEF
        </button>
      </motion.div>

      <div className="md:col-span-2 glass-card p-6 border-t-4 border-pnb-gold">
        <h3 className="text-pnb-maroon font-black text-sm mb-4">ASSETS BY MOSCA RISK STATE</h3>
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data.filter(d => d.value > 0)}>
              <XAxis dataKey="name" fontSize={10} fontWeight="bold" />
              <YAxis fontSize={10} allowDecimals={false} />
              <Tooltip cursor={{fill: 'rgba(162, 12, 57, 0.05)'}} contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgb(0 0 0 / 0.1)'}} />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {data.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="md:col-span-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Total Assets" value={safeAssets.length} icon={<Database size={20}/>} color="#1e293b" />
        <StatCard title="Stable Assets" value={stableCount} icon={<CheckCircle2 size={20}/>} color="#10b981" />
        <StatCard title="Critical Risks" value={criticalCount} icon={<AlertTriangle size={20}/>} color="#dc2626" />
        <StatCard title="Mosca Warnings" value={warningCount} icon={<Clock size={20}/>} color="#fbbf24" />
      </div>

      <div className="md:col-span-3 glass-card p-6 border-l-4 border-pnb-maroon bg-white/50">
         <h4 className="text-pnb-maroon font-black text-sm mb-4 flex items-center gap-2">
           <Activity size={18} /> LIVE THREAT INTELLIGENCE FEED
         </h4>
         <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {intel.map((item, idx) => (
                <IntelItem key={idx} {...item} />
            ))}
         </div>
      </div>
    </motion.div>
  );
};

const IntelItem = ({ date, source, title, impact }) => (
  <div className="border-l-2 border-slate-200 pl-4 hover:border-pnb-gold transition-colors">
    <div className="flex justify-between items-center mb-1">
        <span className="text-[10px] font-black text-pnb-maroon uppercase">{source}</span>
        <span className="text-[9px] text-slate-400 font-bold">{date}</span>
    </div>
    <div className="text-xs font-bold text-slate-700 leading-snug mb-1 line-clamp-2">{title}</div>
    <div className="text-[9px] text-slate-500 font-medium">IMPACT: {impact}</div>
  </div>
);

const AnalystWarmupPanel = () => (
  <div className="min-h-[60vh] flex items-center justify-center">
    <div className="w-full max-w-4xl glass-card border border-slate-200 bg-white/90 shadow-xl overflow-hidden">
      <div className="bg-pnb-maroon text-white px-6 py-5 border-b-4 border-pnb-gold">
        <div className="flex items-center gap-3 text-sm font-black uppercase tracking-[0.2em]">
          <Activity size={18} className="text-pnb-gold animate-spin" />
          Initializing Analyst Workspace
        </div>
        <p className="mt-2 text-xs text-white/75 font-semibold">
          Establishing secure data channels, loading asset posture, and preparing live intelligence modules.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-6">
        <InfoTile
          icon={<Radar size={18} />}
          title="Start Here"
          body="Use TRIGGER FULL SCAN to assess a domain such as pnb.bank.in or a target subsidiary endpoint."
        />
        <InfoTile
          icon={<TimerReset size={18} />}
          title="Typical Runtime"
          body="Average full scans usually complete in 2 to 5 minutes, depending on discovery depth, open services, and endpoint latency."
        />
        <InfoTile
          icon={<Waypoints size={18} />}
          title="What Loads"
          body="The platform prepares asset inventory, MOSCA risk states, PQC readiness, threat intelligence, and migration playbooks."
        />
      </div>

      <div className="border-t border-slate-100 px-6 py-4 bg-slate-50 text-[11px] text-slate-600 font-semibold flex flex-col gap-1 md:flex-row md:items-center md:justify-between">
        <span>Tip: the API Scanner tab is best for targeted endpoint checks after the baseline domain scan completes.</span>
        <span className="text-pnb-maroon uppercase tracking-widest font-black">Secure session in progress</span>
      </div>
    </div>
  </div>
);

const InfoTile = ({ icon, title, body }) => (
  <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
    <div className="flex items-center gap-2 text-pnb-maroon font-black text-[11px] uppercase tracking-widest">
      {icon}
      {title}
    </div>
    <p className="mt-3 text-sm leading-relaxed text-slate-600 font-medium">
      {body}
    </p>
  </div>
);

const StatCard = ({ title, value, icon, color }) => (
  <div className="glass-card p-4 flex items-center gap-4 hover:-translate-y-1 transition-transform border-b-2" style={{borderBottomColor: color}}>
    <div className={`p-3 rounded bg-slate-50`} style={{color: color}}>
      {icon}
    </div>
    <div>
      <div className="text-[10px] font-black text-slate-400 uppercase tracking-widest">{title}</div>
      <div className="text-2xl font-black text-slate-800">{value}</div>
    </div>
  </div>
);

export default Dashboard;
