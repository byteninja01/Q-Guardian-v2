import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { ShieldCheck, AlertCircle, ExternalLink, ChevronRight } from 'lucide-react';
import { API_BASE } from '../lib/api.js';

const ComplianceMapper = () => {
  const [data, setData] = useState([]);

  useEffect(() => {
    axios.get(`${API_BASE}/compliance/rbi`)
      .then(res => setData(res.data))
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="space-y-6">
      <div className="glass-card p-6 bg-pnb-maroon text-white border-b-4 border-pnb-gold">
         <h3 className="font-black text-sm uppercase flex items-center gap-2">
           <ShieldCheck size={20} /> RBI CYBERSECURITY FRAMEWORK (CSF) 2.0 AUTO-MAPPER
         </h3>
         <p className="text-[10px] opacity-70 mt-1">AUTOMATIC MAPPING OF CRYPTOGRAPHIC FINDINGS TO REGULATORY CONTROLS</p>
      </div>

      <div className="space-y-4">
        {data.length === 0 ? (
          <div className="glass-card p-12 text-center text-slate-400 font-bold uppercase text-sm">
            NO REGULATORY VIOLATIONS DETECTED IN CURRENT CBOM
          </div>
        ) : (
          data.map((item, idx) => (
            <div key={idx} className="glass-card overflow-hidden">
               <div className="bg-slate-50 border-b px-4 py-3 flex justify-between items-center">
                  <span className="text-xs font-black text-slate-700">{item.hostname}</span>
                  <span className="text-[9px] font-bold text-red-600 uppercase italic">
                    {item.findings.length} VIOLATIONS
                  </span>
               </div>
               <div className="p-4 space-y-4">
                  {item.findings.map((finding, fIdx) => (
                    <div key={fIdx} className="flex gap-4 border-l-2 border-red-500 pl-4 py-1">
                       <div className="flex-1">
                          <div className="text-[10px] font-black text-pnb-maroon uppercase">{finding.control}</div>
                          <div className="text-sm font-bold text-slate-800 mt-1">{finding.description}</div>
                          <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1 italic">
                             REMEDIATION: {finding.remediation}
                          </div>
                       </div>
                       <button className="text-pnb-maroon/40 hover:text-pnb-maroon self-center">
                          <ExternalLink size={14} />
                       </button>
                    </div>
                  ))}
               </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ComplianceMapper;
