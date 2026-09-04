import React, { useState, useEffect, Suspense, lazy } from 'react';
import axios from 'axios';
import { ShieldCheck, Clock, FileText, LayoutDashboard, Database, Activity, Terminal, Radar, TimerReset, Waypoints, Layers, Boxes } from 'lucide-react';
import Header from './components/Header';
import PlaybookModal from './components/PlaybookModal';
import Chatbot from './components/Chatbot';
import { useToast } from './context/ToastContext.jsx';
import { useAuth } from './context/AuthContext.jsx';
import LoginPage from './components/LoginPage';
import ErrorBoundary from './components/ErrorBoundary';
import { API_BASE } from './lib/api.js';

const Dashboard = lazy(() => import('./components/Dashboard'));
const AssetTable = lazy(() => import('./components/AssetTable'));
const HNDLSimulator = lazy(() => import('./components/HNDLSimulator'));
const CBOMViewer = lazy(() => import('./components/CBOMViewer'));
const DependencyGraph = lazy(() => import('./components/DependencyGraph'));
const ComplianceMapper = lazy(() => import('./components/ComplianceMapper'));
const ApiScanner = lazy(() => import('./components/ApiScanner'));
const SourceScanner = lazy(() => import('./components/SourceScanner'));

const AnalystLoadingPanel = () => (
  <div className="min-h-[60vh] flex items-center justify-center">
    <div className="w-full max-w-4xl glass-card overflow-hidden">
      <div className="flex items-center gap-3 border-b border-slate-200 bg-slate-50 px-6 py-5">          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cobalt-50 text-cobalt-600">
          <Activity size={16} className="animate-spin" />
        </div>
        <div>
          <div className="flex items-center gap-2 text-sm font-bold tracking-tight text-slate-900">
            Initializing Cryptographic Analyst Workspace
          </div>
          <p className="mt-0.5 text-xs text-slate-500">
            Establishing secure data channels, loading multi-source posture, and preparing live intelligence modules.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-6">
        <InfoTile
          icon={<Radar size={16} />}
          title="Start here"
          body="Use TRIGGER FULL SCAN to assess an enterprise domain or use Multi-Source Scanner for containers and binaries."
        />
        <InfoTile
          icon={<TimerReset size={16} />}
          title="Typical runtime"
          body="Average full scans usually complete in 2 to 5 minutes, depending on discovery depth, open services, and endpoint latency."
        />
        <InfoTile
          icon={<Waypoints size={16} />}
          title="What loads"
          body="The platform prepares asset inventory, MOSCA risk states, PQC readiness, threat intelligence, and migration playbooks."
        />
      </div>

      <div className="flex flex-col gap-1 border-t border-slate-200 bg-slate-50 px-6 py-4 text-[11px] font-medium text-slate-500 md:flex-row md:items-center md:justify-between">
        <span>Tip: the API Scanner tab is best for targeted endpoint checks after the baseline domain scan completes.</span>
        <span className="font-mono text-[10px] font-semibold uppercase tracking-widest text-cobalt-700">Secure session in progress</span>
      </div>
    </div>
  </div>
);

const InfoTile = ({ icon, title, body }) => (
  <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
    <div className="mb-1.5 flex items-center gap-2 text-[11px] font-semibold text-slate-900">
      <span className="text-cobalt-600">{icon}</span>
      {title}
    </div>
    <p className="text-xs leading-relaxed text-slate-600">{body}</p>
  </div>
);

function App() {
  const { isAuthenticated, token } = useAuth();
  const toast = useToast();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [assets, setAssets] = useState([]);
  const [rating, setRating] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [polling, setPolling] = useState(false);
  
  const [domain, setDomain] = useState('');
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [playbook, setPlaybook] = useState(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatusMsg, setScanStatusMsg] = useState('');

  const fetchData = async () => {
    try {
      // Pass the bearer token explicitly: AuthProvider's axios-default sync
      // effect may not have run yet when App's own effect fires right after login.
      const authHeaders = token ? { Authorization: `Bearer ${token}` } : {};
      const [assetsRes, ratingRes] = await Promise.all([
        axios.get(`${API_BASE}/assets`, { headers: authHeaders }),
        axios.get(`${API_BASE}/enterprise/rating`, { headers: authHeaders })
      ]);
      setAssets(Array.isArray(assetsRes.data) ? assetsRes.data : []);
      setRating(ratingRes.data && typeof ratingRes.data === 'object' ? ratingRes.data : null);
    } catch (err) {
      console.error("Error fetching data:", err);
      setAssets([]);
      setRating(null);
    }
  };

  const handleScan = async () => {
    setScanning(true);
    setPolling(false);
    try {
      const res = await axios.post(`${API_BASE}/scan/trigger`, { domain }, {
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
      const jobId = res.data.job_id;
      
      // Poll for completion (Adaptive polling for production feel)
      setPolling(true);
      let pollDelay = 1000;
      let active = true;

      const poll = async () => {
          if (!active) return;
          try {
              const statusRes = await axios.get(`${API_BASE}/scan/${jobId}/status`);
              const data = statusRes.data;
              
              setScanProgress(data.progress || 0);
              setScanStatusMsg(data.current_step || 'Processing...');
              
              if (data.status === 'COMPLETED') {
                  active = false;
                  setPolling(false);
                  setScanning(false);
                  setScanProgress(100);
                  setScanStatusMsg('Finalizing...');
                  setTimeout(async () => {
                      await fetchData();
                      setActiveTab('dashboard');
                  }, 1000);
                  return;
              } else if (data.status === 'FAILED') {
                  active = false;
                  setPolling(false);
                  setScanning(false);
                  toast.showError("Scan Error: " + data.current_step);
                  setScanStatusMsg('');
                  return;
              }

              // Adaptive polling: up to 3 seconds
              if (pollDelay < 3000) pollDelay += 500;
              setTimeout(poll, pollDelay);
              
          } catch (e) {
              console.error("Polling error", e);
              setTimeout(poll, 1000); // Retry 
          }
      };

      setTimeout(poll, pollDelay);
      
    } catch (err) {
      toast.showError("Scan failed. Ensure backend is running.");
      setScanning(false);
    }
  };

  const handleOpenPlaybook = async (asset) => {
    setSelectedAsset(asset);
    try {
      const res = await axios.get(`${API_BASE}/migration/${asset.id}/playbook`);
      setPlaybook(res.data);
    } catch (err) {
      console.error("Failed to fetch playbook");
    }
  };

  useEffect(() => {
    if (isAuthenticated) {
      fetchData();
    }
  }, [isAuthenticated]);

  // ⚠️ Rules of Hooks: this conditional return MUST stay after every hook call,
  // otherwise the hook count changes between the unauthenticated and
  // authenticated renders and React crashes with "Rendered more hooks...".
  if (!isAuthenticated) {
    return <LoginPage />;
  }

  const navItems = [
    { id: 'dashboard',      label: 'Posture',          icon: <LayoutDashboard size={14} /> },
    { id: 'assets',         label: 'Inventory',        icon: <Database size={14} /> },
    { id: 'source_scanner', label: 'Multi-source',     icon: <Layers size={14} /> },
    { id: 'api_scanner',    label: 'API Scanner',      icon: <Terminal size={14} /> },
    { id: 'hndl',           label: 'HNDL',             icon: <Clock size={14} /> },
    { id: 'graph',          label: 'Topology',         icon: <Boxes size={14} /> },
    { id: 'compliance',     label: 'Cert-IN',          icon: <ShieldCheck size={14} /> },
    { id: 'cbom',           label: 'CBOM Export',      icon: <FileText size={14} /> },
  ];

  return (
    <div className={`min-h-screen pb-16 bg-slate-50 w-full isolate ${scanning || polling ? 'pt-[126px]' : 'pt-24'}`}>
      <Header 
        onScan={handleScan} 
        scanning={scanning} 
        polling={polling}
        domain={domain} 
        setDomain={setDomain} 
        progress={scanProgress}
        statusMessage={scanStatusMsg}
      />
      
      <main className="max-w-[1400px] w-full mx-auto px-4 sm:px-6">
        <nav className="flex gap-2 flex-wrap mb-6">
          {navItems.map(item => (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={`px-3.5 py-2 rounded-lg text-[11px] font-semibold transition-all border flex items-center gap-2 tracking-wide
                ${activeTab === item.id 
                  ? 'border-slate-900 bg-slate-900 text-white shadow-[0_1px_2px_rgba(15,23,42,0.25)]' 
                  : 'border-slate-200 bg-white text-slate-500 hover:border-slate-300 hover:text-slate-800'}`}
            >
              <span className={activeTab === item.id ? 'text-white' : 'text-slate-400'}>{item.icon}</span> 
              {item.label}
            </button>
          ))}
        </nav>

        <div className="animate-in fade-in slide-in-from-bottom-4 duration-500 w-full min-h-[60vh]">
          <ErrorBoundary>
            <Suspense fallback={<AnalystLoadingPanel />}>
              {activeTab === 'dashboard'      && <Dashboard assets={assets} rating={rating} />}
              {activeTab === 'assets'         && <AssetTable assets={assets} onPlaybook={handleOpenPlaybook} />}
              {activeTab === 'source_scanner' && <SourceScanner onScanComplete={fetchData} />}
              {activeTab === 'api_scanner'    && <ApiScanner />}
              {activeTab === 'hndl'           && <HNDLSimulator assets={assets} />}
              {activeTab === 'graph'          && <DependencyGraph assets={assets} />}
              {activeTab === 'compliance'     && <ComplianceMapper />}
              {activeTab === 'cbom'           && <CBOMViewer assets={assets} />}
            </Suspense>
          </ErrorBoundary>
        </div>
      </main>

      <Chatbot />

      <PlaybookModal 
        asset={selectedAsset} 
        playbook={playbook} 
        onClose={() => { setSelectedAsset(null); setPlaybook(null); }} 
      />

      <footer className="fixed bottom-0 left-0 right-0 bg-white border-t border-slate-200 text-slate-400 py-2 px-6 text-[10px] flex justify-between uppercase font-bold tracking-widest z-40">
        <div>&copy; 2026 Q-GUARDIAN QUANTUM TRANSITION INTELLIGENCE. ALL RIGHTS RESERVED.</div>
        <div className="flex gap-4">
          <span>PRIVACY POLICY</span>
          <span>DISCLAIMER</span>
          <span className="hidden sm:inline">POWERED BY MOSCA RISK COUNTDOWN ENGINE</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
