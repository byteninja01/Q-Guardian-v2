import React, { useMemo, useRef, useCallback } from 'react';
import ForceGraph2D from 'react-force-graph-2d';

const DependencyGraph = ({ assets }) => {
  const fgRef = useRef();

  const graphData = useMemo(() => {
    const nodes = [];
    const links = [];
    const cas = new Set();
    const algos = new Set();

    (Array.isArray(assets) ? assets : []).forEach(asset => {
      const hostname = asset?.hostname || `unknown-${nodes.length}`;
      const risk = asset?.mosca?.risk_state || 'UNKNOWN';
      const algorithm = asset?.algorithm || 'Unknown Algorithm';
      // Asset Node
      nodes.push({ 
        id: hostname, 
        name: hostname.toUpperCase(), 
        val: 4, 
        color: risk === 'CRITICAL' ? '#dc2626' : '#A20C39',
        type: 'asset',
        risk
      });

      // Algorithm Node
      if (!algos.has(algorithm)) {
        algos.add(algorithm);
        nodes.push({ 
          id: algorithm, 
          name: algorithm, 
          val: 7, 
          color: '#FBBC09',
          type: 'algo'
        });
      }
      links.push({ source: hostname, target: algorithm, value: 2 });

      // CA Node
      const domainParts = hostname.split('.');
      const baseDomain = domainParts.length > 2 ? domainParts.slice(-2).join('.').toUpperCase() : hostname.toUpperCase();
      const ca = `ROOT-CA (${baseDomain})`;
      if (!cas.has(ca)) {
        cas.add(ca);
        nodes.push({ 
          id: ca, 
          name: ca, 
          val: 10, 
          color: '#1e293b',
          type: 'ca'
        });
      }
      links.push({ source: hostname, target: ca, value: 5 });
    });

    return { nodes, links };
  }, [assets]);

  const paintNode = useCallback((node, ctx, globalScale) => {
    const label = node.name;
    const fontSize = 12 / globalScale;
    ctx.font = `${fontSize}px "Orbitron", sans-serif`;
    const textWidth = ctx.measureText(label).width;
    const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

    // Node shape
    ctx.beginPath();
    ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
    ctx.fillStyle = node.color;
    ctx.fill();

    // Glow Effect for Critical
    if (node.risk === 'CRITICAL') {
        ctx.shadowBlur = 15;
        ctx.shadowColor = 'rgba(255, 77, 77, 0.8)';
        ctx.strokeStyle = '#ff4d4d';
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.shadowBlur = 0;
    }

    // Text Label
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillStyle = '#1e293b';
    ctx.fillText(label, node.x, node.y + node.val + fontSize);
  }, []);

  React.useEffect(() => {
    if (fgRef.current) {
        fgRef.current.d3Force('charge').strength(-300);
        fgRef.current.d3Force('link').distance(150);
        fgRef.current.d3Force('center').strength(0.05);
    }
  }, [graphData]);

  return (
    <div className="glass-card p-0 h-[600px] overflow-hidden relative border-2 border-pnb-maroon/20 bg-white shadow-2xl">
      <div className="absolute top-6 left-8 z-20 pointer-events-none">
        <h3 className="text-pnb-maroon font-black text-lg tracking-widest flex items-center gap-3">
            <span className="w-2 h-8 bg-pnb-maroon inline-block"></span>
            CRYPTO DEPENDENCY GRAPH
        </h3>
        <p className="text-[10px] text-slate-500 font-bold uppercase mt-1 tracking-widest opacity-80">
            PLATFORM ASSET & AUTHORITY TOPOLOGY
        </p>
      </div>
      
      <div className="absolute bottom-8 right-8 z-20 flex flex-col gap-3 glass-card p-4 bg-white/80 border-slate-200">
         <div className="flex items-center gap-3 text-[10px] font-black text-slate-700">
            <div className="w-3 h-3 rounded-full bg-pnb-maroon shadow-[0_0_10px_rgba(162,12,57,0.3)]" /> PROTECTED ASSET
         </div>
         <div className="flex items-center gap-3 text-[10px] font-black text-slate-700">
            <div className="w-3 h-3 rounded-full bg-red-600 shadow-[0_0_10px_rgba(220,38,38,0.3)]" /> CRITICAL RISK
         </div>
         <div className="flex items-center gap-3 text-[10px] font-black text-slate-700">
            <div className="w-3 h-3 rounded-full bg-pnb-gold shadow-[0_0_10px_rgba(251,188,9,0.3)]" /> CIPHER ALGO
         </div>
         <div className="flex items-center gap-3 text-[10px] font-black text-slate-700">
            <div className="w-3 h-3 rounded-full bg-slate-800 shadow-[0_0_10px_rgba(30,41,59,0.3)]" /> ROOT AUTHORITY
         </div>
      </div>

      <ForceGraph2D
        ref={fgRef}
        graphData={graphData}
        nodeCanvasObject={paintNode}
        nodePointerAreaPaint={(node, color, ctx) => {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
            ctx.fill();
        }}
        linkDirectionalParticles={4}
        linkDirectionalParticleSpeed={0.002}
        linkCurvature={0.25}
        linkColor={() => 'rgba(0,0,0,0.1)'}
        backgroundColor="#ffffff"
        cooldownTicks={100}
        d3AlphaDecay={0.02}
        d3VelocityDecay={0.3}
        onEngineStop={() => fgRef.current.zoomToFit(400)}
      />
    </div>
  );
};

export default DependencyGraph;
