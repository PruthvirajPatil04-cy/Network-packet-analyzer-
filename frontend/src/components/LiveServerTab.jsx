import React, { useState, useEffect, useRef } from 'react';
import {
  Server, ShieldAlert, ShieldCheck, Zap, Activity, ExternalLink,
  Play, Pause, RefreshCw, Trash2, Plus, AlertTriangle, Sparkles, X, ChevronRight, Lock
} from 'lucide-react';
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend
} from 'recharts';

const DECISION_BADGES = {
  allow: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  throttle: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  block: 'bg-rose-500/15 text-rose-400 border-rose-500/30 animate-pulse',
};

const SIGNATURE_COLORS = {
  'SQL Injection': '#ef4444',
  'Brute Force': '#f97316',
  'Path Traversal': '#eab308',
  'XSS': '#a855f7',
  'Command Injection': '#ec4899',
  'Honeypot Probe': '#06b6d4',
  'Rate Flood': '#3b82f6',
  'Port Scan': '#10b981',
  'Other Violation': '#64748b',
};

export default function LiveServerTab() {
  const [serverStatus, setServerStatus] = useState(null);
  const [events, setEvents] = useState([]);
  const [blockedList, setBlockedList] = useState([]);
  const [attackSummary, setAttackSummary] = useState({});
  const [selectedEvent, setSelectedEvent] = useState(null);

  // Demo Controls State
  const [trafficMode, setTrafficMode] = useState('mixed');
  const [trafficRate, setTrafficRate] = useState(20);
  const [isInjecting, setIsInjecting] = useState(false);
  const [manualIp, setManualIp] = useState('');
  const [manualReason, setManualReason] = useState('');

  // WebSocket for live server events
  useEffect(() => {
    let ws = null;
    let timer = null;

    const connectWS = () => {
      try {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.port === '3000' ? 'localhost:8000' : window.location.host;
        ws = new WebSocket(`${protocol}//${host}/ws/server-events`);

        ws.onmessage = (msg) => {
          try {
            const parsed = JSON.parse(msg.data);
            if (parsed.type === 'server_decision') {
              setEvents((prev) => [parsed.data, ...prev].slice(0, 200));
            }
          } catch (e) {}
        };

        ws.onclose = () => {
          timer = setTimeout(connectWS, 3000);
        };
      } catch (e) {
        timer = setTimeout(connectWS, 3000);
      }
    };

    connectWS();

    return () => {
      if (ws) ws.close();
      if (timer) clearTimeout(timer);
    };
  }, []);

  // Poll status, blocked list, and attack summary
  const refreshData = async () => {
    try {
      const [sRes, bRes, aRes] = await Promise.all([
        fetch('/api/server/status'),
        fetch('/api/server/blocked'),
        fetch('/api/server/attack-summary'),
      ]);
      if (sRes.ok) setServerStatus(await sRes.json());
      if (bRes.ok) setBlockedList(await bRes.json());
      if (aRes.ok) setAttackSummary(await aRes.json());
    } catch (e) {}
  };

  useEffect(() => {
    refreshData();
    const interval = setInterval(refreshData, 2000);
    return () => clearInterval(interval);
  }, []);

  // Actions
  const handleUnblock = async (ip) => {
    try {
      await fetch(`/api/server/blocked/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      refreshData();
    } catch (e) {}
  };

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!manualIp) return;
    try {
      await fetch('/api/server/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: manualIp, reason: manualReason || 'Manual administrator block', ttl: 300 }),
      });
      setManualIp('');
      setManualReason('');
      refreshData();
    } catch (e) {}
  };

  const handleTrafficControl = async (updates) => {
    try {
      const payload = {
        mode: updates.mode || trafficMode,
        pkts_per_sec: updates.rate || trafficRate,
        inject_attack: updates.inject_attack || false,
        clear_blocklist: updates.clear_blocklist || false,
      };
      if (updates.inject_attack) setIsInjecting(true);
      await fetch('/api/server/traffic-control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (updates.inject_attack) setTimeout(() => setIsInjecting(false), 1500);
      refreshData();
    } catch (e) {
      setIsInjecting(false);
    }
  };

  // Format Chart Data
  const chartData = Object.entries(attackSummary).map(([name, count]) => ({
    name,
    count,
    fill: SIGNATURE_COLORS[name] || '#64748b',
  }));

  return (
    <div className="space-y-5">
      {/* 4.1 Connection Status Banner */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Demo Server */}
        <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400 block">Target Application</span>
            <div className="flex items-center space-x-2 mt-1">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]" />
              <h4 className="font-bold text-sm text-white font-mono">student.college.edu</h4>
            </div>
            <p className="text-[11px] text-gray-500 mt-1 font-mono">
              Port :8001 · Uptime: {serverStatus?.demo_server?.uptime_sec || 0}s
            </p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <Server className="w-4 h-4" />
          </div>
        </div>

        {/* Backend API & Latency */}
        <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400 block">FastAPI Telemetry Hub</span>
            <div className="flex items-center space-x-2 mt-1">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_8px_#10b981]" />
              <h4 className="font-bold text-sm text-cyan-400 font-mono">p50: 3.8ms · p99: 11ms</h4>
            </div>
            <p className="text-[11px] text-gray-500 mt-1 font-mono">
              WebSocket Clients: {serverStatus?.websocket?.clients || 1}
            </p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
            <Activity className="w-4 h-4" />
          </div>
        </div>

        {/* Capture Agent */}
        <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400 block">Capture Sniffer</span>
            <div className="flex items-center space-x-2 mt-1">
              <span className={`w-2.5 h-2.5 rounded-full ${serverStatus?.agent?.online ? 'bg-emerald-400 shadow-[0_0_8px_#10b981]' : 'bg-amber-400'}`} />
              <h4 className="font-bold text-sm text-white font-mono">
                {serverStatus?.agent?.online ? 'ONLINE & SNIFFING' : 'AGENT STANDBY'}
              </h4>
            </div>
            <p className="text-[11px] text-gray-500 mt-1 font-mono">
              Last Frame: {serverStatus?.agent?.last_packet_age_seconds || 0}s ago
            </p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
            <Zap className="w-4 h-4" />
          </div>
        </div>

        {/* Dynamic Firewall Blocklist */}
        <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex items-center justify-between">
          <div>
            <span className="text-[10px] font-mono uppercase text-gray-400 block">Dynamic Firewall</span>
            <div className="flex items-baseline space-x-2 mt-1">
              <h4 className="font-bold text-2xl text-rose-400 font-mono">
                {blockedList.length}
              </h4>
              <span className="text-xs text-rose-300 font-mono">Blocked IPs</span>
            </div>
            <p className="text-[11px] text-gray-500 mt-0.5 font-mono">
              Auto-eviction: 300s TTL
            </p>
          </div>
          <div className="w-9 h-9 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
      </div>

      {/* Main Grid: Live Request Feed (Left 2 cols) vs Attack Activity & Blocklist (Right 1 col) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* 4.2 Live Request Feed */}
        <div className="lg:col-span-2 bg-[#101728] border border-[#1e2a44] rounded-xl overflow-hidden flex flex-col h-[580px]">
          <div className="px-4 py-3 border-b border-[#1e2a44] bg-[#0d1424] flex items-center justify-between">
            <div className="flex items-center space-x-2 font-mono">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              <h3 className="text-xs font-bold uppercase text-gray-200 tracking-wider">
                Live Ingress Request Stream & Defense Engine
              </h3>
              <span className="text-[10px] text-gray-500 font-normal">
                ({events.length} records)
              </span>
            </div>
            <a
              href="http://localhost:8001"
              target="_blank"
              rel="noreferrer"
              className="flex items-center space-x-1.5 px-3 py-1 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 text-xs font-mono hover:bg-cyan-500/20 transition-colors"
            >
              <span>Open Student Portal</span>
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>

          <div className="flex-1 overflow-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#0b101c] text-gray-400 uppercase text-[10px] sticky top-0 z-10 border-b border-[#1b253b]">
                <tr>
                  <th className="px-3.5 py-2">Time</th>
                  <th className="px-3.5 py-2">Source IP</th>
                  <th className="px-3.5 py-2">Method</th>
                  <th className="px-3.5 py-2">Path</th>
                  <th className="px-3.5 py-2">Decision</th>
                  <th className="px-3.5 py-2">Score</th>
                  <th className="px-3.5 py-2">Reasons / Rule Triggered</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#182339]">
                {events.length > 0 ? (
                  events.map((evt, idx) => {
                    const isBlock = evt.decision === 'block';
                    const isThrottle = evt.decision === 'throttle';
                    const timeStr = new Date(evt.ts * 1000).toLocaleTimeString();
                    return (
                      <tr
                        key={`${evt.ts}-${idx}`}
                        onClick={() => setSelectedEvent(evt)}
                        className={`hover:bg-cyan-950/20 cursor-pointer transition-colors ${
                          isBlock
                            ? 'border-l-4 border-l-rose-500 bg-rose-950/10'
                            : isThrottle
                            ? 'border-l-4 border-l-amber-500 bg-amber-950/10'
                            : 'border-l-4 border-l-transparent'
                        }`}
                      >
                        <td className="px-3.5 py-2 text-gray-400 text-[11px] whitespace-nowrap">{timeStr}</td>
                        <td className="px-3.5 py-2 text-gray-200 font-medium whitespace-nowrap">{evt.src_ip}</td>
                        <td className="px-3.5 py-2 text-gray-400 whitespace-nowrap">{evt.method}</td>
                        <td className="px-3.5 py-2 text-cyan-300 whitespace-nowrap truncate max-w-[140px]">{evt.path}</td>
                        <td className="px-3.5 py-2 whitespace-nowrap">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${DECISION_BADGES[evt.decision] || DECISION_BADGES.allow}`}>
                            {evt.decision}
                          </span>
                        </td>
                        <td className="px-3.5 py-2 font-bold whitespace-nowrap">
                          <span className={isBlock ? 'text-rose-400' : isThrottle ? 'text-amber-400' : 'text-gray-400'}>
                            {evt.score?.toFixed(2)}
                          </span>
                        </td>
                        <td className="px-3.5 py-2 text-gray-300 text-[11px] truncate max-w-[200px]">
                          {evt.reasons?.length > 0 ? evt.reasons.join('; ') : 'Benign normal request'}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={7} className="py-16 text-center text-gray-500 font-mono">
                      Awaiting live traffic from traffic generator...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Event Inspector Drawer */}
          {selectedEvent && (
            <div className="border-t border-[#23314f] bg-[#0c1322] p-4 text-xs font-mono">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-2">
                  <span className="text-cyan-400 font-bold uppercase">Decision Inspector</span>
                  <span className="text-gray-500">|</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${DECISION_BADGES[selectedEvent.decision]}`}>
                    {selectedEvent.decision}
                  </span>
                  <span className="text-gray-400">IP: {selectedEvent.src_ip}</span>
                </div>
                <button onClick={() => setSelectedEvent(null)} className="text-gray-400 hover:text-white">
                  <X className="w-4 h-4" />
                </button>
              </div>

              {selectedEvent.antigravity_explanation && (
                <div className="bg-cyan-950/30 border border-cyan-800/40 p-2.5 rounded-lg mb-2 text-cyan-300">
                  <div className="flex items-center space-x-1.5 text-cyan-400 font-bold text-[11px] uppercase mb-1">
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Antigravity AI Forensic Triage</span>
                  </div>
                  <p className="text-[11px] leading-relaxed">{selectedEvent.antigravity_explanation}</p>
                  {selectedEvent.antigravity_action && (
                    <p className="text-[10px] text-cyan-400 mt-1 font-semibold">
                      Recommendation: {selectedEvent.antigravity_action}
                    </p>
                  )}
                </div>
              )}

              <div className="bg-[#11192e] p-2 rounded border border-[#1b253b] text-[10px] text-gray-400 overflow-auto max-h-24">
                <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: 4.3 Attack Activity Chart + 4.4 Blocklist Panel */}
        <div className="space-y-5 flex flex-col justify-between">
          {/* 4.3 Attack Activity Chart */}
          <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4">
            <h4 className="text-xs font-mono uppercase text-gray-300 font-semibold tracking-wider mb-2 flex items-center justify-between">
              <span>Attack Activity (Rolling 15m)</span>
              <span className="text-[10px] text-rose-400 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-800/40">
                Threat Breakdown
              </span>
            </h4>
            <div className="h-44 w-full">
              {chartData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} layout="vertical" margin={{ left: 10, right: 10 }}>
                    <XAxis type="number" stroke="#4b5563" fontSize={9} tickLine={false} />
                    <YAxis dataKey="name" type="category" stroke="#9ca3af" fontSize={9} tickLine={false} width={90} />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0c1220',
                        borderColor: '#1e2a44',
                        borderRadius: '8px',
                        fontSize: '11px',
                        fontFamily: 'monospace',
                      }}
                    />
                    <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                      {chartData.map((entry, index) => (
                        <cell key={`cell-${index}`} fill={entry.fill} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">
                  No attack signatures detected in window.
                </div>
              )}
            </div>
          </div>

          {/* 4.4 Blocklist Panel */}
          <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex-1 flex flex-col">
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-mono uppercase text-gray-300 font-semibold tracking-wider flex items-center space-x-1.5">
                <Lock className="w-3.5 h-3.5 text-rose-400" />
                <span>Simulated Firewall Blocklist</span>
              </h4>
              <span className="text-[10px] font-mono text-rose-400 bg-rose-950/40 px-2 py-0.5 rounded border border-rose-800/40">
                {blockedList.length} Active
              </span>
            </div>

            <div className="flex-1 overflow-auto max-h-48 border border-[#1b253b] rounded-lg mb-3">
              <table className="w-full text-left font-mono text-xs">
                <thead className="bg-[#0b101c] text-gray-400 text-[10px] uppercase sticky top-0">
                  <tr>
                    <th className="px-2.5 py-1.5">IP</th>
                    <th className="px-2.5 py-1.5">TTL</th>
                    <th className="px-2.5 py-1.5">Hits</th>
                    <th className="px-2.5 py-1.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#182339]">
                  {blockedList.length > 0 ? (
                    blockedList.map((entry) => (
                      <tr key={entry.ip} className="hover:bg-rose-950/20">
                        <td className="px-2.5 py-1.5 text-rose-300 font-medium">{entry.ip}</td>
                        <td className="px-2.5 py-1.5 text-gray-400">{entry.ttl_remaining}s</td>
                        <td className="px-2.5 py-1.5 text-gray-300">{entry.hits}</td>
                        <td className="px-2.5 py-1.5 text-right">
                          <button
                            onClick={() => handleUnblock(entry.ip)}
                            className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20"
                          >
                            Unblock
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={4} className="py-6 text-center text-gray-500 text-xs">
                        Blocklist is empty (No blocked IPs).
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Manual Add IP Form */}
            <form onSubmit={handleManualBlock} className="flex gap-1.5 font-mono text-xs">
              <input
                type="text"
                placeholder="IP (e.g. 10.0.5.88)"
                value={manualIp}
                onChange={(e) => setManualIp(e.target.value)}
                className="bg-[#151f33] border border-[#23314f] rounded px-2 py-1 text-gray-200 placeholder-gray-500 text-xs flex-1 focus:outline-none focus:border-cyan-500"
              />
              <button
                type="submit"
                className="flex items-center space-x-1 px-2.5 py-1 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 hover:bg-rose-500/30"
              >
                <Plus className="w-3 h-3" />
                <span>Block</span>
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* 4.6 Demo Controls Toolbar */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 font-mono text-xs">
        <div className="flex items-center space-x-4">
          <span className="text-gray-400 uppercase text-[11px] font-bold">Simulator Controls:</span>
          {/* Traffic Mode Toggle */}
          <div className="flex rounded-lg overflow-hidden border border-[#23314f]">
            <button
              onClick={() => {
                setTrafficMode('benign');
                handleTrafficControl({ mode: 'benign' });
              }}
              className={`px-3 py-1 text-xs transition-colors ${
                trafficMode === 'benign' ? 'bg-cyan-500 text-black font-bold' : 'bg-[#151f33] text-gray-400'
              }`}
            >
              Benign (100% Students)
            </button>
            <button
              onClick={() => {
                setTrafficMode('mixed');
                handleTrafficControl({ mode: 'mixed' });
              }}
              className={`px-3 py-1 text-xs transition-colors ${
                trafficMode === 'mixed' ? 'bg-rose-500 text-white font-bold' : 'bg-[#151f33] text-gray-400'
              }`}
            >
              Mixed (80% Benign + 20% Attacks)
            </button>
          </div>

          {/* Rate Selector */}
          <div className="flex items-center space-x-2">
            <span className="text-gray-500 text-[11px]">Rate:</span>
            {[10, 20, 50, 100].map((rate) => (
              <button
                key={rate}
                onClick={() => {
                  setTrafficRate(rate);
                  handleTrafficControl({ rate });
                }}
                className={`px-2 py-0.5 rounded text-xs border ${
                  trafficRate === rate
                    ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40 font-bold'
                    : 'bg-[#151f33] text-gray-400 border-[#23314f]'
                }`}
              >
                {rate} req/s
              </button>
            ))}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-2.5">
          <button
            onClick={() => handleTrafficControl({ inject_attack: true })}
            disabled={isInjecting}
            className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border font-bold text-xs transition-all ${
              isInjecting
                ? 'bg-rose-600 text-white animate-bounce'
                : 'bg-rose-500/20 text-rose-400 border-rose-500/40 hover:bg-rose-500/30'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>{isInjecting ? 'Injecting Attack...' : '⚡ Inject Test Attack'}</span>
          </button>

          <button
            onClick={() => handleTrafficControl({ clear_blocklist: true })}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-800 text-gray-300 border border-gray-700 hover:bg-gray-700 text-xs transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Blocklist</span>
          </button>
        </div>
      </div>
    </div>
  );
}
