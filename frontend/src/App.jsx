import React, { useState, useEffect, useRef, useCallback } from 'react';
import Header from './components/Header';
import MetricCards from './components/MetricCards';
import ChartsPanel from './components/ChartsPanel';
import PacketTable from './components/PacketTable';
import AlertsPanel from './components/AlertsPanel';
import MetricsModal from './components/MetricsModal';
import LiveServerTab from './components/LiveServerTab';
import { Layers, Server } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('telemetry'); // 'telemetry' | 'liveserver'
  const [isConnected, setIsConnected] = useState(false);
  const [activeClients, setActiveClients] = useState(1);
  const [packets, setPackets] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [isMetricsOpen, setIsMetricsOpen] = useState(false);

  const wsRef = useRef(null);
  const isPausedRef = useRef(isPaused);
  isPausedRef.current = isPaused;

  // Determine WebSocket URL
  const getWsUrl = () => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    if (window.location.port === '3000') {
      return `${protocol}//localhost:8000/ws/packets`;
    }
    return `${protocol}//${window.location.host}/ws/packets`;
  };

  // Connect WebSocket for Telemetry
  useEffect(() => {
    let reconnectTimer = null;
    let isMounted = true;

    const connect = () => {
      try {
        const wsUrl = getWsUrl();
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (!isMounted) return;
          setIsConnected(true);
        };

        ws.onmessage = (event) => {
          if (!isMounted) return;
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'packet_batch') {
              if (!isPausedRef.current) {
                const incoming = msg.data || [];
                setPackets((prev) => {
                  const combined = [...incoming.slice().reverse(), ...prev];
                  return combined.slice(0, 500); // Max 500 rows in memory
                });
              }
            } else if (msg.type === 'soc_alert') {
              setAlerts((prev) => [...prev, msg.data]);
            }
          } catch (e) {
            console.error('Error parsing WS message:', e);
          }
        };

        ws.onclose = () => {
          if (!isMounted) return;
          setIsConnected(false);
          reconnectTimer = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (err) {
        console.error('Failed to create WebSocket:', err);
        reconnectTimer = setTimeout(connect, 3000);
      }
    };

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  // Poll /api/stats and /api/alerts
  useEffect(() => {
    let isMounted = true;

    const fetchStats = async () => {
      try {
        const resp = await fetch('/api/stats?window_seconds=10');
        if (resp.ok) {
          const data = await resp.json();
          if (isMounted) {
            setStats(data);
            const nowStr = new Date().toLocaleTimeString('en-GB');
            setHistory((prev) => {
              const updated = [...prev, { time: nowStr, pps: data.pps, kbps: (data.bps / 1024).toFixed(1) }];
              return updated.slice(-30);
            });
          }
        }
      } catch (e) {}
    };

    const fetchAlerts = async () => {
      try {
        const resp = await fetch('/api/alerts?limit=50');
        if (resp.ok) {
          const data = await resp.json();
          if (isMounted) setAlerts(data);
        }
      } catch (e) {}
    };

    const fetchHealth = async () => {
      try {
        const resp = await fetch('/health');
        if (resp.ok) {
          const data = await resp.json();
          if (isMounted) setActiveClients(data.active_ws_clients || 1);
        }
      } catch (e) {}
    };

    fetchStats();
    fetchAlerts();
    fetchHealth();

    const statsInterval = setInterval(fetchStats, 1000);
    const alertsInterval = setInterval(fetchAlerts, 2000);
    const healthInterval = setInterval(fetchHealth, 5000);

    return () => {
      isMounted = false;
      clearInterval(statsInterval);
      clearInterval(alertsInterval);
      clearInterval(healthInterval);
    };
  }, []);

  return (
    <div className="min-h-screen bg-[#0a0e17] text-gray-100 flex flex-col font-sans">
      {/* Top Navigation Bar */}
      <Header
        isConnected={isConnected}
        activeClients={activeClients}
        totalPackets={stats?.total_packets || 0}
        onOpenMetrics={() => setIsMetricsOpen(true)}
      />

      {/* Tab Switcher */}
      <div className="border-b border-[#1b253b] bg-[#0d1424] px-6 py-2.5">
        <div className="max-w-[1600px] mx-auto flex items-center space-x-3 font-mono text-xs">
          <button
            onClick={() => setActiveTab('telemetry')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'telemetry'
                ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 font-bold shadow-[0_0_10px_rgba(6,182,212,0.15)]'
                : 'text-gray-400 hover:text-gray-200 border border-transparent'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Network Telemetry (Raw Frames)</span>
          </button>

          <button
            onClick={() => setActiveTab('liveserver')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg transition-all ${
              activeTab === 'liveserver'
                ? 'bg-rose-500/15 text-rose-400 border border-rose-500/40 font-bold shadow-[0_0_10px_rgba(244,63,94,0.15)]'
                : 'text-gray-400 hover:text-gray-200 border border-transparent'
            }`}
          >
            <Server className="w-4 h-4" />
            <span>Live Server: student.college.edu (Threat Defense)</span>
          </button>
        </div>
      </div>

      {/* Main Dashboard Content */}
      <main className="flex-1 p-4 sm:p-6 space-y-5 max-w-[1600px] w-full mx-auto">
        {activeTab === 'telemetry' ? (
          <>
            {/* Metric Summary Cards */}
            <MetricCards stats={stats} alertCount={alerts.length} />

            {/* Real-time Charts Panel */}
            <ChartsPanel stats={stats} history={history} />

            {/* Bottom Split: Live Packet Table & SOC Threat Intelligence */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
              <div className="lg:col-span-2">
                <PacketTable
                  packets={packets}
                  isPaused={isPaused}
                  onTogglePause={() => setIsPaused((prev) => !prev)}
                />
              </div>
              <div>
                <AlertsPanel alerts={alerts} />
              </div>
            </div>
          </>
        ) : (
          <LiveServerTab />
        )}
      </main>

      {/* Prometheus Metrics Modal */}
      <MetricsModal
        isOpen={isMetricsOpen}
        onClose={() => setIsMetricsOpen(false)}
      />
    </div>
  );
}
