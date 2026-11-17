import React, { useState, useEffect, useRef, useCallback } from 'react';
import Header from './components/Header';
import MetricCards from './components/MetricCards';
import ChartsPanel from './components/ChartsPanel';
import PacketTable from './components/PacketTable';
import AlertsPanel from './components/AlertsPanel';
import MetricsModal from './components/MetricsModal';

export default function App() {
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
    // If running under Vite dev on port 3000, connect to backend at 8000
    if (window.location.port === '3000') {
      return `${protocol}//localhost:8000/ws/packets`;
    }
    return `${protocol}//${window.location.host}/ws/packets`;
  };

  // Connect WebSocket
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
              return updated.slice(-30); // 30 points (approx 30s)
            });
          }
        }
      } catch (e) {
        // Silent fail on network blips
      }
    };

    const fetchAlerts = async () => {
      try {
        const resp = await fetch('/api/alerts?limit=50');
        if (resp.ok) {
          const data = await resp.json();
          if (isMounted) {
            setAlerts(data);
          }
        }
      } catch (e) {
        // Silent fail
      }
    };

    const fetchHealth = async () => {
      try {
        const resp = await fetch('/health');
        if (resp.ok) {
          const data = await resp.json();
          if (isMounted) {
            setActiveClients(data.active_ws_clients || 1);
          }
        }
      } catch (e) {
        // Silent fail
      }
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
      {/* Top Navigation */}
      <Header
        isConnected={isConnected}
        activeClients={activeClients}
        totalPackets={stats?.total_packets || 0}
        onOpenMetrics={() => setIsMetricsOpen(true)}
      />

      {/* Main Dashboard Grid */}
      <main className="flex-1 p-4 sm:p-6 space-y-5 max-w-[1600px] w-full mx-auto">
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
      </main>

      {/* Prometheus Metrics Modal */}
      <MetricsModal
        isOpen={isMetricsOpen}
        onClose={() => setIsMetricsOpen(false)}
      />
    </div>
  );
}
