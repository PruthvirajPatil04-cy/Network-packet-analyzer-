import React from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from 'recharts';

const PROTO_COLORS = {
  TCP: '#10b981',   // Emerald
  UDP: '#06b6d4',   // Cyan
  ICMP: '#f59e0b',  // Amber
  OTHER: '#8b5cf6', // Violet
};

export default function ChartsPanel({ stats, history }) {
  // Protocol pie data
  const rawDist = stats?.protocol_distribution || { TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 };
  const pieData = Object.entries(rawDist).map(([name, value]) => ({
    name,
    value: value || 0,
  }));
  const totalPie = pieData.reduce((acc, curr) => acc + curr.value, 0);

  // Top talkers bar data
  const topSources = (stats?.top_sources || []).slice(0, 5).map((s) => ({
    ip: s.ip.length > 15 ? s.ip.slice(0, 14) + '…' : s.ip,
    fullIp: s.ip,
    packets: s.packet_count,
    kb: (s.byte_count / 1024).toFixed(1),
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
      {/* 1. Real-time Throughput History Chart */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-xs font-mono uppercase text-gray-300 font-semibold tracking-wider">
            Live Throughput (PPS)
          </h4>
          <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800/40">
            Realtime 60s
          </span>
        </div>
        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={history}>
              <XAxis dataKey="time" stroke="#4b5563" fontSize={9} tickLine={false} />
              <YAxis stroke="#4b5563" fontSize={9} tickLine={false} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0c1220',
                  borderColor: '#1e2a44',
                  borderRadius: '8px',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              />
              <Line
                type="monotone"
                dataKey="pps"
                stroke="#06b6d4"
                strokeWidth={2}
                dot={false}
                isAnimationActive={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* 2. Protocol Distribution Donut */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-xs font-mono uppercase text-gray-300 font-semibold tracking-wider">
            Protocol Breakdown
          </h4>
          <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/40">
            L4 Layer
          </span>
        </div>
        <div className="flex items-center justify-between h-44">
          <div className="h-full w-1/2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  innerRadius={38}
                  outerRadius={55}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {pieData.map((entry) => (
                    <Cell
                      key={`cell-${entry.name}`}
                      fill={PROTO_COLORS[entry.name] || '#6b7280'}
                    />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
          </div>
          {/* Legend */}
          <div className="w-1/2 space-y-1.5 pl-2 font-mono text-xs">
            {pieData.map((entry) => {
              const pct = totalPie > 0 ? ((entry.value / totalPie) * 100).toFixed(1) : 0;
              return (
                <div key={entry.name} className="flex items-center justify-between">
                  <div className="flex items-center space-x-1.5">
                    <span
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: PROTO_COLORS[entry.name] || '#6b7280' }}
                    />
                    <span className="text-gray-400 text-[11px]">{entry.name}</span>
                  </div>
                  <span className="text-gray-200 text-[11px] font-semibold">{pct}%</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 3. Top Talkers Bar Chart */}
      <div className="bg-[#101728] border border-[#1e2a44] rounded-xl p-4 flex flex-col justify-between">
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-xs font-mono uppercase text-gray-300 font-semibold tracking-wider">
            Top 5 Talkers (Sources)
          </h4>
          <span className="text-[10px] font-mono text-purple-400 bg-purple-950/50 px-2 py-0.5 rounded border border-purple-800/40">
            Traffic Leaders
          </span>
        </div>
        <div className="h-44 w-full">
          {topSources.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topSources} layout="vertical" margin={{ left: 10, right: 10 }}>
                <XAxis type="number" stroke="#4b5563" fontSize={9} tickLine={false} />
                <YAxis
                  dataKey="ip"
                  type="category"
                  stroke="#9ca3af"
                  fontSize={10}
                  tickLine={false}
                  width={85}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0c1220',
                    borderColor: '#1e2a44',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                  }}
                  formatter={(val, name, item) => [`${val} pkts (${item.payload.kb} KB)`, 'Volume']}
                />
                <Bar dataKey="packets" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-gray-500 font-mono">
              Waiting for traffic data...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
