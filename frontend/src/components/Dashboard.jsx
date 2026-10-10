import { useState } from "react";
import { api } from "../api.js";
import {
  Bar, BarChart, CartesianGrid, Cell, Legend, Pie, PieChart, ResponsiveContainer,
  Tooltip, XAxis, YAxis, Area, AreaChart,
} from "recharts";

export const SEV_COLOR = { Critical: "#d92d20", High: "#f79009", Medium: "#eab308", Low: "#2e90fa", None: "#12b76a" };
export const ATTACK_COLOR = { BENIGN: "#12b76a", DDoS: "#d92d20", PortScan: "#f79009", BruteForce: "#7a5af8", Anomaly: "#2e90fa" };

function Stat({ label, value, sub, tone }) {
  return (
    <div className={`card stat ${tone || ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub && <div className="muted small">{sub}</div>}
    </div>
  );
}

export function Badge({ text, color }) {
  return <span className="badge" style={{ background: color + "22", color }}>{text}</span>;
}

export default function Dashboard({ stats, rows, filters, setFilters, live, setLive, refresh }) {
  const [busy, setBusy] = useState(false);
  const [ratio, setRatio] = useState(0.3);

  const run = async (fn) => {
    setBusy(true);
    try { await fn(); await refresh(); } finally { setBusy(false); }
  };

  const attackData = Object.entries(stats?.by_attack || {}).map(([name, value]) => ({ name, value }));
  const sevData = ["Critical", "High", "Medium", "Low"].map((k) => ({ name: k, value: stats?.by_severity?.[k] || 0 }));

  return (
    <>
      <section className="toolbar card">
        <button disabled={busy} onClick={() => run(() => api.simulate(30, ratio))}>▶ Simulate 30 flows</button>
        <label className="inline">
          Attack share {Math.round(ratio * 100)}%
          <input type="range" min="0" max="1" step="0.05" value={ratio} onChange={(e) => setRatio(+e.target.value)} />
        </label>
        <button className={live ? "danger" : ""} onClick={() => setLive(!live)}>
          {live ? "■ Stop live monitor" : "● Start live monitor"}
        </button>
        <button className="ghost" disabled={busy} onClick={() => run(api.clear)}>Clear history</button>
      </section>

      <section className="grid stats">
        <Stat label="Flows analysed" value={stats?.total ?? "–"} />
        <Stat label="Suspicious" value={stats?.suspicious ?? "–"} tone={stats?.suspicious ? "warn" : ""}
          sub={stats ? `${(stats.suspicious_rate * 100).toFixed(1)}% of traffic` : ""} />
        <Stat label="Normal" value={stats?.normal ?? "–"} tone="good" />
        <Stat label="Avg threat severity" value={stats ? stats.avg_severity : "–"} sub="out of 100, suspicious flows" />
      </section>

      <section className="grid charts">
        <div className="card wide">
          <h3>Traffic – last 30 minutes</h3>
          <ResponsiveContainer width="100%" height={230}>
            <AreaChart data={stats?.timeline || []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="time" tick={{ fontSize: 11 }} interval={4} />
              <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Legend />
              <Area type="monotone" dataKey="normal" stackId="1" stroke="#12b76a" fill="#12b76a55" />
              <Area type="monotone" dataKey="suspicious" stackId="1" stroke="#d92d20" fill="#d92d2066" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h3>Attack categories</h3>
          <ResponsiveContainer width="100%" height={230}>
            <PieChart>
              <Pie data={attackData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={80} paddingAngle={2}>
                {attackData.map((d) => <Cell key={d.name} fill={ATTACK_COLOR[d.name] || "#98a2b3"} />)}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="card">
          <h3>Severity levels</h3>
          <ResponsiveContainer width="100%" height={230}>
            <BarChart data={sevData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="name" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Bar dataKey="value">{sevData.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name]} />)}</Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="card">
        <div className="row-between">
          <h3>Detection log</h3>
          <div className="filters">
            <select value={filters.status} onChange={(e) => setFilters({ ...filters, status: e.target.value })}>
              <option value="">All traffic</option><option value="suspicious">Suspicious</option><option value="normal">Normal</option>
            </select>
            <select value={filters.attack_type} onChange={(e) => setFilters({ ...filters, attack_type: e.target.value })}>
              <option value="">All types</option>
              {["DDoS", "PortScan", "BruteForce", "Anomaly", "BENIGN"].map((t) => <option key={t}>{t}</option>)}
            </select>
            <select value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
              <option value="">All severities</option>
              {["Critical", "High", "Medium", "Low"].map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Time</th><th>Source → Destination</th><th>Proto</th><th>Verdict</th><th>Attack type</th>
                <th>Confidence</th><th>Severity</th></tr>
            </thead>
            <tbody>
              {rows.length === 0 && <tr><td colSpan="7" className="muted center">No detections yet — press “Simulate”.</td></tr>}
              {rows.map((r) => (
                <tr key={r.id}>
                  <td>{new Date(r.created_at).toLocaleTimeString()}</td>
                  <td className="mono">{r.src_ip || "—"}:{r.src_port} → {r.dst_ip || "—"}:{r.dst_port}</td>
                  <td>{{ 6: "TCP", 17: "UDP", 1: "ICMP" }[r.protocol] || r.protocol}</td>
                  <td><Badge text={r.status} color={r.status === "suspicious" ? "#d92d20" : "#12b76a"} /></td>
                  <td><Badge text={r.attack_type} color={ATTACK_COLOR[r.attack_type] || "#667085"} /></td>
                  <td>{(r.confidence * 100).toFixed(1)}%</td>
                  <td>
                    <span className="sev-bar"><i style={{ width: `${r.severity_score}%`, background: SEV_COLOR[r.severity_level] }} /></span>
                    {r.severity_score} <span className="muted small">{r.severity_level}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
