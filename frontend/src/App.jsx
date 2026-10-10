import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api.js";
import Dashboard from "./components/Dashboard.jsx";
import Analyze from "./components/Analyze.jsx";
import ModelTab from "./components/ModelTab.jsx";

const TABS = ["Dashboard", "Analyze Flow", "Model"];

export default function App() {
  const [tab, setTab] = useState("Dashboard");
  const [stats, setStats] = useState(null);
  const [rows, setRows] = useState([]);
  const [filters, setFilters] = useState({ status: "", attack_type: "", severity: "" });
  const [health, setHealth] = useState(null);
  const [error, setError] = useState("");
  const [live, setLive] = useState(false);
  const filtersRef = useRef(filters);
  filtersRef.current = filters;

  const refresh = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([api.stats(), api.detections({ limit: 100, ...filtersRef.current })]);
      setStats(s);
      setRows(d);
      setError("");
    } catch (e) {
      setError(e.message);
    }
  }, []);

  useEffect(() => {
    api.health().then(setHealth).catch((e) => setError(e.message));
    refresh();
  }, [refresh]);

  useEffect(() => { refresh(); }, [filters, refresh]);

  // "Live monitor": every 3 s feed a small batch of simulated traffic through the model.
  useEffect(() => {
    if (!live) return;
    const id = setInterval(async () => {
      try {
        await api.simulate(8, 0.25);
        await refresh();
      } catch (e) {
        setError(e.message);
        setLive(false);
      }
    }, 3000);
    return () => clearInterval(id);
  }, [live, refresh]);

  const level = stats?.by_severity?.Critical ? "critical" : stats?.by_severity?.High ? "high" : stats?.suspicious ? "elevated" : "ok";
  const statusText = { critical: "Critical threats detected", high: "High-severity threats detected",
    elevated: "Suspicious activity detected", ok: "Network looks normal" }[level];

  return (
    <div className="app">
      <header>
        <div>
          <h1>🛡️ AI Threat Detection</h1>
          <p className="muted">ML-based network traffic analysis · DDoS · Port scan · Brute force</p>
        </div>
        <div className={`status-pill ${level}`}>{stats ? statusText : "Connecting…"}</div>
      </header>

      <nav>
        {TABS.map((t) => (
          <button key={t} className={t === tab ? "active" : ""} onClick={() => setTab(t)}>{t}</button>
        ))}
      </nav>

      {error && <div className="banner">API error: {error}. Is the backend running on port 8000?</div>}
      {health && !health.model_loaded && (
        <div className="banner">No trained model found — run <code>python scripts/train.py</code> and restart the API.</div>
      )}

      {tab === "Dashboard" && (
        <Dashboard stats={stats} rows={rows} filters={filters} setFilters={setFilters}
          live={live} setLive={setLive} refresh={refresh} />
      )}
      {tab === "Analyze Flow" && <Analyze onDone={refresh} />}
      {tab === "Model" && <ModelTab />}
    </div>
  );
}
