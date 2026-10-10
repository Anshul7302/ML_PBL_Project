import { useState } from "react";
import { api } from "../api.js";
import { ATTACK_COLOR, Badge, SEV_COLOR } from "./Dashboard.jsx";

const PRESETS = {
  "Normal HTTPS browsing": { protocol: 6, src_port: 50000, dst_port: 443, duration_ms: 220, fwd_packets: 8, bwd_packets: 10, fwd_bytes: 1400, bwd_bytes: 9000, syn_count: 1, rst_count: 0 },
  "DDoS flood": { protocol: 6, src_port: 51544, dst_port: 80, duration_ms: 40, fwd_packets: 900, bwd_packets: 3, fwd_bytes: 54000, bwd_bytes: 180, syn_count: 40, rst_count: 0 },
  "Port scan probe": { protocol: 6, src_port: 44321, dst_port: 3389, duration_ms: 2, fwd_packets: 1, bwd_packets: 0, fwd_bytes: 44, bwd_bytes: 0, syn_count: 1, rst_count: 1 },
  "SSH brute force": { protocol: 6, src_port: 40222, dst_port: 22, duration_ms: 2100, fwd_packets: 16, bwd_packets: 15, fwd_bytes: 1500, bwd_bytes: 1600, syn_count: 1, rst_count: 1 },
};
const FIELDS = ["protocol", "src_port", "dst_port", "duration_ms", "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes", "syn_count", "rst_count"];

export default function Analyze({ onDone }) {
  const [flow, setFlow] = useState(PRESETS["DDoS flood"]);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      const body = Object.fromEntries(FIELDS.map((k) => [k, Number(flow[k])]));
      setResult(await api.predict(body));
      onDone();
    } catch (ex) { setErr(ex.message); setResult(null); }
    finally { setBusy(false); }
  };

  return (
    <div className="grid two">
      <form className="card" onSubmit={submit}>
        <h3>Analyse a network flow</h3>
        <div className="presets">
          {Object.keys(PRESETS).map((p) => (
            <button type="button" className="ghost" key={p} onClick={() => setFlow(PRESETS[p])}>{p}</button>
          ))}
        </div>
        <div className="form-grid">
          {FIELDS.map((k) => (
            <label key={k}>{k}
              <input type="number" step="any" min="0" value={flow[k]} onChange={(e) => setFlow({ ...flow, [k]: e.target.value })} />
            </label>
          ))}
        </div>
        <button disabled={busy}>{busy ? "Analysing…" : "Analyse flow"}</button>
        {err && <p className="err">{err}</p>}
      </form>

      <div className="card">
        <h3>Result</h3>
        {!result && <p className="muted">Pick a preset or enter feature values, then press Analyse.</p>}
        {result && (
          <>
            <div className="verdict" style={{ borderColor: result.status === "suspicious" ? "#d92d20" : "#12b76a" }}>
              <div className="big">{result.status === "suspicious" ? "⚠ Suspicious traffic" : "✓ Normal traffic"}</div>
              <Badge text={result.attack_type} color={ATTACK_COLOR[result.attack_type] || "#667085"} />{" "}
              <Badge text={`Severity: ${result.severity_level} (${result.severity_score})`} color={SEV_COLOR[result.severity_level]} />
            </div>
            <p>Model confidence: <b>{(result.confidence * 100).toFixed(1)}%</b> · Anomaly score: <b>{result.anomaly_score.toFixed(2)}</b></p>
            <h4>Class probabilities</h4>
            {Object.entries(result.probabilities).map(([c, p]) => (
              <div className="prob" key={c}>
                <span>{c}</span>
                <span className="sev-bar wide"><i style={{ width: `${p * 100}%`, background: ATTACK_COLOR[c] }} /></span>
                <span>{(p * 100).toFixed(1)}%</span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
