import { useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api.js";

function ConfusionMatrix({ cm, classes }) {
  const max = Math.max(...cm.flat(), 1);
  return (
    <table className="cm">
      <thead>
        <tr><th></th>{classes.map((c) => <th key={c}>Pred<br />{c}</th>)}</tr>
      </thead>
      <tbody>
        {cm.map((row, i) => (
          <tr key={i}>
            <th>Actual {classes[i]}</th>
            {row.map((v, j) => (
              <td key={j} style={{ background: `rgba(46,144,250,${(v / max) * 0.85})`, color: v / max > 0.5 ? "#fff" : "#101828" }}>{v}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function ModelTab() {
  const [m, setM] = useState(null);
  const [err, setErr] = useState("");
  useEffect(() => { api.model().then(setM).catch((e) => setErr(e.message)); }, []);

  if (err) return <div className="banner">{err}</div>;
  if (!m) return <p className="muted">Loading…</p>;

  const best = m.models[m.best_model];
  const imp = Object.entries(m.feature_selection.importance).map(([name, value]) => ({ name, value }));
  const pct = (x) => `${(x * 100).toFixed(2)}%`;

  return (
    <>
      <section className="card">
        <h3>Model comparison</h3>
        <p className="muted small">Dataset: <b>{m.dataset}</b> · {m.rows.toLocaleString()} flows · best model: <b>{m.best_model}</b></p>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Model</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th><th>Train time</th></tr></thead>
            <tbody>
              {Object.values(m.models).map((r) => (
                <tr key={r.name} className={r.name === m.best_model ? "hl" : ""}>
                  <td>{r.name}</td><td>{pct(r.accuracy)}</td><td>{pct(r.precision_macro)}</td>
                  <td>{pct(r.recall_macro)}</td><td>{pct(r.f1_macro)}</td><td>{r.train_seconds}s</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">Precision / recall / F1 are macro-averaged across classes.</p>
      </section>

      <section className="grid two">
        <div className="card">
          <h3>Confusion matrix – {m.best_model}</h3>
          <ConfusionMatrix cm={best.confusion_matrix} classes={m.classes} />
        </div>
        <div className="card">
          <h3>Feature importance</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={imp} layout="vertical" margin={{ left: 30 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis type="number" tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="name" width={110} tick={{ fontSize: 11 }} />
              <Tooltip />
              <Bar dataKey="value" fill="#2e90fa" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="card">
        <h3>Per-class results – {m.best_model}</h3>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Class</th><th>Precision</th><th>Recall</th><th>F1</th><th>Test samples</th></tr></thead>
            <tbody>
              {Object.entries(best.per_class).map(([c, r]) => (
                <tr key={c}><td>{c}</td><td>{pct(r.precision)}</td><td>{pct(r.recall)}</td><td>{pct(r["f1-score"])}</td><td>{r.support}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">
          Isolation Forest (anomaly detector): flags {pct(m.anomaly_detection.attack_detection_rate)} of attacks on its own,
          with a {pct(m.anomaly_detection.false_positive_rate_on_benign)} false-positive rate on benign traffic.
          Selected features: {m.selected_features.join(", ")}.
        </p>
      </section>
    </>
  );
}
