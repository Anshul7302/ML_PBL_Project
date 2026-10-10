const BASE = import.meta.env.VITE_API_URL || "";

async function request(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch (_) {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

export const api = {
  health: () => request("/api/health"),
  stats: () => request("/api/stats"),
  detections: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v));
    return request(`/api/detections?${q}`);
  },
  predict: (flow) => request("/api/predict", { method: "POST", body: JSON.stringify(flow) }),
  simulate: (count, attack_ratio) =>
    request("/api/simulate", { method: "POST", body: JSON.stringify({ count, attack_ratio }) }),
  clear: () => request("/api/detections", { method: "DELETE" }),
  model: () => request("/api/model"),
};
