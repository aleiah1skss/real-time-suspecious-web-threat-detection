import { useState } from "react";

export default function App() {
  const [ip, setIp] = useState("");
  const [url, setUrl] = useState("");
  const [payload, setPayload] = useState("");
  const [ua, setUa] = useState("");
  const [logsText, setLogsText] = useState("");
  const [results, setResults] = useState([]);
  const [autoDetect, setAutoDetect] = useState(true);

  const rules = [
    { id: "sqli_union", name: "SQLi - UNION SELECT", pattern: /union\s+select/i, level: "High" },
    { id: "sqli_or_true", name: "SQLi - OR 1=1", pattern: /or\s+1\s*=\s*1/i, level: "High" },
    { id: "sqli_drop", name: "SQLi - DROP TABLE", pattern: /drop\s+table/i, level: "High" },
    { id: "xss_script", name: "XSS - <script>", pattern: /<script\b[^>]*>/i, level: "High" },
    { id: "xss_onerror", name: "XSS - onerror=", pattern: /onerror\s*=/i, level: "Medium" },
    { id: "js_proto", name: "javascript: URL", pattern: /javascript:/i, level: "Medium" },
    { id: "path_traversal", name: "Path Traversal", pattern: /\.\.\//, level: "Medium" },
    { id: "sus_chars", name: "Suspicious Characters", pattern: /['\";]{2,}|--/, level: "Low" },
    { id: "sus_ua", name: "Suspicious User-Agent", pattern: /(sqlmap|curl|nikto|nmap|masscan)/i, level: "Medium" },
  ];

  function analyze(entry) {
    const text = [entry.ip, entry.url, entry.payload, entry.ua].join(" ");
    const matched = rules.filter(r => r.pattern.test(text));

    let level = "Low";
    if (matched.some(m => m.level === "High")) level = "High";
    else if (matched.some(m => m.level === "Medium")) level = "Medium";

    return {
      id: Math.random().toString(36).slice(2),
      ...entry,
      matched,
      threat_level: level,
      detected_at: new Date().toLocaleString(),
    };
  }

  function detect() {
    const res = analyze({ ip, url, payload, ua });
    setResults([res, ...results]);
  }

  function scanLogs() {
    const lines = logsText.split("\n").filter(l => l.trim() !== "");
    const out = [];

    for (const ln of lines) {
      let parts = ln.split("|").map(p => p.trim());
      const entry = {
        ip: parts[0] || "",
        url: parts[1] || "",
        payload: parts[2] || "",
        ua: parts[3] || "",
      };
      out.push(analyze(entry));
    }
    setResults([...out, ...results]);
  }

  return (
    <div className="min-h-screen bg-black text-cyan-100 p-6 font-mono">
      <h1 className="text-4xl neon-text text-center mb-8">CYBER THREAT DETECTOR</h1>

      <div className="max-w-4xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-6">
        
        {/* INPUT PANEL */}
        <div className="p-4 border border-cyan-600 rounded-xl bg-black/50">
          <h2 className="text-xl mb-3">Manual Detection</h2>

          <label>IP</label>
          <input className="w-full mb-2 p-2 bg-transparent border border-cyan-700 rounded" 
            value={ip} onChange={e => setIp(e.target.value)} />

          <label>URL</label>
          <input className="w-full mb-2 p-2 bg-transparent border border-cyan-700 rounded" 
            value={url} onChange={e => setUrl(e.target.value)} />

          <label>Payload</label>
          <textarea className="w-full mb-2 p-2 bg-transparent border border-cyan-700 rounded"
            value={payload} onChange={e => setPayload(e.target.value)} />

          <label>User-Agent</label>
          <input className="w-full mb-2 p-2 bg-transparent border border-cyan-700 rounded"
            value={ua} onChange={e => setUa(e.target.value)} />

          <button onClick={detect} className="w-full mt-3 p-2 bg-cyan-800 rounded-xl">
            Detect Threat
          </button>
        </div>

        {/* LOG PANEL */}
        <div className="p-4 border border-cyan-600 rounded-xl bg-black/50">
          <h2 className="text-xl mb-3">Bulk Log Scanner</h2>
          <textarea className="w-full h-40 p-2 bg-transparent border border-cyan-700 rounded"
            value={logsText} onChange={e => setLogsText(e.target.value)}
            placeholder="192.168.0.1 | /login | ' OR 1=1 -- | sqlmap/1.5" />
          
          <button onClick={scanLogs} className="w-full mt-3 p-2 bg-purple-700 rounded-xl">
            Scan Logs
          </button>
        </div>

      </div>

      {/* RESULTS */}
      <div className="max-w-4xl mx-auto mt-8">
        <h2 className="text-2xl mb-3">Detections</h2>

        {results.map(r => (
          <div key={r.id} className="mb-3 p-4 border border-cyan-700 rounded-xl bg-black/40">
            <div className="flex justify-between">
              <span className="text-sm opacity-70">{r.ip || "No IP"}</span>
              <span className="text-sm opacity-70">{r.detected_at}</span>
            </div>

            <div className="mt-2">URL: {r.url}</div>
            {r.payload && <div className="text-sm opacity-70">Payload: {r.payload}</div>}
            {r.ua && <div className="text-sm opacity-70">User-Agent: {r.ua}</div>}

            <div className="mt-3">
              <strong>Level:</strong> {r.threat_level}
            </div>

            <div className="mt-2 flex flex-wrap gap-2">
              {r.matched.map(m => (
                <span key={m.id} className="px-2 py-1 border border-cyan-600 rounded-full text-xs">
                  {m.name}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Neon CSS */}
      <style>{`
        .neon-text {
          color: #7efcff;
          text-shadow: 0 0 10px rgba(126,252,255,0.7),
                       0 0 20px rgba(126,252,255,0.5);
        }
      `}</style>
    </div>
  );
}
