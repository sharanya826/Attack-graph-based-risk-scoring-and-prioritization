import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { Network } from "vis-network";
import { DataSet } from "vis-data";

const STAGE = (from, to, w, fails) => {
  if (from === "auth-service" && to === "admin-role") return `EXPLOIT: forged-token ${from}->${to}`;
  if (fails > 5) return `BRUTE: 80x401 ${from}->${to}`;
  if (w > 100) return `RECON/EXFIL: flood ${from}->${to} x${Math.round(w)}`;
  if (w > 30) return `FLOOD: ${from}->${to} x${Math.round(w)}`;
  return `${from}->${to}`;
};

export default function PathsPanel() {
  const ref = useRef(null);
  const net = useRef(null);
  const nodesDs = useRef(null);
  const [live, setLive] = useState(null);
  const [step, setStep] = useState(0);
  const [chain, setChain] = useState([]);
  const [hopInfo, setHopInfo] = useState([]);

  useEffect(() => {
    const poll = async () => {
      try {
        const [{ data: paths }, { data: risks }, { data: latest }] = await Promise.all([
          axios.get("http://localhost:8000/attack-paths"),
          axios.get("http://localhost:8000/risk-scores").catch(() => ({ data: [] })),
          axios.get("http://localhost:8000/latest").catch(() => ({ data: null })),
        ]);
        setLive(latest);
        const rm = Object.fromEntries((risks || []).map(x => [x.node, x.level]));
        const col = l => l === "HIGH" ? "#ef9a9a" : l === "MEDIUM" ? "#ffe082" : "#a5d6a7";
        const edgeMap = {};
        (latest && latest.edges ? latest.edges : []).forEach(e => { edgeMap[`${e.source || e.from}->${e.target || e.to}`] = e; });
        const dynSet = new Set((latest && latest.edges ? latest.edges : []).filter(e => e.type === "dynamic_attack").map(e => `${e.source || e.from}->${e.target || e.to}`));
        let best = paths[0]; let bestHit = -1;
        paths.slice(0, 20).forEach(p => {
          const hit = (p.path || []).slice(1).filter((n, i) => dynSet.has(`${p.path[i]}->${n}`)).length;
          if (hit > bestHit) { bestHit = hit; best = p; }
        });
        if (!best) return;
        const ch = best.path || [];
        setChain(ch);
        setHopInfo(ch.slice(1).map((n, i) => {
          const e = edgeMap[`${ch[i]}->${n}`] || {};
          return { from: ch[i], to: n, w: e.weight || 1, fails: (latest && latest.max_failed_login) || 0, fired: dynSet.has(`${ch[i]}->${n}`) };
        }));
        const nodes = new DataSet(ch.map(n => ({ id: n, label: n, shape: "box", color: col(rm[n]) })));
        const edges = new DataSet(ch.slice(1).map((n, i) => ({ id: i, from: ch[i], to: n, arrows: "to", color: "#848484", width: 2 })));
        nodesDs.current = nodes;
        if (net.current) net.current.destroy();
        net.current = new Network(ref.current, { nodes, edges }, {
          layout: { hierarchical: { enabled: true, direction: "LR" } },
          interaction: { dragNodes: true, zoomView: true, hover: true }, physics: { enabled: false },
        });
        setStep(0);
      } catch {}
    };
    poll();
    const t = setInterval(poll, 15000);
    return () => { clearInterval(t); if (net.current) net.current.destroy(); };
  }, []);

  // animate attacker moving hop-by-hop
  useEffect(() => {
    if (!chain.length || !nodesDs.current || !net.current) return;
    const firedIdx = hopInfo.map((h, i) => h.fired ? i : -1).filter(i => i >= 0);
    const seq = firedIdx.length ? firedIdx : chain.slice(1).map((_, i) => i);
    if (!seq.length) return;
    let k = 0;
    const anim = setInterval(() => {
      const hi = seq[k % seq.length];
      try {
        const nodes = nodesDs.current;
        chain.forEach(n => nodes.update({ id: n, color: "#a5d6a7" }));
        for (let j = 0; j <= hi + 1 && j < chain.length; j++) nodes.update({ id: chain[j], color: j <= hi ? "#ef9a9a" : "#ffe082" });
        net.current.selectNodes([chain[Math.min(hi + 1, chain.length - 1)]]);
      } catch {}
      setStep(hi);
      k++;
    }, 900);
    return () => clearInterval(anim);
  }, [chain, hopInfo]);

  const attackLive = live && live.edges && live.edges.some(e => e.type === "dynamic_attack");
  const cur = hopInfo[step];
  return <div>
    <h3>Live attack replay</h3>
    <div style={{ marginBottom: 8, padding: 8, background: attackLive ? "#ffebee" : "#e8f5e9", border: "1px solid #ccc" }}>
      {live ? <>Window {live.window} — <b>{live.label}</b> — {attackLive ? <>ATTACKER MOVING: <b>{cur ? STAGE(cur.from, cur.to, cur.w, cur.fails) : ""}</b> (hop {step + 1}/{hopInfo.length})</> : "no attack — run simulator window 9 / forged-token"} </> : "Loading..."}
    </div>
    <div ref={ref} style={{ height: 320, border: "1px solid #ccc" }} />
    <div style={{ fontSize: 13, marginTop: 6 }}>Green = not yet reached, amber = next, red = breached. Attacker dot auto-steps every 0.9s through fired hops.</div>
  </div>;
}
