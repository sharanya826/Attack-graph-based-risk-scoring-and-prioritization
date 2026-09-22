import { useEffect, useRef, useState } from "react";
import axios from "axios";
import { Network } from "vis-network";
import { DataSet } from "vis-data";

export default function AttackGraph() {
  const ref = useRef(null);
  const net = useRef(null);
  const [win, setWin] = useState(null);

  useEffect(() => {
    let timer;
    const draw = async () => {
      try {
        const [{ data: g }, { data: risks }, { data: latest }] = await Promise.all([
          axios.get("http://localhost:8000/graph"),
          axios.get("http://localhost:8000/risk-scores").catch(() => ({ data: [] })),
          axios.get("http://localhost:8000/latest").catch(() => ({ data: null })),
        ]);
        const rm = Object.fromEntries((risks || []).map(r => [r.node, r.level]));
        const col = l => l === "HIGH" ? "#ef9a9a" : l === "MEDIUM" ? "#ffe082" : "#a5d6a7";
        // base nodes, id = clean name
        const nodeIds = new Set();
        const nodes = new DataSet((g.nodes || []).map(n => {
          const id = n.name || n.id;
          nodeIds.add(id);
          return { id, label: id, shape: "box", color: col(rm[id]), title: `${id}<br/>${rm[id] || "?"}` };
        }));
        // live edges: prefer latest snapshot (has dynamic_attack + weights), fallback to base
        const live = latest && latest.edges ? latest.edges : (g.edges || []);
        if (latest && latest.window !== undefined) setWin(latest.window);
        const edges = new DataSet(live.map((e, i) => {
          const from = e.from || e.source, to = e.to || e.target;
          if (!nodeIds.has(from)) { nodes.add({ id: from, label: from, shape: "box", color: col(rm[from]) }); nodeIds.add(from); }
          if (!nodeIds.has(to)) { nodes.add({ id: to, label: to, shape: "box", color: col(rm[to]) }); nodeIds.add(to); }
          const dyn = (e.type || "") === "dynamic_attack";
          return { id: i, from, to, arrows: "to", color: dyn ? "#d32f2f" : "#848484",
            width: Math.min(1 + (e.weight || 1) / 20, 6), title: `${from}->${to} w=${e.weight || 1}${dyn ? " ATTACK" : ""}` };
        }));
        if (net.current) { try { net.current.destroy(); } catch {} }
        net.current = new Network(ref.current, { nodes, edges }, {
          layout: { hierarchical: { enabled: true, direction: "LR", sortMethod: "directed" } },
          interaction: { dragNodes: true, zoomView: true, hover: true },
          physics: { enabled: false },
        });
        // pulse live attack edges (flow animation): toggle width 4<->8
        const dynIds = live.map((e, i) => ((e.type || "") === "dynamic_attack" ? i : -1)).filter(i => i >= 0);
        if (dynIds.length) {
          let big = false;
          const pulse = setInterval(() => {
            big = !big;
            try { dynIds.forEach(id => edges.update({ id, width: big ? 8 : 4 })); } catch {}
          }, 600);
          edges.on("*", () => {});
          net.current.once("destroy", () => clearInterval(pulse));
          ref.current._pulse = pulse;
        }
      } catch {}
    };
    draw();
    timer = setInterval(() => { try { clearInterval(ref.current._pulse); } catch {} draw(); }, 5000); // live: refresh 5s so attack edges appear immediately
    return () => { clearInterval(timer); try { clearInterval(ref.current._pulse); } catch {} if (net.current) net.current.destroy(); };
  }, []);
  return <div><h3>Attack graph {win !== null && <span>(window {win}, red pulsing = live attack, refresh 5s)</span>}</h3>
    <div ref={ref} style={{ height: 480, border: "1px solid #ccc" }} /></div>;
}
