import { useEffect, useState } from "react";
import axios from "axios";

export default function Summary() {
  const [s, setS] = useState(null);
  useEffect(() => { axios.get("http://localhost:8000/summary").then(r => setS(r.data)).catch(() => {}); }, []);
  if (!s) return <div>Loading summary...</div>;
  const cards = [["Assets", s.total_assets], ["High", s.high], ["Medium", s.medium], ["Low", s.low], ["Paths", s.paths]];
  return <div style={{ display: "flex", gap: 12 }}>{cards.map(([k, v]) =>
    <div key={k} style={{ border: "1px solid #ccc", padding: 12, minWidth: 90 }}><div>{k}</div><b>{v}</b></div>)}</div>;
}
