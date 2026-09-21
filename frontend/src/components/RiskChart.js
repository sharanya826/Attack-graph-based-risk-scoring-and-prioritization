import { useEffect, useState } from "react";
import axios from "axios";
import { BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer } from "recharts";

export default function RiskChart() {
  const [data, setData] = useState([]);
  useEffect(() => {
    axios.get("http://localhost:8000/risk-scores").then(r => {
      setData([...r.data].sort((a, b) => b.risk - a.risk));
    }).catch(() => {});
  }, []);
  const color = l => l === "HIGH" ? "#d32f2f" : l === "MEDIUM" ? "#f9a825" : "#2e7d32";
  return <div style={{ height: 320 }}><h3>Risk scores (25 assets)</h3>
    <ResponsiveContainer><BarChart data={data} layout="vertical" margin={{ left: 110 }}>
      <XAxis type="number" domain={[0, 1]} /><YAxis type="category" dataKey="node" width={110} tick={{ fontSize: 11 }} />
      <Tooltip /><Bar dataKey="risk">{data.map(d => <Cell key={d.node} fill={color(d.level)} />)}</Bar>
    </BarChart></ResponsiveContainer></div>;
}
