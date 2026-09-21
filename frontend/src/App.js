import { useState } from "react";
import Summary from "./components/Summary";
import RiskChart from "./components/RiskChart";
import AttackGraph from "./components/AttackGraph";
import PathsPanel from "./components/PathsPanel";

const TABS = [["summary", "Summary"], ["risk", "Risk Chart"], ["graph", "Attack Graph"], ["paths", "Critical Paths"]];

function App() {
  const [tab, setTab] = useState("summary");
  return (
    <div style={{ padding: 16, fontFamily: "sans-serif" }}>
      <h2>Fintech Risk Dashboard</h2>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {TABS.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)}
            style={{ padding: "8px 16px", cursor: "pointer", fontWeight: tab === id ? "bold" : "normal",
              background: tab === id ? "#1976d2" : "#eee", color: tab === id ? "#fff" : "#000", border: "none" }}>
            {label}</button>))}
      </div>
      {tab === "summary" && <Summary />}
      {tab === "risk" && <RiskChart />}
      {tab === "graph" && <AttackGraph />}
      {tab === "paths" && <PathsPanel />}
    </div>
  );
}
export default App;
