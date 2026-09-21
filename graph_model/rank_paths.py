"""Rank attack paths: BFS cutoff 8, score=avg_risk*impact*hops. -> ranked_paths.json"""
import json
from pathlib import Path
import networkx as nx
import pickle

BASE = Path(__file__).resolve().parent.parent
G = pickle.load(open(BASE / "graph_model" / "attack_graph.pkl", "rb"))
risks = {r["node"]: r["risk"] for r in json.load(open(BASE / "ml_model" / "risk_scores.json"))}

ENTRY = ["waf-firewall", "load-balancer", "fintech-api-gateway", "api-server"]
TARGETS = ["mysql-db", "kyc-files", "kms-keys", "admin-role", "payment-service"]
IMPACT = {"mysql-db": 3.0, "kyc-files": 3.0, "kms-keys": 2.5, "admin-role": 2.5,
          "payment-service": 1.8}

ranked = []
for e in ENTRY:
    for t in TARGETS:
        if e not in G or t not in G:
            continue
        try:
            for p in nx.all_simple_paths(G, e, t, cutoff=8):
                avg = sum(risks.get(n, 0.3) for n in p) / len(p)
                score = round(avg * IMPACT.get(t, 1.0) * (len(p) - 1), 4)
                ranked.append({"entry": e, "target": t, "path": p, "hops": len(p) - 1,
                               "score": score, "impact": IMPACT.get(t, 1.0),
                               "path_str": " -> ".join(p)})
        except Exception:
            pass
ranked.sort(key=lambda x: -x["score"])
json.dump(ranked[:20], open(BASE / "graph_model" / "ranked_paths.json", "w"), indent=2)
print(f"ranked {len(ranked)} paths, saved top20. Top3:")
for r in ranked[:3]:
    print(r["score"], r["path_str"])
