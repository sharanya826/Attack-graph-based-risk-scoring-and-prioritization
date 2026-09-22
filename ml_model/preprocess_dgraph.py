"""Preprocess DGraphFin -> window JSONs for pre-training.
DGraph is a large directed graph with edge timestamps. If dataset not downloaded yet,
this script generates synthetic pre-train windows in the same format so the
T-GCN+GAT pipeline is unblocked. Replace SYNTHETIC with real loading later.

Real usage: place dgraphfin.npz / edge list in ml_model/dgraph/ with columns
src,dst,timestamp,label then run with --real.
Output: ml_model/dgraph_windows/window_dgraph_{i}.json
"""
import argparse
import json
import random
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT = BASE / "dgraph_windows"
FEATURE_NAMES = ["cvss", "exposure", "privilege", "patch_status", "auth_strength",
                 "asset_type", "pagerank", "betweenness", "degree_centrality",
                 "in_degree", "out_degree", "anomaly_score"]
NODES = [f"entity-{i}" for i in range(25)]


def synth_window(i):
    events = random.randint(50, 250)
    fraud_heavy = (i % 5 == 4)
    label = "HIGH" if fraud_heavy else ("MEDIUM" if events > 120 else "LOW")
    matrix = []
    for _ in NODES:
        anomaly = round(random.uniform(0.5, 1.0) if fraud_heavy else random.uniform(0.0, 0.3), 4)
        matrix.append([round(random.uniform(0.3, 0.9), 3), 0.5, 0.8, 0.0, 0.0, 4.0,
                       0.04, 0.01, 0.1, random.randint(1, 6), random.randint(1, 6), anomaly])
    edges = [{"source": random.choice(NODES), "target": random.choice(NODES),
              "weight": float(random.randint(1, 10)), "type": "base"} for _ in range(30)]
    return {"window": f"dgraph_{i}", "label": label, "event_count": events,
            "max_failed_login": 0, "nodes": NODES, "feature_names": FEATURE_NAMES,
            "feature_matrix": matrix, "edges": edges}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--num-windows", type=int, default=200)
    ap.add_argument("--real", action="store_true",
                    help="Set when ml_model/dgraph/ real files are present (TODO: wire loader)")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if args.real:
        print("Real DGraph loader not wired yet - falling back to synthetic. See docstring.")
    for i in range(args.num_windows):
        with open(OUT / f"window_dgraph_{i}.json", "w") as f:
            json.dump(synth_window(i), f)
    print(f"Wrote {args.num_windows} windows to {OUT}. Pre-train with these, swap to real DGraph later.")


if __name__ == "__main__":
    main()
