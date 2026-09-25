"""Snapshot builder: logs -> temporal graph windows.
Reads cloud_simulation/logs/requests.jsonl (shared volume), slices WINDOW_SEC,
builds 25-node graph, 11-feature vectors, LOW/MEDIUM/HIGH label.

Also reads cloud_simulation/logs/run_state.json (written by simulator.py) so
each snapshot is tagged with run_id + scheduled_phase. scheduled_phase is
ground-truth metadata for debugging/train-val-test splitting only -- it is
NOT a model input feature.

Run: python -m graph_model.snapshot_builder [--window-sec 300]
Output: graph_model/snapshots/window_{N}.json
"""
import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

import networkx as nx

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "cloud_simulation" / "logs" / "requests.jsonl"
STATE_FILE = BASE_DIR / "cloud_simulation" / "logs" / "run_state.json"
SNAP_DIR = BASE_DIR / "graph_model" / "snapshots"
ASSETS_FILE = BASE_DIR / "asset_discovery" / "assets.json"

NODE_ORDER = [
    "api-server", "auth-service", "payment-service", "worker-service",
    "user-docs", "kyc-files", "audit-logs", "backups",
    "db-access-role", "lambda-exec-role", "readonly-role", "payment-role",
    "admin-role", "payment-lambda", "kyc-lambda", "notify-lambda",
    "fintech-api-gateway", "tx-queue", "notify-queue", "mysql-db",
    "redis-cache", "waf-firewall", "load-balancer", "cloudtrail-logs", "kms-keys",
]

BASE_EDGES = [
    ("waf-firewall", "load-balancer"), ("load-balancer", "fintech-api-gateway"),
    ("load-balancer", "api-server"), ("fintech-api-gateway", "api-server"),
    ("api-server", "auth-service"), ("api-server", "payment-service"),
    ("api-server", "mysql-db"), ("auth-service", "mysql-db"),
    ("payment-service", "mysql-db"), ("payment-service", "redis-cache"),
    ("api-server", "user-docs"), ("api-server", "audit-logs"),
    ("payment-service", "kyc-files"), ("payment-service", "backups"),
    ("api-server", "readonly-role"), ("auth-service", "db-access-role"),
    ("payment-service", "payment-role"), ("db-access-role", "admin-role"),
    ("payment-role", "admin-role"), ("tx-queue", "payment-lambda"),
    ("notify-queue", "notify-lambda"), ("kyc-files", "kyc-lambda"),
    ("lambda-exec-role", "payment-lambda"), ("lambda-exec-role", "kyc-lambda"),
    ("lambda-exec-role", "notify-lambda"), ("admin-role", "kms-keys"),
    ("admin-role", "cloudtrail-logs"), ("admin-role", "mysql-db"),
    ("worker-service", "tx-queue"), ("worker-service", "notify-queue"),
    ("api-server", "worker-service"), ("api-server", "api-server"),
]

EXPOSURE_MAP = {"public": 1.0, "internal": 0.5, "private": 0.0}
PRIVILEGE_MAP = {"limited": 0.25, "storage": 0.5, "compute": 0.6, "gateway": 0.7,
                 "api": 0.75, "auth": 0.8, "database": 0.9, "payment": 0.9,
                 "admin": 1.0, "infra": 0.5}
TYPE_MAP = {"DockerService": 1.0, "EC2": 2.0, "S3Bucket": 3.0, "IAMRole": 4.0,
            "Lambda": 5.0, "APIGateway": 6.0, "SQS": 7.0, "ElastiCache": 8.0,
            "WAF": 9.0, "ALB": 10.0, "CloudTrail": 11.0, "KMS": 12.0}
FEATURE_NAMES = ["cvss", "exposure", "privilege", "patch_status", "auth_strength",
                 "asset_type", "pagerank", "betweenness", "degree_centrality",
                 "in_degree", "out_degree", "anomaly_score"]


def load_assets():
    with open(ASSETS_FILE) as f:
        assets = json.load(f)
    lookup = {}
    for a in assets:
        lookup[a["name"]] = a  # last wins (Docker entries)
    return lookup


def read_run_state():
    """Best-effort read of the simulator's current run_id/phase. Returns
    defaults if the simulator isn't running or hasn't written state yet."""
    if not STATE_FILE.exists():
        return {"run_id": "unknown", "window": None, "cycle_window": None, "phase": None}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {"run_id": "unknown", "window": None, "cycle_window": None, "phase": None}


def read_window(window_sec):
    if not LOG_FILE.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_sec)
    out = []
    with open(LOG_FILE) as f:
        for line in f:
            try:
                e = json.loads(line)
                ts = datetime.fromisoformat(e["timestamp"])
                if ts >= cutoff:
                    out.append(e)
            except Exception:
                continue
    return out


def build_snapshot(events, window_id, asset_lookup, run_meta):
    pair_counts = Counter((e["source"], e["destination"]) for e in events)
    failed_401 = Counter(e["destination"] for e in events if int(e.get("status", 200)) == 401)
    hits = Counter(e["destination"] for e in events)
    hits.update(e["source"] for e in events)

    G = nx.DiGraph()
    for n in NODE_ORDER:
        G.add_node(n)
    base_set = set(BASE_EDGES)
    for s, t in BASE_EDGES:
        G.add_edge(s, t, weight=float(pair_counts.get((s, t), 1)), type="base")
    for (s, t), c in pair_counts.items():
        if (s, t) not in base_set:
            if s not in G:
                G.add_node(s)
            if t not in G:
                G.add_node(t)
            G.add_edge(s, t, weight=float(c), type="dynamic_attack")
        else:
            G[s][t]["weight"] = float(c if c else 1)
            # Red attack edges: new exploit edge OR volume spike (recon/exfil) OR brute 401s
            if c and ((s, t) == ("auth-service", "admin-role") or c > 30 or failed_401.get(t, 0) > 5):
                G[s][t]["type"] = "dynamic_attack"

    pr = nx.pagerank(G, weight="weight")
    bw = nx.betweenness_centrality(G, weight="weight")
    dc = nx.degree_centrality(G)

    matrix = []
    for n in NODE_ORDER:
        a = asset_lookup.get(n, {})
        sec = [float(a.get("cvss", 0)) / 10.0,
               EXPOSURE_MAP.get(a.get("exposure", "private"), 0.0),
               PRIVILEGE_MAP.get(a.get("privilege", "limited"), 0.0),
               0.0, 0.0, TYPE_MAP.get(a.get("type", ""), 0.0)]
        fl = float(failed_401.get(n, 0))
        hc = float(hits.get(n, 0))
        anomaly = round(min(max(fl / 20.0, hc / 200.0), 1.0), 4)
        graph = [round(pr.get(n, 0.0), 6), round(bw.get(n, 0.0), 6),
                 round(dc.get(n, 0.0), 6), float(G.in_degree(n)), float(G.out_degree(n))]
        matrix.append(sec + graph + [anomaly])

    total = len(events)
    max_fail = max(failed_401.values()) if failed_401 else 0
    has_exploit = ("auth-service", "admin-role") in pair_counts
    label = "HIGH" if (max_fail > 20 or total > 200 or has_exploit) else ("MEDIUM" if total > 80 else "LOW")
    edges = [{"source": s, "target": t, "weight": d["weight"], "type": d["type"]} for s, t, d in G.edges(data=True)]
    return {"window": window_id, "timestamp": datetime.now(timezone.utc).isoformat(),
            "label": label, "event_count": total, "max_failed_login": max_fail,
            "run_id": run_meta.get("run_id"),
            "sim_window": run_meta.get("window"),
            "cycle_window": run_meta.get("cycle_window"),
            "scheduled_phase": run_meta.get("phase"),
            "nodes": NODE_ORDER, "feature_names": FEATURE_NAMES,
            "feature_matrix": matrix, "edges": edges}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-sec", type=int, default=300)
    args = ap.parse_args()
    SNAP_DIR.mkdir(parents=True, exist_ok=True)
    lookup = load_assets()
    # resume numbering
    existing = list(SNAP_DIR.glob("window_*.json"))
    window_id = len(existing)
    print(f"Snapshot builder: log={LOG_FILE}, window_sec={args.window_sec}, start={window_id}")
    while True:
        events = read_window(args.window_sec)
        run_meta = read_run_state()
        snap = build_snapshot(events, window_id, lookup, run_meta)
        with open(SNAP_DIR / f"window_{window_id}.json", "w") as f:
            json.dump(snap, f, indent=2)
        print(f"window_{window_id}.json: run={snap['run_id']} scheduled={snap['scheduled_phase']} "
              f"label={snap['label']} events={snap['event_count']} max401={snap['max_failed_login']} "
              f"edges={len(snap['edges'])}")
        window_id += 1
        time.sleep(args.window_sec)


if __name__ == "__main__":
    main()