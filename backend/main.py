"""FastAPI backend: 6 GET endpoints. Run: uvicorn backend.main:app --port 8000"""
import glob
import json
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

BASE = Path(__file__).resolve().parent.parent
app = FastAPI(title="Risk Scoring API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.get("/health")
def health():
    return {"status": "healthy", "service": "backend"}


def load(p, default):
    try:
        return json.load(open(BASE / p))
    except Exception:
        return default


@app.get("/assets")
def assets():
    return load("asset_discovery/assets.json", [])


@app.get("/graph")
def graph():
    return load("graph_model/graph.json", {"nodes": [], "edges": []})


@app.get("/risk-scores")
def risks():
    return load("ml_model/risk_scores.json", [])


@app.get("/attack-paths")
def paths():
    return load("graph_model/ranked_paths.json", load("graph_model/attack_paths.json", []))


@app.get("/summary")
def summary():
    risks = load("ml_model/risk_scores.json", [])
    paths = load("graph_model/ranked_paths.json", [])
    return {"total_assets": len(load("asset_discovery/assets.json", [])),
            "high": sum(1 for r in risks if r.get("level") == "HIGH"),
            "medium": sum(1 for r in risks if r.get("level") == "MEDIUM"),
            "low": sum(1 for r in risks if r.get("level") == "LOW"),
            "paths": len(paths)}


@app.get("/window/{n}")
def window(n: int):
    return load(f"graph_model/snapshots/window_{n}.json", {"error": "not found"})


@app.get("/latest")
def latest():
    files = sorted((BASE / "graph_model" / "snapshots").glob("window_*.json"),
                   key=lambda p: int(p.stem.split("_")[1]) if p.stem.split("_")[1].isdigit() else -1)
    if not files:
        return {"error": "no snapshots"}
    try:
        return json.load(open(files[-1]))
    except Exception as e:
        return {"error": str(e)}
