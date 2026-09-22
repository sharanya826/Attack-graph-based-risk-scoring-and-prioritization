"""Load window JSONs -> tensors. No torch_geometric needed."""
import glob
import json
from pathlib import Path

import torch

BASE = Path(__file__).resolve().parent.parent
LABEL_MAP = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def load_windows(patterns):
    files = []
    for p in patterns:
        files.extend(glob.glob(str(BASE / p)))
    out = []
    for f in sorted(files):
        try:
            d = json.load(open(f))
            X = torch.tensor(d["feature_matrix"], dtype=torch.float32)  # [25,12] (11+anomaly? actually 12)
            # keep first 11 to match roadmap (drop or keep anomaly -> use 12, model adapts)
            nodes = d["nodes"]
            idx = {n: i for i, n in enumerate(nodes)}
            src, dst, w = [], [], []
            for e in d.get("edges", []):
                if e["source"] in idx and e["target"] in idx:
                    src.append(idx[e["source"]]); dst.append(idx[e["target"]])
                    w.append(float(e.get("weight", 1.0)))
            if not src:
                src, dst, w = [0], [0], [1.0]
            edge_index = torch.tensor([src, dst], dtype=torch.long)
            edge_weight = torch.tensor(w, dtype=torch.float32)
            y = torch.tensor(LABEL_MAP.get(d.get("label", "LOW"), 0), dtype=torch.long)
            out.append({"X": X, "edge_index": edge_index, "edge_weight": edge_weight,
                        "y": y, "file": f, "label": d.get("label", "LOW")})
        except Exception as e:
            print(f"skip {f}: {e}")
    return out
