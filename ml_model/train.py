"""Train: pre-train on DGraph, fine-tune on sim+PaySim. Baselines: RF. Outputs model.pt, metrics.json, risk_scores.json."""
import argparse
import json
import random
from collections import Counter
from pathlib import Path

import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split

from ml_model.dataset import load_windows
from ml_model.model import TGCN_GAT

BASE = Path(__file__).resolve().parent.parent
OUT = BASE / "ml_model"


def to_device(b, dev):
    return {k: (v.to(dev) if isinstance(v, torch.Tensor) else v) for k, v in b.items()}


def train_torch(data, epochs, lr=0.01, patience=10, save="model.pt"):
    dev = torch.device("cpu")
    in_dim = data[0]["X"].size(1)
    model = TGCN_GAT(in_dim).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=5e-4)
    ys = [d["y"].item() for d in data]
    cnt = Counter(ys)
    w = torch.tensor([len(ys) / cnt.get(i, 1) for i in range(3)])
    loss_fn = nn.CrossEntropyLoss(weight=w)
    tr, va = train_test_split(data, test_size=0.2, random_state=42, stratify=ys)
    best, best_state, wait = -1, None, 0
    for ep in range(epochs):
        model.train()
        h = None
        tot = 0
        random.shuffle(tr)
        for b in tr:
            b = to_device(b, dev)
            opt.zero_grad()
            out, h = model(b["X"], b["edge_index"], b["edge_weight"], None)
            loss = loss_fn(out, b["y"].unsqueeze(0))
            loss.backward()
            opt.step()
            tot += loss.item()
            h = h.detach()
        # val
        model.eval()
        preds, gold = [], []
        with torch.no_grad():
            for b in va:
                b = to_device(b, dev)
                out, _ = model(b["X"], b["edge_index"], b["edge_weight"], None)
                preds.append(out.argmax(1).item()); gold.append(b["y"].item())
        f1 = f1_score(gold, preds, average="weighted", zero_division=0)
        print(f"ep{ep}: loss={tot/len(tr):.3f} val_f1={f1:.3f}")
        if f1 > best:
            best, best_state, wait = f1, {k: v.cpu() for k, v in model.state_dict().items()}, 0
        else:
            wait += 1
            if wait >= patience:
                break
    model.load_state_dict(best_state)
    torch.save(best_state, OUT / save)
    return model, tr, va, best


def eval_split(model, data):
    model.eval()
    preds, gold, probs = [], [], []
    import torch.nn.functional as F
    with torch.no_grad():
        for b in data:
            out, _ = model(b["X"], b["edge_index"], b["edge_weight"], None)
            p = F.softmax(out, 1).squeeze(0)
            preds.append(out.argmax(1).item()); gold.append(b["y"].item()); probs.append(p.tolist())
    try:
        auc = roc_auc_score(gold, probs, multi_class="ovr")
    except Exception:
        auc = 0.0
    return {"acc": accuracy_score(gold, preds), "prec": precision_score(gold, preds, average="weighted", zero_division=0),
            "rec": recall_score(gold, preds, average="weighted", zero_division=0),
            "f1": f1_score(gold, preds, average="weighted", zero_division=0), "auc": auc}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pretrain-epochs", type=int, default=20)
    ap.add_argument("--finetune-epochs", type=int, default=50)
    args = ap.parse_args()
    dg = load_windows(["ml_model/dgraph_windows/*.json"])
    sim = load_windows(["graph_model/snapshots/window_*.json"])
    ps = load_windows(["ml_model/paysim_windows/*.json"])
    print(f"loaded: dgraph={len(dg)} sim={len(sim)} paysim={len(ps)}")
    print("== pre-train on DGraph ==")
    model, _, va_dg, _ = train_torch(dg, args.pretrain_epochs, save="pretrained.pt")
    print("== fine-tune on sim+paysim ==")
    combo = sim + ps
    model2, tr, va, best = train_torch(combo, args.finetune_epochs, save="model.pt")
    m_torch = eval_split(model2, va)
    print("T-GCN+GAT:", m_torch)
    # RF baseline on flattened features
    import numpy as np
    X = np.array([d["X"].flatten().numpy() for d in combo])
    y = np.array([d["y"].item() for d in combo])
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    rf = RandomForestClassifier(n_estimators=100, random_state=42).fit(Xtr, ytr)
    yp = rf.predict(Xte)
    m_rf = {"acc": accuracy_score(yte, yp), "f1": f1_score(yte, yp, average="weighted", zero_division=0)}
    print("RF:", m_rf)
    json.dump({"tgcn_gat": m_torch, "rf": m_rf}, open(OUT / "metrics.json", "w"), indent=2)
    # risk scores from last sim HIGH window (or last window)
    highs = [d for d in sim if d["label"] == "HIGH"] or sim[-1:]
    b = highs[-1]
    import torch.nn.functional as F
    model2.eval()
    with torch.no_grad():
        out, _ = model2(b["X"], b["edge_index"], b["edge_weight"], None)
        probs = F.softmax(out, 1).squeeze(0)
    # node risk: 0.6*HIGH_prob + 0.4*anomaly (attention-weighted propagation approx)
    import json as js
    nodes = js.load(open(sorted([str(p) for p in (BASE / "graph_model" / "snapshots").glob("window_*.json")])[-1]))["nodes"]
    anoms = b["X"][:, -1].tolist()
    hp = float(probs[2])
    risks = [{"node": n, "risk": round(0.6 * hp + 0.4 * a, 4),
              "level": "HIGH" if 0.6 * hp + 0.4 * a > 0.6 else ("MEDIUM" if 0.6 * hp + 0.4 * a > 0.3 else "LOW")}
             for n, a in zip(nodes, anoms)]
    risks.sort(key=lambda x: -x["risk"])
    json.dump(risks, open(BASE / "ml_model" / "risk_scores.json", "w"), indent=2)
    print(f"saved model.pt, metrics.json, risk_scores.json (top3={[r['node'] for r in risks[:3]]})")


if __name__ == "__main__":
    main()
