"""T-GCN + GAT (pure torch, no torch_geometric). Input dim 12 (11+anomaly)."""
import torch
import torch.nn as nn
import torch.nn.functional as F


def gcn_norm(edge_index, edge_weight, n):
    row, col = edge_index
    deg = torch.zeros(n)
    deg.index_add_(0, row, edge_weight)
    deg_inv = (deg + 1e-8).pow(-0.5)
    return deg_inv[row] * edge_weight * deg_inv[col]


class GCNLayer(nn.Module):
    def __init__(self, inp, out):
        super().__init__()
        self.lin = nn.Linear(inp, out)

    def forward(self, X, edge_index, edge_weight):
        n = X.size(0)
        w = gcn_norm(edge_index, edge_weight, n)
        row, col = edge_index
        agg = torch.zeros_like(X)
        agg.index_add_(0, row, X[col] * w.unsqueeze(1))
        return self.lin(X + agg)


class GATLayer(nn.Module):
    def __init__(self, inp, head_dim=16, heads=4):
        super().__init__()
        self.heads = heads
        self.head_dim = head_dim
        self.W = nn.Linear(inp, head_dim * heads, bias=False)
        self.a = nn.Parameter(torch.randn(heads, 2 * head_dim))

    def forward(self, X):
        n = X.size(0)
        H = self.W(X).view(n, self.heads, self.head_dim)  # [N,H,D]
        # full attention over 25 nodes (small graph, dense is fine)
        Hi = H.unsqueeze(1).expand(n, n, self.heads, self.head_dim)
        Hj = H.unsqueeze(0).expand(n, n, self.heads, self.head_dim)
        cat = torch.cat([Hi, Hj], dim=-1)  # [N,N,H,2D]
        e = (cat * self.a.view(1, 1, self.heads, -1)).sum(-1)  # [N,N,H]
        alpha = F.softmax(F.leaky_relu(e, 0.2), dim=1)
        out = (alpha.unsqueeze(-1) * Hj).sum(1)  # [N,H,D]
        return out.reshape(n, self.heads * self.head_dim)


class TGCN_GAT(nn.Module):
    def __init__(self, in_dim=12, hid=64, classes=3):
        super().__init__()
        self.gcn1 = GCNLayer(in_dim, hid)
        self.gru = nn.GRUCell(hid, hid)
        self.gcn2 = GCNLayer(hid, hid)
        self.gat = GATLayer(hid, 16, 4)  # 64 out
        self.mlp = nn.Sequential(nn.Linear(hid, 32), nn.ReLU(), nn.Linear(32, classes))

    def forward(self, X, edge_index, edge_weight, h=None):
        n = X.size(0)
        if h is None:
            h = torch.zeros(n, 64, device=X.device)
        x1 = F.relu(self.gcn1(X, edge_index, edge_weight))
        h = self.gru(x1, h)
        x2 = F.relu(self.gcn2(h, edge_index, edge_weight))
        att = self.gat(x2)
        fused = x2 + att  # residual (x1 shape matches too, use x2)
        graph = fused.mean(0)  # graph-level pooling for window label
        return self.mlp(graph).unsqueeze(0), h  # [1,3]
