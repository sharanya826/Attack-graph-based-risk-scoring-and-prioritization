import json
import pickle
import networkx as nx

with open("../asset_discovery/assets.json") as f:
    raw_assets = json.load(f)

# Deduplicate: if same name appears twice, keep the Docker one (has vuln flags)
# Docker entries come later in the list, so just let last-one-win
seen = {}
for asset in raw_assets:
    seen[asset["name"]] = asset
assets = list(seen.values())

print(f"Unique assets after dedup: {len(assets)}")


# Load your assets
with open("../asset_discovery/assets.json") as f:
    assets = json.load(f)

G = nx.DiGraph()

# Add all assets as nodes with their metadata as attributes
for asset in assets:
    G.add_node(asset["name"], **asset)

# Define directed edges — group them by relationship type
edges = [
    ("waf-firewall",         "load-balancer"),
    ("load-balancer",        "fintech-api-gateway"),   # <-- fix here
    ("load-balancer",        "api-server"),
    ("fintech-api-gateway",  "api-server"),             # <-- fix here
    ("api-server",           "auth-service"),
    ("api-server",           "payment-service"),
    ("api-server",           "mysql-db"),
    ("auth-service",         "mysql-db"),
    ("payment-service",      "mysql-db"),
    ("payment-service",      "redis-cache"),
    ("api-server",           "user-docs"),
    ("api-server",           "audit-logs"),
    ("payment-service",      "kyc-files"),
    ("payment-service",      "backups"),
    ("api-server",           "readonly-role"),
    ("auth-service",         "db-access-role"),
    ("payment-service",      "payment-role"),
    ("db-access-role",       "admin-role"),
    ("payment-role",         "admin-role"),
    ("tx-queue",             "payment-lambda"),
    ("notify-queue",         "notify-lambda"),
    ("kyc-files",            "kyc-lambda"),
    ("lambda-exec-role",     "payment-lambda"),
    ("lambda-exec-role",     "kyc-lambda"),
    ("lambda-exec-role",     "notify-lambda"),
    ("admin-role",           "kms-keys"),
    ("admin-role",           "cloudtrail-logs"),
    ("admin-role",           "mysql-db"),
    ("worker-service",       "tx-queue"),
    ("worker-service",       "notify-queue"),
    ("api-server",           "worker-service"),
]
# Only add edges where both nodes exist in your graph
valid_names = set(G.nodes())
added = 0
for src, dst in edges:
    if src in valid_names and dst in valid_names:
        G.add_edge(src, dst)
        added += 1
    else:
        print(f"  SKIPPED edge {src} -> {dst} (node not found)")

print(f"Nodes: {G.number_of_nodes()}")
print(f"Edges added: {added}")

# Save as pickle
with open("attack_graph.pkl", "wb") as f:
    pickle.dump(G, f)

# Export as JSON for frontend
graph_data = {
    "nodes": [{"id": n, **G.nodes[n]} for n in G.nodes()],
    "edges": [{"from": u, "to": v} for u, v in G.edges()]
}
with open("graph.json", "w") as f:
    json.dump(graph_data, f, indent=2)

print("Saved attack_graph.pkl and graph.json")