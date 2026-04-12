import json
import pickle
import networkx as nx

with open("attack_graph.pkl", "rb") as f:
    G = pickle.load(f)

# Entry points = publicly exposed nodes
entry_points = ["fintech-api-gateway", "waf-firewall", "load-balancer"]

# High-value targets
target_nodes = ["mysql-db", "kyc-files", "kms-keys", "admin-role"]

all_paths = []

for entry in entry_points:
    for target in target_nodes:
        if entry not in G.nodes() or target not in G.nodes():
            continue
        
        # All simple paths (BFS), max 7 hops
        try:
            simple_paths = list(nx.all_simple_paths(G, source=entry, target=target, cutoff=7))
            for path in simple_paths:
                all_paths.append({
                    "entry": entry,
                    "target": target,
                    "path": path,
                    "hops": len(path) - 1,
                    "path_str": " -> ".join(path)
                })
        except nx.NetworkXNoPath:
            pass
        
        # Shortest path
        try:
            shortest = nx.shortest_path(G, source=entry, target=target)
            print(f"Shortest {entry} -> {target}: {' -> '.join(shortest)}")
        except nx.NetworkXNoPath:
            print(f"No path: {entry} -> {target}")

print(f"\nTotal paths found: {len(all_paths)}")

with open("attack_paths.json", "w") as f:
    json.dump(all_paths, f, indent=2)

print("Saved attack_paths.json")