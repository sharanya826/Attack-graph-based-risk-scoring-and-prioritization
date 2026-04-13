import json
import pickle
import networkx as nx

with open("attack_graph.pkl", "rb") as f:
    G = pickle.load(f)

pagerank       = nx.pagerank(G)
betweenness    = nx.betweenness_centrality(G)
degree_cent    = nx.degree_centrality(G)

features = {}
for node in G.nodes():
    features[node] = {
        "pagerank":            round(pagerank[node], 6),
        "betweenness":         round(betweenness[node], 6),
        "degree_centrality":   round(degree_cent[node], 6),
        "in_degree":           G.in_degree(node),
        "out_degree":          G.out_degree(node),
    }
    print(f"{node:30s} PR={features[node]['pagerank']:.4f}  "
          f"BC={features[node]['betweenness']:.4f}  "
          f"in={features[node]['in_degree']}  out={features[node]['out_degree']}")

with open("graph_features.json", "w") as f:
    json.dump(features, f, indent=2)

print("\nSaved graph_features.json")