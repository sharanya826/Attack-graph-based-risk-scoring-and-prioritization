import json

import networkx as nx

from graph_model.dynamic_graph import build_dynamic_graph


GRAPH_FEATURES = [
    "pagerank",
    "betweenness",
    "degree_centrality",
    "in_degree",
    "out_degree",
]


def extract_dynamic_graph_features(snapshot):
    """
    Build the current dynamic graph Gt from the snapshot
    and calculate graph features for every node.
    """

    G = build_dynamic_graph(snapshot)

    # -----------------------------
    # PageRank
    # -----------------------------
    pagerank = nx.pagerank(
        G,
        weight="weight"
    )

    # -----------------------------
    # Betweenness centrality
    #
    # distance is the inverse of
    # edge weight because higher
    # activity should represent a
    # stronger/closer connection.
    # -----------------------------
    for source, target, data in G.edges(data=True):

        weight = float(
            data.get("weight", 1.0)
        )

        data["distance"] = 1.0 / max(
            weight,
            1.0
        )

    betweenness = nx.betweenness_centrality(
        G,
        weight="distance",
        normalized=True
    )

    # -----------------------------
    # Degree centrality
    # -----------------------------
    degree_centrality = nx.degree_centrality(G)

    # -----------------------------
    # In-degree
    # -----------------------------
    in_degree = dict(
        G.in_degree()
    )

    # -----------------------------
    # Out-degree
    # -----------------------------
    out_degree = dict(
        G.out_degree()
    )

    # -----------------------------
    # Combine all features
    # -----------------------------
    features = {}

    for node in G.nodes():

        features[node] = {

            "pagerank": round(
                float(pagerank.get(node, 0)),
                6
            ),

            "betweenness": round(
                float(betweenness.get(node, 0)),
                6
            ),

            "degree_centrality": round(
                float(
                    degree_centrality.get(node, 0)
                ),
                6
            ),

            "in_degree": float(
                in_degree.get(node, 0)
            ),

            "out_degree": float(
                out_degree.get(node, 0)
            ),
        }

    return features


if __name__ == "__main__":

    with open(
        "feature_store/snapshots/latest.json",
        "r"
    ) as file:

        snapshot = json.load(file)

    features = extract_dynamic_graph_features(
        snapshot
    )

    print(
        json.dumps(
            features,
            indent=2
        )
    )