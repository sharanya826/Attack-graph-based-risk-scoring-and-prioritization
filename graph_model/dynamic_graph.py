
import pickle
from pathlib import Path

import networkx as nx


BASE_DIR = Path(__file__).resolve().parent.parent

ATTACK_GRAPH_FILE = (
    BASE_DIR / "graph_model" / "attack_graph.pkl"
)


def load_base_graph():
    """
    Load the original static attack graph.
    """

    with open(
        ATTACK_GRAPH_FILE,
        "rb"
    ) as file:

        return pickle.load(file)


def build_dynamic_graph(snapshot):
    """
    Build the current graph by combining:

    static base graph
    +
    observed Redis edges
    """

    G = load_base_graph().copy()

    # Give every static edge a default weight.
    for source, target in G.edges():

        G[source][target]["weight"] = 1.0

        G[source][target]["type"] = "base"

    observed_edges = snapshot.get(
        "edges",
        {}
    )

    for edge_data in observed_edges.values():

        source = edge_data.get("source")
        target = edge_data.get("target")

        if not source or not target:
            continue

        count = float(
            edge_data.get(
                "count",
                0
            )
        )

        edge_type = edge_data.get(
            "type",
            "base"
        )

        weight = max(
            count,
            1.0
        )

        if source not in G:

            G.add_node(source)

        if target not in G:

            G.add_node(target)

        if G.has_edge(
            source,
            target
        ):

            G[source][target][
                "weight"
            ] = weight

            G[source][target][
                "type"
            ] = edge_type

        else:

            G.add_edge(
                source,
                target,
                weight=weight,
                type=edge_type
            )

    return G


if __name__ == "__main__":

    import json

    SNAPSHOT_FILE = (
        BASE_DIR
        / "feature_store"
        / "snapshots"
        / "latest.json"
    )

    with open(
        SNAPSHOT_FILE,
        "r"
    ) as file:

        snapshot = json.load(file)

    G = build_dynamic_graph(
        snapshot
    )

    print(
        "Dynamic graph created"
    )

    print(
        f"Nodes: {G.number_of_nodes()}"
    )

    print(
        f"Edges: {G.number_of_edges()}"
    )

    print(
        "\nDynamic attack edges:"
    )

    for source, target, data in G.edges(
        data=True
    ):

        if data.get(
            "type"
        ) == "dynamic_attack":

            print(
                f"{source} -> {target} | "
                f"weight={data.get('weight')}"
            )
