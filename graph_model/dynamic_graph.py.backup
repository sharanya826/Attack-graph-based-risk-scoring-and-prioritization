import pickle
import networkx as nx


def load_base_graph():
    """
    Load the original static attack graph.
    """

    with open("graph_model/attack_graph.pkl", "rb") as file:
        base_graph = pickle.load(file)

    return base_graph


def build_dynamic_graph(snapshot):
    """
    Build the graph for the current snapshot.

    Starts with the static base graph and applies
    the observed Redis edge state from the snapshot.
    """

    # Copy the static graph so the original graph
    # is never permanently modified.
    G = load_base_graph().copy()

    # Default weight for every static edge.
    for source, target in G.edges():
        G[source][target]["weight"] = 1.0

    # Read observed edges from the snapshot.
    observed_edges = snapshot.get("edges", {})

    for edge_data in observed_edges.values():

        source = edge_data["source"]
        target = edge_data["target"]

        count = float(
            edge_data.get("count", 0)
        )

        edge_type = edge_data.get(
            "type",
            "base"
        )

        # Convert traffic count into a usable weight.
        weight = max(count, 1.0)

        # Add nodes if a dynamic edge references
        # nodes not already present.
        if source not in G:
            G.add_node(source)

        if target not in G:
            G.add_node(target)

        if G.has_edge(source, target):

            # Existing base edge:
            # update its weight using observed traffic.
            G[source][target]["weight"] = weight
            G[source][target]["type"] = edge_type

        else:

            # New attack edge:
            # this genuinely changes graph topology.
            G.add_edge(
                source,
                target,
                weight=weight,
                type=edge_type,
            )

    return G


if __name__ == "__main__":

    import json

    with open(
        "feature_store/snapshots/latest.json"
    ) as file:
        snapshot = json.load(file)

    G = build_dynamic_graph(snapshot)

    print("Dynamic graph created")
    print(f"Nodes: {G.number_of_nodes()}")
    print(f"Edges: {G.number_of_edges()}")

    print("\nEdges involving dynamic attack activity:")

    for source, target, data in G.edges(data=True):

        if data.get("type") == "dynamic_attack":

            print(
                f"{source} -> {target} | "
                f"weight={data.get('weight')}"
            )