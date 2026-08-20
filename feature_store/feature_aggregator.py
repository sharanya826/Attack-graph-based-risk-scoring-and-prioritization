import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

ASSETS_FILE = BASE_DIR / "asset_discovery" / "assets.json"
GRAPH_FEATURES_FILE = BASE_DIR / "graph_model" / "graph_features.json"
LATEST_SNAPSHOT_FILE = (
    BASE_DIR / "feature_store" / "snapshots" / "latest.json"
)


# IMPORTANT:
# This is the canonical node order from attack_graph.pkl.
NODE_ORDER = [
    "api-server",
    "auth-service",
    "payment-service",
    "worker-service",
    "user-docs",
    "kyc-files",
    "audit-logs",
    "backups",
    "db-access-role",
    "lambda-exec-role",
    "readonly-role",
    "payment-role",
    "admin-role",
    "payment-lambda",
    "kyc-lambda",
    "notify-lambda",
    "fintech-api-gateway",
    "tx-queue",
    "notify-queue",
    "mysql-db",
    "redis-cache",
    "waf-firewall",
    "load-balancer",
    "cloudtrail-logs",
    "kms-keys",
]


EXPOSURE_MAP = {
    "public": 1.0,
    "internal": 0.5,
    "private": 0.0,
}


SENSITIVITY_MAP = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
}


DYNAMIC_FEATURES = [
    "request_count",
    "success_count",
    "failed_request_count",
    "error_count",
    "failed_login_count",
    "avg_latency_ms",
]


GRAPH_FEATURES = [
    "pagerank",
    "betweenness",
    "degree_centrality",
    "in_degree",
    "out_degree",
]


SECURITY_FEATURES = [
    "cvss",
    "exposure",
    "sensitivity",
]


FEATURE_ORDER = (
    DYNAMIC_FEATURES
    + GRAPH_FEATURES
    + SECURITY_FEATURES
)


def load_json(path):
    with open(path, "r") as file:
        return json.load(file)


def build_asset_lookup():
    assets = load_json(ASSETS_FILE)

    lookup = {}

    for asset in assets:
        name = asset["name"]

        # Later entries override earlier entries.
        lookup[name] = asset

    return lookup


def get_dynamic_features(snapshot, node):
    node_state = snapshot.get("nodes", {}).get(node, {})

    return [
        float(node_state.get("request_count", 0)),
        float(node_state.get("success_count", 0)),
        float(node_state.get("failed_request_count", 0)),
        float(node_state.get("error_count", 0)),
        float(node_state.get("failed_login_count", 0)),
        float(node_state.get("avg_latency_ms", 0)),
    ]


def get_graph_features(graph_features, node):
    node_features = graph_features.get(node, {})

    return [
        float(node_features.get("pagerank", 0)),
        float(node_features.get("betweenness", 0)),
        float(node_features.get("degree_centrality", 0)),
        float(node_features.get("in_degree", 0)),
        float(node_features.get("out_degree", 0)),
    ]


def get_security_features(asset_lookup, node):
    asset = asset_lookup.get(node, {})

    cvss = float(asset.get("cvss", 0))
    exposure = asset.get("exposure", "private")
    sensitivity = asset.get("sensitivity", "MEDIUM")

    return [
        cvss / 10.0,
        EXPOSURE_MAP.get(exposure, 0.0),
        SENSITIVITY_MAP.get(sensitivity, 0.0),
    ]


def aggregate_features():
    graph_features = load_json(GRAPH_FEATURES_FILE)
    snapshot = load_json(LATEST_SNAPSHOT_FILE)
    asset_lookup = build_asset_lookup()

    feature_matrix = []

    for node in NODE_ORDER:

        dynamic = get_dynamic_features(
            snapshot,
            node
        )

        graph = get_graph_features(
            graph_features,
            node
        )

        security = get_security_features(
            asset_lookup,
            node
        )

        node_vector = (
            dynamic
            + graph
            + security
        )

        feature_matrix.append(node_vector)

    return {
        "timestamp": snapshot["timestamp"],
        "nodes": NODE_ORDER,
        "feature_names": FEATURE_ORDER,
        "feature_matrix": feature_matrix,
    }


if __name__ == "__main__":
    result = aggregate_features()

    print(
        json.dumps(
            result,
            indent=2
        )
    )