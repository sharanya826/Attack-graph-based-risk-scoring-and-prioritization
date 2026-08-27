import json
import sys

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

ASSETS_FILE = (
    BASE_DIR
    / "asset_discovery"
    / "assets.json"
)

LATEST_SNAPSHOT_FILE = (
    BASE_DIR
    / "feature_store"
    / "snapshots"
    / "latest.json"
)


# Allow imports from the project root.
if str(BASE_DIR) not in sys.path:
    sys.path.insert(
        0,
        str(BASE_DIR)
    )


from graph_model.dynamic_graph_features import (
    extract_dynamic_graph_features,
)


# IMPORTANT:
# Canonical node order from attack_graph.pkl.
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


PRIVILEGE_MAP = {
    "limited": 0.25,
    "storage": 0.50,
    "compute": 0.60,
    "gateway": 0.70,
    "api": 0.75,
    "auth": 0.80,
    "database": 0.90,
    "payment": 0.90,
    "admin": 1.00,
    "infra": 0.50,
}


ASSET_TYPE_MAP = {
    "DockerService": 1.0,
    "EC2": 2.0,
    "S3Bucket": 3.0,
    "IAMRole": 4.0,
    "Lambda": 5.0,
    "APIGateway": 6.0,
    "SQS": 7.0,
    "ElastiCache": 8.0,
    "WAF": 9.0,
    "ALB": 10.0,
    "CloudTrail": 11.0,
    "KMS": 12.0,
}


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
    "privilege",
    "patch_status",
    "auth_strength",
    "asset_type",
]


FEATURE_ORDER = (
    SECURITY_FEATURES
    + GRAPH_FEATURES
    + ["anomaly_score"]
)


def load_json(path):
    """
    Load a JSON file.
    """

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def build_asset_lookup():
    """
    Build a lookup dictionary:

    node_name -> asset metadata

    Later entries override earlier entries.
    """

    assets = load_json(
        ASSETS_FILE
    )

    lookup = {}

    for asset in assets:

        name = asset["name"]

        lookup[name] = asset

    return lookup


def get_graph_features(
    graph_features,
    node
):
    """
    Return the five dynamic graph features
    for one node.
    """

    node_features = graph_features.get(
        node,
        {}
    )

    return [
        float(
            node_features.get(
                "pagerank",
                0
            )
        ),

        float(
            node_features.get(
                "betweenness",
                0
            )
        ),

        float(
            node_features.get(
                "degree_centrality",
                0
            )
        ),

        float(
            node_features.get(
                "in_degree",
                0
            )
        ),

        float(
            node_features.get(
                "out_degree",
                0
            )
        ),
    ]


def get_anomaly_score(
    snapshot,
    node
):
    """
    Calculate anomaly score from the
    current Redis node state stored
    in the snapshot.
    """

    node_state = (
        snapshot
        .get("nodes", {})
        .get(node, {})
    )

    request_count = float(
        node_state.get(
            "request_count",
            0
        )
    )

    failed_request_count = float(
        node_state.get(
            "failed_request_count",
            0
        )
    )

    error_count = float(
        node_state.get(
            "error_count",
            0
        )
    )

    avg_latency_ms = float(
        node_state.get(
            "avg_latency_ms",
            0
        )
    )

    if request_count == 0:
        return 0.0

    failure_ratio = (
        failed_request_count
        / request_count
    )

    error_ratio = (
        error_count
        / request_count
    )

    latency_score = min(
        avg_latency_ms / 5000.0,
        1.0
    )

    anomaly_score = (
        0.4 * failure_ratio
        + 0.4 * error_ratio
        + 0.2 * latency_score
    )

    return round(
        min(
            anomaly_score,
            1.0
        ),
        4
    )


def get_security_features(
    asset_lookup,
    node
):
    """
    Return the six static/security
    features for one node.
    """

    asset = asset_lookup.get(
        node,
        {}
    )

    cvss = (
        float(
            asset.get(
                "cvss",
                0
            )
        )
        / 10.0
    )

    exposure = EXPOSURE_MAP.get(
        asset.get(
            "exposure",
            "private"
        ),
        0.0
    )

    privilege = PRIVILEGE_MAP.get(
        asset.get(
            "privilege",
            "limited"
        ),
        0.0
    )

    # Currently fixed because these
    # values are not dynamically
    # provided by assets.json.
    patch_status = 0.0

    auth_strength = 0.0

    asset_type = ASSET_TYPE_MAP.get(
        asset.get(
            "type",
            ""
        ),
        0.0
    )

    return [
        cvss,
        exposure,
        privilege,
        patch_status,
        auth_strength,
        asset_type,
    ]


def aggregate_features():
    snapshot = load_json(LATEST_SNAPSHOT_FILE)

    graph_features = extract_dynamic_graph_features(
        snapshot
    )

    asset_lookup = build_asset_lookup()

    feature_matrix = []

    for node in NODE_ORDER:
        security = get_security_features(
            asset_lookup,
            node
        )

        graph = get_graph_features(
            graph_features,
            node
        )

        anomaly_score = get_anomaly_score(
            snapshot,
            node
        )

        node_vector = (
            security
            + graph
            + [anomaly_score]
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
    