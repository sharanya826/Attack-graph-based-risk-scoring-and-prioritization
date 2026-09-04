import redis
from datetime import datetime, timezone


REDIS_HOST = "localhost"
REDIS_PORT = 6379


redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    decode_responses=True
)


def record_event(event):
    destination = event["destination"]

    key = f"feature:node:{destination}"

    pipe = redis_client.pipeline()

    # Total requests
    pipe.hincrby(key, "request_count", 1)

    # Success / failure
    if event["success"]:
        pipe.hincrby(key, "success_count", 1)
    else:
        pipe.hincrby(key, "failed_request_count", 1)

    # HTTP errors
    status_code = event["status_code"]

    if status_code >= 400:
        pipe.hincrby(key, "error_count", 1)

    # Failed login
    if (
        event["endpoint"] == "/api/login"
        and not event["success"]
    ):
        pipe.hincrby(key, "failed_login_count", 1)

    # Latency
    pipe.hincrbyfloat(
        key,
        "total_latency_ms",
        event["latency_ms"]
    )

    # Last seen
    pipe.hset(
        key,
        "last_seen",
        event["timestamp"]
    )

    pipe.execute()

    # Calculate current average latency
    state = redis_client.hgetall(key)

    request_count = int(
        state.get("request_count", 0)
    )

    total_latency = float(
        state.get("total_latency_ms", 0)
    )

    avg_latency = (
        total_latency / request_count
        if request_count > 0
        else 0
    )

    redis_client.hset(
        key,
        "avg_latency_ms",
        round(avg_latency, 2)
    )

def record_edge_event(source, target, edge_type="base"):
    """
    Record an observed connection between source and target.
    """

    if edge_type == "dynamic_attack":
        key = f"dynamic_edge:{source}:{target}"
    else:
        key = f"edge:{source}:{target}"

    redis_client.hincrby(
        key,
        "count",
        1
    )

    redis_client.hset(
        key,
        mapping={
            "source": source,
            "target": target,
            "type": edge_type,
            "last_seen": datetime.now(
                timezone.utc
            ).isoformat()
        }
    )

def get_node_state(node):
    key = f"feature:node:{node}"

    return redis_client.hgetall(key)

def get_all_edge_states():
    edges = {}

    for pattern in ["edge:*", "dynamic_edge:*"]:

        for key in redis_client.scan_iter(match=pattern):

            data = redis_client.hgetall(key)

            if not data:
                continue

            source = data.get("source")
            target = data.get("target")

            if not source or not target:
                continue

            edges[f"{source}:{target}"] = {
                "source": source,
                "target": target,
                "count": int(
                    data.get("count", 0)
                ),
                "type": data.get(
                    "type",
                    "base"
                ),
                "last_seen": data.get(
                    "last_seen"
                )
            }

    return edges

def get_all_node_states():
    nodes = [
    # Application layer
    "api-server",
    "auth-service",
    "payment-service",
    "worker-service",

    # Data layer
    "mysql-db",
    "redis-cache",

    # Infrastructure layer
    "fintech-api-gateway",
    "load-balancer",
    "waf-firewall",

    # Queues / serverless
    "tx-queue",
    "notify-queue",
    "payment-lambda",
    "kyc-lambda",
    "notify-lambda",

    # Storage
    "user-docs",
    "kyc-files",
    "audit-logs",
    "backups",
]

    return {
        node: get_node_state(node)
        for node in nodes
    }

