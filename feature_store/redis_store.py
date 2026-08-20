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


def get_node_state(node):
    key = f"feature:node:{node}"

    return redis_client.hgetall(key)


def get_all_node_states():
    nodes = [
        "api-server",
        "auth-service",
        "payment-service"
    ]

    return {
        node: get_node_state(node)
        for node in nodes
    }

