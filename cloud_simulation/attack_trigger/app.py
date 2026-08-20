import sys
from pathlib import Path

# Add project root to Python path so feature_store can be imported
sys.path.append(
    str(Path(__file__).resolve().parents[2])
)

from flask import Flask, jsonify
import requests
import time
from datetime import datetime, timezone

from feature_store.redis_store import record_event


app = Flask(__name__)

API_SERVER_URL = "http://localhost:5000"


def make_event(
    traffic_type,
    endpoint,
    method,
    status_code,
    latency_ms,
    success,
    destination="api-server",
    error=None
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "traffic_type": traffic_type,
        "source": "attack-trigger",
        "destination": destination,
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "latency_ms": latency_ms,
        "success": success
    }

    if error:
        event["error"] = error

    return event


def login():
    start_time = time.perf_counter()

    try:
        response = requests.post(
            f"{API_SERVER_URL}/api/login",
            json={
                "username": "admin",
                "password": "admin123"
            },
            timeout=5
        )

        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        event = make_event(
            traffic_type="normal",
            endpoint="/api/login",
            method="POST",
            status_code=response.status_code,
            latency_ms=latency_ms,
            success=response.ok
        )

        # Store real event in Redis
        record_event(event)

        return event

    except requests.RequestException as error:
        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        event = make_event(
            traffic_type="normal",
            endpoint="/api/login",
            method="POST",
            status_code=503,
            latency_ms=latency_ms,
            success=False,
            error=str(error)
        )

        # Store failed request event in Redis
        record_event(event)

        return event


def data_access():
    start_time = time.perf_counter()

    try:
        response = requests.get(
            f"{API_SERVER_URL}/api/data",
            timeout=5
        )

        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        event = make_event(
            traffic_type="normal",
            endpoint="/api/data",
            method="GET",
            status_code=response.status_code,
            latency_ms=latency_ms,
            success=response.ok
        )

        # Store real event in Redis
        record_event(event)

        return event

    except requests.RequestException as error:
        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        event = make_event(
            traffic_type="normal",
            endpoint="/api/data",
            method="GET",
            status_code=503,
            latency_ms=latency_ms,
            success=False,
            error=str(error)
        )

        # Store failed request event in Redis
        record_event(event)

        return event


def payment():
    start_time = time.perf_counter()

    try:
        response = requests.post(
            f"{API_SERVER_URL}/api/pay",
            json={
                "amount": 100,
                "to_account": "MERCHANT-001",
                "from_account": "ACC-98234-XYZ"
            },
            timeout=5
        )

        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        event = make_event(
            traffic_type="normal",
            endpoint="/api/pay",
            method="POST",
            status_code=response.status_code,
            latency_ms=latency_ms,
            success=response.ok
        )

        # Store real event in Redis
        record_event(event)

        return event

    except requests.RequestException as error:
        latency_ms = round(
            (time.perf_counter() - start_time) * 1000,
            2
        )

        event = make_event(
            traffic_type="normal",
            endpoint="/api/pay",
            method="POST",
            status_code=503,
            latency_ms=latency_ms,
            success=False,
            error=str(error)
        )

        # Store failed request event in Redis
        record_event(event)

        return event


@app.get("/health")
def health():
    return jsonify({
        "service": "attack-trigger",
        "status": "healthy"
    })


@app.post("/traffic/normal")
def normal_traffic():
    events = []

    # 1. Normal login
    login_event = login()
    events.append(login_event)

    # 2. Normal data access
    data_event = data_access()
    events.append(data_event)

    # 3. Normal payment
    payment_event = payment()
    events.append(payment_event)

    return jsonify({
        "scenario": "normal",
        "event_count": len(events),
        "events": events
    }), 200


@app.post("/traffic/normal/data")
def normal_data_access():
    return jsonify(data_access()), 200


@app.post("/traffic/normal/payment")
def normal_payment():
    return jsonify(payment()), 200


@app.post("/traffic/attack/bruteforce")
def brute_force_attack():
    events = []

    attempts = [
        {
            "username": "admin",
            "password": "wrong-password-1"
        },
        {
            "username": "admin",
            "password": "wrong-password-2"
        },
        {
            "username": "admin",
            "password": "wrong-password-3"
        },
        {
            "username": "admin",
            "password": "wrong-password-4"
        },
        {
            "username": "admin",
            "password": "wrong-password-5"
        }
    ]

    for attempt in attempts:
        start_time = time.perf_counter()

        try:
            response = requests.post(
                f"{API_SERVER_URL}/api/login",
                json=attempt,
                timeout=5
            )

            latency_ms = round(
                (time.perf_counter() - start_time) * 1000,
                2
            )

            event = make_event(
                traffic_type="attack_bruteforce",
                endpoint="/api/login",
                method="POST",
                status_code=response.status_code,
                latency_ms=latency_ms,
                success=response.ok
            )

        except requests.RequestException as error:
            latency_ms = round(
                (time.perf_counter() - start_time) * 1000,
                2
            )

            event = make_event(
                traffic_type="attack_bruteforce",
                endpoint="/api/login",
                method="POST",
                status_code=503,
                latency_ms=latency_ms,
                success=False,
                error=str(error)
            )

        print(event)

        # Store real attack event in Redis
        record_event(event)

        events.append(event)

        # Controlled delay between brute-force attempts
        time.sleep(0.5)

    return jsonify({
        "scenario": "bruteforce",
        "attempt_count": len(events),
        "events": events
    }), 200


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5003,
        debug=True
    )