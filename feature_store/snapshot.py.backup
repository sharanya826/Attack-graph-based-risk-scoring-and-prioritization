from datetime import datetime, timezone
from pathlib import Path
import json
import time

from feature_store.redis_store import (
    get_all_node_states,
    get_all_edge_states,
)


# Directory where snapshots will be stored
SNAPSHOT_DIR = Path(__file__).resolve().parent / "snapshots"
HISTORY_DIR = SNAPSHOT_DIR / "history"


def create_snapshot():
    """
    Capture the current state of all nodes and edges
    from Redis at a single point in time.
    """

    snapshot = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nodes": get_all_node_states(),
        "edges": get_all_edge_states(),
    }

    return snapshot


def save_snapshot(snapshot):
    """
    Save the snapshot as:
    1. latest.json
    2. a timestamped historical JSON file
    """

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    # Save latest snapshot
    latest_file = SNAPSHOT_DIR / "latest.json"

    with open(latest_file, "w") as file:
        json.dump(snapshot, file, indent=2)

    # Create a filesystem-safe timestamp
    timestamp = datetime.fromisoformat(
        snapshot["timestamp"]
    ).strftime("%Y%m%d_%H%M%S_%f")

    history_file = HISTORY_DIR / f"snapshot_{timestamp}.json"

    with open(history_file, "w") as file:
        json.dump(snapshot, file, indent=2)

    return latest_file, history_file


def capture_and_save_snapshot():
    """
    Create a snapshot from Redis and save it.
    """

    snapshot = create_snapshot()
    latest_file, history_file = save_snapshot(snapshot)

    print(
        f"Snapshot created at {snapshot['timestamp']}"
    )
    print(f"Latest: {latest_file}")
    print(f"History: {history_file}")

    return snapshot


def run_periodic_snapshot(interval_seconds=5):
    """
    Continuously capture and save Redis snapshots
    at the specified interval.
    """

    print(
        f"Starting periodic snapshot every "
        f"{interval_seconds} seconds..."
    )

    try:
        while True:
            capture_and_save_snapshot()
            time.sleep(interval_seconds)

    except KeyboardInterrupt:
        print("\nPeriodic snapshot stopped.")


if __name__ == "__main__":
    run_periodic_snapshot()