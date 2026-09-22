"""Traffic simulator: normal fintech traffic + windowed attacks.
Windows: 5=recon 150 req, 8=brute 80x401, 9=exploit forged-token (auth-service->admin-role), 10=exfil 80 req.
Run: python simulator.py [--window-sec 30]
"""
import argparse
import random
import time
import requests

API = "http://localhost:5000"
AUTH = "http://localhost:5001"
PAY = "http://localhost:5002"

ATTACK_SCHEDULE = {5: "recon", 8: "brute", 9: "exploit", 10: "exfil"}


def _get(url, timeout=5):
    try:
        return requests.get(url, timeout=timeout)
    except Exception as e:
        print(f"GET {url} failed: {e}")
        return None


def _post(url, payload, timeout=5):
    try:
        return requests.post(url, json=payload, timeout=timeout)
    except Exception as e:
        print(f"POST {url} failed: {e}")
        return None


def normal_login():
    _post(f"{API}/api/login", {"username": "admin", "password": "admin123"})


def normal_pay():
    _post(f"{API}/api/pay", {"amount": 100, "to_account": "MERCHANT-001", "from_account": "ACC-98234-XYZ"})


def normal_data():
    _get(f"{API}/api/data")


def normal_health():
    _get(f"{API}/health")


def normal_burst():
    for fn in [normal_login, normal_data, normal_pay, normal_health]:
        if random.random() < 0.7:
            fn()
            time.sleep(random.uniform(0.5, 2.0))


def attack_recon():
    print("[ATTACK] recon: 150 rapid GETs")
    for _ in range(150):
        _get(f"{API}/api/data")
        _get(f"{API}/api/user-docs")
        time.sleep(0.1)


def attack_brute():
    print("[ATTACK] brute: 80 wrong passwords -> 401s")
    for i in range(80):
        _post(f"{API}/api/login", {"username": "admin", "password": f"wrong-{i}"})
        time.sleep(0.05)


def attack_exploit():
    print("[ATTACK] exploit: forged token -> auth-service->admin-role edge")
    for tok in ["admin-token-abc123", "finance-token-abc123"]:
        _post(f"{AUTH}/validate-token", {"token": tok})
        time.sleep(0.2)
    _post(f"{API}/api/pay", {"amount": 50000, "to_account": "ATTACKER", "from_account": "ACC-98234-XYZ"})


def attack_exfil():
    print("[ATTACK] exfil: 80 doc/txn reads")
    for _ in range(30):
        _get(f"{API}/api/user-docs")
        time.sleep(0.1)
    for _ in range(30):
        _get(f"{PAY}/transactions")
        time.sleep(0.1)
    for _ in range(20):
        _get(f"{API}/api/data")
        time.sleep(0.1)


ATTACKS = {"recon": attack_recon, "brute": attack_brute, "exploit": attack_exploit, "exfil": attack_exfil}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window-sec", type=int, default=30)
    args = ap.parse_args()
    window = 0
    print(f"Simulator started. Schedule={ATTACK_SCHEDULE}, window_sec={args.window_sec}")
    while True:
        print(f"--- window {window} ---")
        if window in ATTACK_SCHEDULE:
            ATTACKS[ATTACK_SCHEDULE[window]]()
        normal_burst()
        window = (window + 1) % 13
        time.sleep(args.window_sec)


if __name__ == "__main__":
    main()
