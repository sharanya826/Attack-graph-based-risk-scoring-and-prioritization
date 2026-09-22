from flask import Flask, jsonify, request, g
import requests
import os
import json
from datetime import datetime, timezone
from pathlib import Path

app = Flask(__name__)

SERVICE_NAME = os.environ.get("SERVICE_NAME", "api-server")
LOG_FILE = Path("/app/logs/requests.jsonl")
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

DEST_MAP = {
    "/api/login": "auth-service",
    "/api/pay": "payment-service",
    "/api/data": "mysql-db",
    "/api/user-docs": "user-docs",
    "/health": "api-server",
}


def write_log(endpoint, status):
    dest = DEST_MAP.get(endpoint, "api-server")
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": SERVICE_NAME,
        "destination": dest,
        "status": status,
        "endpoint": endpoint,
    }
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


@app.after_request
def after_log(response):
    try:
        write_log(request.path, response.status_code)
    except Exception:
        pass
    return response

# Vulnerability: hardcoded secret key (weak)
app.config['SECRET_KEY'] = 'supersecretkey123'

# Vulnerability: debug mode ON — exposes full error stack to anyone
app.run if False else None

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "api-server"})

@app.route('/api/data')
def get_data():
    # Returns fake sensitive fintech data
    return jsonify({
        "status": "ok",
        "data": {
            "account_number": "ACC-98234-XYZ",
            "balance": 52000.75,
            "transactions": [
                {"id": "TX001", "amount": 1500, "type": "credit"},
                {"id": "TX002", "amount": 300,  "type": "debit"},
            ]
        }
    })

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    try:
        # Calls auth-service using container name as hostname
        response = requests.post(
            'http://auth-service:5000/verify',
            json={"username": username, "password": password},
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/pay', methods=['POST'])
def pay():
    data = request.get_json()
    try:
        # Calls payment-service using container name as hostname
        response = requests.post(
            'http://payment-service:5000/pay',
            json=data,
            timeout=5
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/user-docs')
def user_docs():
    # Vulnerability: sensitive docs accessible without authentication
    return jsonify({
        "files": [
            "kyc_john_doe.pdf",
            "bank_statement_march.pdf",
            "aadhar_scan.jpg"
        ],
        "bucket": "fintech-user-docs"
    })

if __name__ == '__main__':
    # Vulnerability: debug=True exposes Werkzeug debugger
    # Vulnerability: host='0.0.0.0' exposes to all network interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)



## api_server/requirements.txt
flask
requests