from flask import Flask, jsonify, request
import requests
import os


app = Flask(__name__)

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