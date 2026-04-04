from flask import Flask, jsonify, request
import os

app = Flask(__name__)

# Vulnerability: DB credentials hardcoded in code
DB_HOST     = os.environ.get('DB_HOST',     'mysql-db')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'weakpassword123')
DB_USER     = os.environ.get('DB_USER',     'root')

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "payment-service"})

@app.route('/pay', methods=['POST'])
def pay():
    data   = request.get_json()
    amount = data.get('amount')
    to     = data.get('to_account')
    frm    = data.get('from_account')

    # Vulnerability: no authentication check before processing payment
    # Vulnerability: no input validation on amount
    if not amount or not to or not frm:
        return jsonify({"status": "error", "message": "Missing fields"}), 400

    # Simulated payment processing (no real DB call needed)
    return jsonify({
        "status":          "success",
        "transaction_id":  "TXN-" + str(hash(f"{frm}{to}{amount}"))[-6:],
        "from_account":    frm,
        "to_account":      to,
        "amount":          amount,
        "message":         "Payment processed"
    }), 200

@app.route('/transactions', methods=['GET'])
def transactions():
    # Vulnerability: returns all transactions without any auth check
    return jsonify({
        "transactions": [
            {"id": "TXN-001", "from": "ACC-111", "to": "ACC-222", "amount": 5000},
            {"id": "TXN-002", "from": "ACC-333", "to": "ACC-444", "amount": 12000},
            {"id": "TXN-003", "from": "ACC-555", "to": "ACC-666", "amount": 800},
        ],
        "db_host":     DB_HOST,
        "db_user":     DB_USER
        # Vulnerability: exposes DB connection info in response
    }), 200

if __name__ == '__main__':
    # Vulnerability: debug=True, exposed on all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)

