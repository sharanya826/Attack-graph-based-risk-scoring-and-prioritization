from flask import Flask, jsonify, request
import os

app = Flask(__name__)

# Vulnerability: weak secret key
app.config['SECRET_KEY'] = 'weakauthkey456'

# Fake user database (hardcoded - vulnerability)
USERS = {
    "admin":   "admin123",
    "user1":   "password",
    "finance": "finance123"
}

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "service": "auth-service"})

"""@app.route('/verify', methods=['POST'])
def verify():
    data     = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Vulnerability: plain text password comparison, no hashing
    if USERS.get(username) == password:
        # Vulnerability: token is just username + hardcoded string
        token = f"{username}-token-abc123"
        return jsonify({
            "status":       "success",
            "token":        token,
            "role":         "admin" if username == "admin" else "user",
            "message":      "Login successful"
        }), 200

    return jsonify({"status": "failed", "message": "Invalid credentials"}), 401
"""
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'GET':
        return "Use POST to login"

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if USERS.get(username) == password:
        token = f"{username}-token-abc123"
        return jsonify({
            "status": "success",
            "token": token,
            "role": "admin" if username == "admin" else "user"
        }), 200

    return jsonify({"status": "failed"}), 401

@app.route('/validate-token', methods=['POST'])
def validate_token():
    data  = request.get_json()
    token = data.get('token', '')

    # Vulnerability: anyone who knows the pattern can forge a token
    if '-token-abc123' in token:
        username = token.replace('-token-abc123', '')
        return jsonify({
            "valid":    True,
            "username": username,
            "role":     "admin" if username == "admin" else "user"
        }), 200

    return jsonify({"valid": False}), 401

if __name__ == '__main__':
    # Vulnerability: debug=True, exposed on all interfaces
    app.run(host='0.0.0.0', port=5001, debug=True)