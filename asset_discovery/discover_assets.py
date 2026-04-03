import boto3, json

ENDPOINT = "http://localhost:4566"
REGION   = "us-east-1"
KWARGS   = dict(endpoint_url=ENDPOINT, region_name=REGION,
                aws_access_key_id="test", aws_secret_access_key="test")

def client(service): return boto3.client(service, **KWARGS)

assets = []

# ── Security metadata map ─────────────────────────────────────────────────────
# Format: "asset-name" → { cvss, exposure, privilege, notes }
SECURITY_META = {
    # EC2
    "api-server":       {"cvss": 7.5, "exposure": 1, "privilege": 0, "notes": "Public-facing API, open port 80/443"},
    "auth-service":     {"cvss": 9.0, "exposure": 1, "privilege": 1, "notes": "Handles auth tokens, critical exposure"},
    "payment-service":  {"cvss": 8.5, "exposure": 1, "privilege": 1, "notes": "PCI-DSS scope, payment processing"},
    "worker-service":   {"cvss": 4.0, "exposure": 0, "privilege": 0, "notes": "Internal worker, low exposure"},
    # S3
    "user-docs":        {"cvss": 6.5, "exposure": 1, "privilege": 0, "notes": "User PII documents, public bucket risk"},
    "kyc-files":        {"cvss": 8.0, "exposure": 0, "privilege": 0, "notes": "KYC sensitive files, should be private"},
    "audit-logs":       {"cvss": 5.0, "exposure": 0, "privilege": 0, "notes": "Audit trail, internal only"},
    "backups":          {"cvss": 6.0, "exposure": 0, "privilege": 0, "notes": "Backup data, encryption needed"},
    # IAM
    "admin-role":       {"cvss": 9.5, "exposure": 0, "privilege": 1, "notes": "Full admin privileges, high risk"},
    "payment-role":     {"cvss": 8.0, "exposure": 0, "privilege": 1, "notes": "Payment access, elevated privilege"},
    "readonly-role":    {"cvss": 2.0, "exposure": 0, "privilege": 0, "notes": "Read-only, low risk"},
    "db-access-role":   {"cvss": 7.0, "exposure": 0, "privilege": 1, "notes": "Direct DB access, sensitive"},
    "lambda-exec-role": {"cvss": 5.5, "exposure": 0, "privilege": 0, "notes": "Lambda execution role"},
    # Lambda
    "payment-lambda":   {"cvss": 7.5, "exposure": 1, "privilege": 1, "notes": "Processes payments, internet-triggered"},
    "kyc-lambda":       {"cvss": 6.5, "exposure": 0, "privilege": 0, "notes": "KYC verification logic"},
    "notify-lambda":    {"cvss": 3.0, "exposure": 0, "privilege": 0, "notes": "Notification sender, low risk"},
    # SQS
    "tx-queue":         {"cvss": 6.0, "exposure": 0, "privilege": 0, "notes": "Transaction queue, internal"},
    "notify-queue":     {"cvss": 2.5, "exposure": 0, "privilege": 0, "notes": "Notification queue, low risk"},
    # API Gateway
    "fintech-api-gateway": {"cvss": 7.0, "exposure": 1, "privilege": 0, "notes": "Public API entry point"},
    # Manual Nodes
    "mysql-db":         {"cvss": 8.5, "exposure": 0, "privilege": 1, "notes": "Main database, weak password risk"},
    "redis-cache":      {"cvss": 6.0, "exposure": 0, "privilege": 0, "notes": "Cache layer, no auth by default"},
    "waf-firewall":     {"cvss": 4.5, "exposure": 1, "privilege": 0, "notes": "WAF protection layer"},
    # Infra Nodes
    "load-balancer":    {"cvss": 5.0, "exposure": 1, "privilege": 0, "notes": "Public load balancer"},
    "cloudtrail-logs":  {"cvss": 3.5, "exposure": 0, "privilege": 0, "notes": "Audit logging service"},
    "kms-keys":         {"cvss": 7.0, "exposure": 0, "privilege": 1, "notes": "Encryption keys, critical asset"},
}

def meta(name, asset_type):
    """Attach security metadata to an asset."""
    m = SECURITY_META.get(name, {"cvss":5.0,"exposure":0,"privilege":0,"notes":"No metadata"})
    return {
        "name":        name,
        "type":        asset_type,
        "cvss_score":  m["cvss"],
        "exposure":    m["exposure"],
        "privilege":   m["privilege"],
        "notes":       m["notes"],
    }

# ── 1. Discover EC2 Instances ─────────────────────────────────────────────────
def discover_ec2():
    ec2  = client("ec2")
    resp = ec2.describe_instances()
    for r in resp["Reservations"]:
        for inst in r["Instances"]:
            name   = next((t["Value"] for t in inst.get("Tags",[]) if t["Key"]=="Name"), "unknown")
            record = meta(name, "EC2")
            record.update({
                "instance_id": inst["InstanceId"],
                "state":       inst["State"]["Name"],
                "public_ip":   inst.get("PublicIpAddress", "N/A"),
            })
            assets.append(record)
            print(f"  🔍 EC2: {name} | state={record['state']} | ip={record['public_ip']}")

# ── 2. Discover S3 Buckets ────────────────────────────────────────────────────
def discover_s3():
    s3   = client("s3")
    resp = s3.list_buckets()
    for b in resp["Buckets"]:
        name   = b["Name"]
        record = meta(name, "S3")
        record["created"] = str(b["CreationDate"])
        assets.append(record)
        print(f"  🔍 S3: {name}")

# ── 3. Discover IAM Roles ─────────────────────────────────────────────────────
def discover_iam():
    iam  = client("iam")
    resp = iam.list_roles()
    for r in resp["Roles"]:
        name   = r["RoleName"]
        record = meta(name, "IAM")
        record["arn"] = r["Arn"]
        assets.append(record)
        print(f"  🔍 IAM: {name}")

# ── 4. Discover Lambda Functions ──────────────────────────────────────────────
def discover_lambda():
    lam  = client("lambda")
    resp = lam.list_functions()
    for fn in resp["Functions"]:
        name   = fn["FunctionName"]
        record = meta(name, "Lambda")
        record["arn"]     = fn["FunctionArn"]
        record["runtime"] = fn["Runtime"]
        assets.append(record)
        print(f"  🔍 Lambda: {name}")

# ── 5. Discover SQS Queues ────────────────────────────────────────────────────
def discover_sqs():
    sqs  = client("sqs")
    resp = sqs.list_queues()
    for url in resp.get("QueueUrls", []):
        name   = url.split("/")[-1]
        record = meta(name, "SQS")
        record["queue_url"] = url
        assets.append(record)
        print(f"  🔍 SQS: {name}")

# ── 6. Discover API Gateway ───────────────────────────────────────────────────
def discover_api_gateway():
    apigw = client("apigateway")
    resp  = apigw.get_rest_apis()
    for api in resp["items"]:
        name   = api["name"]
        record = meta(name, "APIGateway")
        record["api_id"] = api["id"]
        assets.append(record)
        print(f"  🔍 API Gateway: {name}")

# ── 7. Manual Service Nodes (define manually) ─────────────────────────────────
def discover_manual_nodes():
    manual = [
        {"name":"mysql-db",    "host":"mysql-db.local",    "port":3306},
        {"name":"redis-cache", "host":"redis-cache.local",  "port":6379},
        {"name":"waf-firewall","host":"waf-firewall.local", "port":443},
    ]
    for node in manual:
        record = meta(node["name"], "ManualNode")
        record.update({"host": node["host"], "port": node["port"]})
        assets.append(record)
        print(f"  🔍 Manual Node: {node['name']}")

# ── 8. Infrastructure Nodes (define manually) ─────────────────────────────────
def discover_infra_nodes():
    infra = [
        {"name":"load-balancer",   "type_detail":"ALB"},
        {"name":"cloudtrail-logs", "type_detail":"CloudTrail"},
        {"name":"kms-keys",        "type_detail":"KMS"},
    ]
    for node in infra:
        record = meta(node["name"], "InfraNode")
        record["type_detail"] = node["type_detail"]
        assets.append(record)
        print(f"  🔍 Infra Node: {node['name']}")

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    for title, fn in [
        ("EC2 Instances",    discover_ec2),
        ("S3 Buckets",       discover_s3),
        ("IAM Roles",        discover_iam),
        ("Lambda Functions", discover_lambda),
        ("SQS Queues",       discover_sqs),
        ("API Gateway",      discover_api_gateway),
        ("Manual Nodes",     discover_manual_nodes),
        ("Infra Nodes",      discover_infra_nodes),
    ]:
        print(f"\n🔍 Discovering {title}...")
        fn()

    # Save to assets.json
    with open("assets.json", "w") as f:
        json.dump(assets, f, indent=2, default=str)

    print(f"\n{'='*50}")
    print(f"  TOTAL DISCOVERED: {len(assets)} assets")
    print(f"  💾 Saved to assets.json")
    print("  ✅ Done!" if len(assets)==25 else f"  ⚠️ Expected 25, got {len(assets)}")