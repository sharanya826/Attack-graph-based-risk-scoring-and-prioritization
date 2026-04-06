import boto3, json, os

ENDPOINT = "http://localhost:4566"
REGION   = "us-east-1"
KWARGS   = dict(endpoint_url=ENDPOINT, region_name=REGION,
                aws_access_key_id="test", aws_secret_access_key="test")

def client(service): return boto3.client(service, **KWARGS)

assets = []

# ── 1. EC2 Instances ─────────────────────────────────────
def discover_ec2():
    print("🔍 Discovering EC2 instances...")
    ec2 = client("ec2")
    try:
        resp = ec2.describe_instances()
        for r in resp["Reservations"]:
            for i in r["Instances"]:
                if i["State"]["Name"] == "terminated":
                    continue
                name = next(
                    (t["Value"] for t in i.get("Tags", [])
                     if t["Key"] == "Name"), i["InstanceId"]
                )
                asset = {
                    "id":           f"ec2:{i['InstanceId']}",
                    "name":         name,
                    "type":         "EC2",
                    "instance_id":  i["InstanceId"],
                    "state":        i["State"]["Name"],
                    "instance_type":i.get("InstanceType", "t2.micro"),
                    "public_ip":    i.get("PublicIpAddress", None),
                    "exposure":     "public" if i.get("PublicIpAddress") else "internal",
                    "cvss":         7.5 if i.get("PublicIpAddress") else 4.0,
                    "privilege":    "compute",
                    "sensitivity":  "HIGH" if name in ["api-server","payment-service"] else "MEDIUM"
                }
                assets.append(asset)
                print(f"  ✅ EC2: {name} ({i['InstanceId']})")
    except Exception as e:
        print(f"  ❌ EC2 error: {e}")

# ── 2. S3 Buckets ─────────────────────────────────────────
def discover_s3():
    print("🔍 Discovering S3 buckets...")
    s3 = client("s3")
    try:
        resp = s3.list_buckets()
        for b in resp["Buckets"]:
            name = b["Name"]
            # check if public
            try:
                acl    = s3.get_bucket_acl(Bucket=name)
                public = any(
                    "AllUsers" in g["Grantee"].get("URI", "")
                    for g in acl["Grants"]
                )
            except Exception:
                public = False

            sensitivity = "CRITICAL" if "kyc" in name or "audit" in name \
                     else "HIGH"     if "docs" in name \
                     else "MEDIUM"

            asset = {
                "id":          f"s3:{name}",
                "name":        name,
                "type":        "S3Bucket",
                "public":      public,
                "exposure":    "public" if public else "private",
                "cvss":        9.1 if public else 5.5,
                "privilege":   "storage",
                "sensitivity": sensitivity
            }
            assets.append(asset)
            print(f"  ✅ S3: {name}  public={public}  sensitivity={sensitivity}")
    except Exception as e:
        print(f"  ❌ S3 error: {e}")

# ── 3. IAM Roles ──────────────────────────────────────────
def discover_iam():
    print("🔍 Discovering IAM roles...")
    iam = client("iam")
    try:
        resp = iam.list_roles()
        for role in resp["Roles"]:
            rname = role["RoleName"]
            # check attached policies
            try:
                policies = iam.list_attached_role_policies(
                    RoleName=rname)["AttachedPolicies"]
                overprivileged = any(
                    "Admin" in p["PolicyName"] or "FullAccess" in p["PolicyName"]
                    for p in policies
                )
            except Exception:
                overprivileged = False

            asset = {
                "id":             f"iam:{rname}",
                "name":           rname,
                "type":           "IAMRole",
                "overprivileged": overprivileged,
                "exposure":       "internal",
                "cvss":           8.8 if overprivileged else 4.5,
                "privilege":      "admin" if "admin" in rname else "limited",
                "sensitivity":    "CRITICAL" if overprivileged else "MEDIUM"
            }
            assets.append(asset)
            print(f"  ✅ IAM: {rname}  overprivileged={overprivileged}")
    except Exception as e:
        print(f"  ❌ IAM error: {e}")

# ── 4. Lambda Functions ───────────────────────────────────
def discover_lambda():
    print("🔍 Discovering Lambda functions...")
    lam = client("lambda")
    try:
        resp = lam.list_functions()
        for fn in resp["Functions"]:
            fname     = fn["FunctionName"]
            role_name = fn["Role"].split("/")[-1]
            asset = {
                "id":        f"lambda:{fname}",
                "name":      fname,
                "type":      "Lambda",
                "runtime":   fn.get("Runtime", "unknown"),
                "role":      role_name,
                "exposure":  "internal",
                "cvss":      6.5,
                "privilege": "compute",
                "sensitivity": "HIGH" if "payment" in fname else "MEDIUM"
            }
            assets.append(asset)
            print(f"  ✅ Lambda: {fname}  role={role_name}")
    except Exception as e:
        print(f"  ❌ Lambda error: {e}")

# ── 5. API Gateway ────────────────────────────────────────
def discover_api_gateway():
    print("🔍 Discovering API Gateway...")
    apigw = client("apigateway")
    try:
        resp = apigw.get_rest_apis()
        for api in resp["items"]:
            asset = {
                "id":          f"apigw:{api['id']}",
                "name":        api["name"],
                "type":        "APIGateway",
                "api_id":      api["id"],
                "exposure":    "public",
                "cvss":        7.0,
                "privilege":   "gateway",
                "sensitivity": "HIGH"
            }
            assets.append(asset)
            print(f"  ✅ API Gateway: {api['name']} → {api['id']}")
    except Exception as e:
        print(f"  ❌ API Gateway error: {e}")

# ── 6. SSM Parameters (SQS + Manual + Infra nodes) ───────
def discover_ssm_nodes():
    print("🔍 Discovering SSM nodes (SQS + Manual + Infra)...")
    ssm = client("ssm")

    type_map = {
        "SQS":        {"cvss": 5.0, "exposure": "internal", "sensitivity": "MEDIUM"},
        "RDS-MySQL":  {"cvss": 8.5, "exposure": "private",  "sensitivity": "CRITICAL"},
        "ElastiCache":{"cvss": 6.0, "exposure": "private",  "sensitivity": "HIGH"},
        "WAF":        {"cvss": 4.0, "exposure": "public",   "sensitivity": "MEDIUM"},
        "ALB":        {"cvss": 6.5, "exposure": "public",   "sensitivity": "HIGH"},
        "CloudTrail": {"cvss": 3.0, "exposure": "internal", "sensitivity": "MEDIUM"},
        "KMS":        {"cvss": 5.5, "exposure": "internal", "sensitivity": "HIGH"},
    }

    try:
        resp = ssm.get_parameters_by_path(
            Path="/fintech/", Recursive=True)
        for param in resp["Parameters"]:
            try:
                meta  = json.loads(param["Value"])
                pname = param["Name"].split("/")[-1]
                ptype = meta.get("type", "Unknown")
                info  = type_map.get(ptype, {"cvss":5.0,"exposure":"internal","sensitivity":"MEDIUM"})

                asset = {
                    "id":          f"ssm:{pname}",
                    "name":        pname,
                    "type":        ptype,
                    "ssm_path":    param["Name"],
                    "exposure":    info["exposure"],
                    "cvss":        info["cvss"],
                    "privilege":   "storage" if ptype in ["RDS-MySQL","ElastiCache"] else "infra",
                    "sensitivity": info["sensitivity"],
                    **{k: v for k, v in meta.items() if k != "type"}
                }
                assets.append(asset)
                print(f"  ✅ SSM Node: {pname}  type={ptype}")
            except Exception as e:
                print(f"  ⚠️  SSM parse error for {param['Name']}: {e}")
    except Exception as e:
        print(f"  ❌ SSM error: {e}")

# ── 7. Docker services (your 3 Flask containers) ─────────
def discover_docker_services():
    print("🔍 Discovering Docker microservices...")
    services = [
        {
            "id":          "docker:api-server",
            "name":        "api-server",
            "type":        "DockerService",
            "port":        5000,
            "url":         "http://localhost:5000",
            "exposure":    "public",
            "cvss":        7.5,
            "privilege":   "api",
            "sensitivity": "HIGH",
            "debug_mode":  True   # vulnerability
        },
        {
            "id":          "docker:auth-service",
            "name":        "auth-service",
            "type":        "DockerService",
            "port":        5001,
            "url":         "http://localhost:5001",
            "exposure":    "internal",
            "cvss":        8.0,
            "privilege":   "auth",
            "sensitivity": "CRITICAL",
            "weak_secret": True   # vulnerability
        },
        {
            "id":          "docker:payment-service",
            "name":        "payment-service",
            "type":        "DockerService",
            "port":        5002,
            "url":         "http://localhost:5002",
            "exposure":    "internal",
            "cvss":        9.0,
            "privilege":   "payment",
            "sensitivity": "CRITICAL",
            "no_auth_check": True  # vulnerability
        },
        {
            "id":          "docker:mysql-db",
            "name":        "mysql-db",
            "type":        "DockerService",
            "port":        3307,
            "url":         "mysql://localhost:3307",
            "exposure":    "internal",
            "cvss":        9.5,
            "privilege":   "database",
            "sensitivity": "CRITICAL",
            "weak_password": True  # vulnerability
        },
    ]
    for s in services:
        assets.append(s)
        print(f"  ✅ Docker: {s['name']}  cvss={s['cvss']}")

# ── MAIN ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 55)
    print("  FINTECH ASSET DISCOVERY")
    print("=" * 55)
    print()

    discover_ec2()
    print()
    discover_s3()
    print()
    discover_iam()
    print()
    discover_lambda()
    print()
    discover_api_gateway()
    print()
    discover_ssm_nodes()
    print()
    discover_docker_services()
    print()

    # ── save to assets.json ──────────────────────────────
    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..", "asset_discovery", "assets.json"
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(assets, f, indent=2)

    print("=" * 55)
    print(f"  TOTAL ASSETS DISCOVERED: {len(assets)}")
    print(f"  SAVED TO: asset_discovery/assets.json")
    print("=" * 55)

    # ── summary by type ──────────────────────────────────
    print()
    print("Summary by type:")
    from collections import Counter
    counts = Counter(a["type"] for a in assets)
    for t, c in sorted(counts.items()):
        print(f"  {t:<20} {c} asset(s)")

    print()
    print("Critical assets (cvss >= 8.0):")
    for a in sorted(assets, key=lambda x: x["cvss"], reverse=True):
        if a["cvss"] >= 8.0:
            print(f"  [{a['cvss']}] {a['name']} ({a['type']})")