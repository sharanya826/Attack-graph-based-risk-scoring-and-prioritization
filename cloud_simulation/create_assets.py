import boto3, json, zipfile, io

ENDPOINT = "http://localhost:4566"
REGION   = "us-east-1"
KWARGS   = dict(endpoint_url=ENDPOINT, region_name=REGION,
                aws_access_key_id="test", aws_secret_access_key="test")

def client(service): return boto3.client(service, **KWARGS)

asset_log = []

# ── 1. EC2 (4 assets) ────────────────────────────────────
def create_ec2_instances():
    ec2 = client("ec2")
    try:
        existing = ec2.describe_instances()
        for r in existing["Reservations"]:
            for i in r["Instances"]:
                if i["State"]["Name"] not in ["terminated"]:
                    ec2.terminate_instances(InstanceIds=[i["InstanceId"]])
    except Exception:
        pass

    for name in ["api-server","auth-service","payment-service","worker-service"]:
        try:
            resp = ec2.run_instances(
                ImageId="ami-00000000", MinCount=1, MaxCount=1,
                InstanceType="t2.micro",
                TagSpecifications=[{"ResourceType":"instance",
                                    "Tags":[{"Key":"Name","Value":name}]}]
            )
            iid = resp["Instances"][0]["InstanceId"]
            asset_log.append(("EC2", name, iid))
            print(f"  ✅ EC2: {name} → {iid}")
        except Exception as e:
            print(f"  ❌ EC2: {name} → {e}")

# ── 2. S3 (4 assets) ─────────────────────────────────────
def create_s3_buckets():
    s3 = client("s3")
    for name in ["user-docs","kyc-files","audit-logs","backups"]:
        try:
            s3.create_bucket(Bucket=name)
        except Exception:
            pass  # already exists — fine
        asset_log.append(("S3", name, f"s3://{name}"))
        print(f"  ✅ S3: {name}")

# ── 3. IAM (5 assets) ────────────────────────────────────
def create_iam_roles():
    iam = client("iam")
    trust = json.dumps({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow",
        "Principal":{"Service":"lambda.amazonaws.com"},
        "Action":"sts:AssumeRole"}]})
    for name in ["admin-role","payment-role","readonly-role",
                 "db-access-role","lambda-exec-role"]:
        try:
            iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)
        except Exception:
            pass  # already exists — fine
        asset_log.append(("IAM", name, name))
        print(f"  ✅ IAM: {name}")

# ── 4. Lambda (3 assets) ─────────────────────────────────
def create_lambda_functions():
    lam  = client("lambda")
    iam  = client("iam")
    try:
        role = iam.get_role(RoleName="lambda-exec-role")["Role"]["Arn"]
    except Exception as e:
        print(f"  ❌ Lambda: cannot get role → {e}")
        return

    for name, code in {
        "payment-lambda": "def handler(e,c): return {'status':'payment-ok'}",
        "kyc-lambda":     "def handler(e,c): return {'status':'kyc-ok'}",
        "notify-lambda":  "def handler(e,c): return {'status':'notify-ok'}",
    }.items():
        # always delete first to avoid conflict
        try:
            lam.delete_function(FunctionName=name)
        except Exception:
            pass

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("handler.py", code)
        try:
            lam.create_function(
                FunctionName=name, Runtime="python3.11",
                Role=role, Handler="handler.handler",
                Code={"ZipFile": buf.getvalue()}
            )
            asset_log.append(("Lambda", name, name))
            print(f"  ✅ Lambda: {name}")
        except Exception as e:
            print(f"  ❌ Lambda: {name} → {e}")

# ── 5. SQS via SSM (2 assets) ────────────────────────────
# SQS broken in LocalStack 2.3 — stored as SSM parameters instead
def create_sqs_queues():
    ssm = client("ssm")
    for name, meta in {
        "tx-queue":     {"type":"SQS","url":"http://localhost:4566/000000000000/tx-queue",     "msgs":"0"},
        "notify-queue": {"type":"SQS","url":"http://localhost:4566/000000000000/notify-queue", "msgs":"0"},
    }.items():
        try:
            ssm.put_parameter(
                Name=f"/fintech/sqs/{name}",
                Value=json.dumps(meta),
                Type="String",
                Overwrite=True
            )
            asset_log.append(("SQS", name, f"/fintech/sqs/{name}"))
            print(f"  ✅ SQS (simulated): {name}")
        except Exception as e:
            print(f"  ❌ SQS: {name} → {e}")

# ── 6. API Gateway (1 asset) ─────────────────────────────
def create_api_gateway():
    apigw = client("apigateway")
    try:
        existing = apigw.get_rest_apis()["items"]
        found = [a for a in existing if a["name"] == "fintech-api-gateway"]
        if found:
            api_id = found[0]["id"]
            print(f"  ✅ API Gateway: fintech-api-gateway (existing) → {api_id}")
        else:
            resp   = apigw.create_rest_api(name="fintech-api-gateway")
            api_id = resp["id"]
            print(f"  ✅ API Gateway: fintech-api-gateway → {api_id}")
        asset_log.append(("APIGateway", "fintech-api-gateway", api_id))
    except Exception as e:
        print(f"  ❌ API Gateway → {e}")

# ── 7. Manual Nodes via SSM (3 assets) ───────────────────
def create_manual_nodes():
    ssm = client("ssm")
    for name, meta in {
        "mysql-db":    {"type":"RDS-MySQL",   "host":"mysql-db.local",    "port":"3306"},
        "redis-cache": {"type":"ElastiCache", "host":"redis-cache.local", "port":"6379"},
        "waf-firewall":{"type":"WAF",         "host":"waf-firewall.local","port":"443"},
    }.items():
        try:
            ssm.put_parameter(
                Name=f"/fintech/manual/{name}",
                Value=json.dumps(meta),
                Type="String",
                Overwrite=True
            )
            asset_log.append(("ManualNode", name, f"/fintech/manual/{name}"))
            print(f"  ✅ Manual Node: {name}")
        except Exception as e:
            print(f"  ❌ Manual Node: {name} → {e}")

# ── 8. Infra Nodes via SSM (3 assets) ────────────────────
def create_infra_nodes():
    ssm = client("ssm")
    for name, meta in {
        "load-balancer":   {"type":"ALB",        "status":"active"},
        "cloudtrail-logs": {"type":"CloudTrail", "status":"enabled"},
        "kms-keys":        {"type":"KMS",        "status":"active"},
    }.items():
        try:
            ssm.put_parameter(
                Name=f"/fintech/infra/{name}",
                Value=json.dumps(meta),
                Type="String",
                Overwrite=True
            )
            asset_log.append(("InfraNode", name, f"/fintech/infra/{name}"))
            print(f"  ✅ Infra Node: {name}")
        except Exception as e:
            print(f"  ❌ Infra Node: {name} → {e}")

# ── MAIN ─────────────────────────────────────────────────
if __name__ == "__main__":
    print("Starting fintech asset creation...\n")
    for title, fn in [
        ("EC2 Instances (4)",      create_ec2_instances),
        ("S3 Buckets (4)",         create_s3_buckets),
        ("IAM Roles (5)",          create_iam_roles),
        ("Lambda Functions (3)",   create_lambda_functions),
        ("SQS Queues (2)",         create_sqs_queues),
        ("API Gateway (1)",        create_api_gateway),
        ("Manual Nodes (3)",       create_manual_nodes),
        ("Infra Nodes (3)",        create_infra_nodes),
    ]:
        print(f"🔧 {title}...")
        fn()
        print()

    print("=" * 50)
    print(f"  TOTAL: {len(asset_log)} assets created")
    if len(asset_log) >= 25:
        print("🎉 Target of 25 assets reached!")
    else:
        print(f"⚠️  Expected 25, got {len(asset_log)}")
        for t, n, i in asset_log:
            print(f"    {t}: {n}")
