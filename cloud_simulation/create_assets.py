import boto3, json, zipfile, io

ENDPOINT = "http://localhost:4566"
REGION   = "us-east-1"
KWARGS   = dict(endpoint_url=ENDPOINT, region_name=REGION,
                aws_access_key_id="test", aws_secret_access_key="test")

def client(service): return boto3.client(service, **KWARGS)

asset_log = []

def create_ec2_instances():
    ec2 = client("ec2")
    for name in ["api-server","auth-service","payment-service","worker-service"]:
        resp = ec2.run_instances(
            ImageId="ami-00000000", MinCount=1, MaxCount=1,
            InstanceType="t2.micro",
            TagSpecifications=[{"ResourceType":"instance","Tags":[{"Key":"Name","Value":name}]}]
        )
        iid = resp["Instances"][0]["InstanceId"]
        asset_log.append(("EC2", name, iid))
        print(f"  ✅ EC2: {name} → {iid}")

def create_s3_buckets():
    s3 = client("s3")
    for name in ["user-docs","kyc-files","audit-logs","backups"]:
        s3.create_bucket(Bucket=name)
        asset_log.append(("S3", name, f"s3://{name}"))
        print(f"  ✅ S3: {name}")

def create_iam_roles():
    iam = client("iam")
    trust = json.dumps({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},
        "Action":"sts:AssumeRole"}]})
    for name in ["admin-role","payment-role","readonly-role","db-access-role","lambda-exec-role"]:
        resp = iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)
        asset_log.append(("IAM", name, resp["Role"]["Arn"]))
        print(f"  ✅ IAM: {name}")

def create_lambda_functions():
    lam  = client("lambda")
    iam  = client("iam")
    role = iam.get_role(RoleName="lambda-exec-role")["Role"]["Arn"]
    for name, code in {
        "payment-lambda": "def handler(e,c): return {'status':'payment-ok'}",
        "kyc-lambda":     "def handler(e,c): return {'status':'kyc-ok'}",
        "notify-lambda":  "def handler(e,c): return {'status':'notify-ok'}",
    }.items():
        buf = io.BytesIO()
        with zipfile.ZipFile(buf,"w") as z: z.writestr("handler.py", code)
        resp = lam.create_function(FunctionName=name, Runtime="python3.11",
            Role=role, Handler="handler.handler", Code={"ZipFile": buf.getvalue()})
        asset_log.append(("Lambda", name, resp["FunctionArn"]))
        print(f"  ✅ Lambda: {name}")

def create_sqs_queues():
    sqs = client("sqs")
    for name in ["tx-queue","notify-queue"]:
        resp = sqs.create_queue(QueueName=name)
        asset_log.append(("SQS", name, resp["QueueUrl"]))
        print(f"  ✅ SQS: {name}")

def create_api_gateway():
    apigw = client("apigateway")
    resp  = apigw.create_rest_api(name="fintech-api-gateway")
    asset_log.append(("APIGateway", "fintech-api-gateway", resp["id"]))
    print(f"  ✅ API Gateway: fintech-api-gateway")

def create_manual_nodes():
    ssm = client("ssm")
    for name, meta in {
        "mysql-db":    {"type":"RDS-MySQL",  "host":"mysql-db.local",    "port":"3306"},
        "redis-cache": {"type":"ElastiCache","host":"redis-cache.local",  "port":"6379"},
        "waf-firewall":{"type":"WAF",        "host":"waf-firewall.local", "port":"443"},
    }.items():
        ssm.put_parameter(Name=f"/fintech/manual/{name}",
            Value=json.dumps(meta), Type="String", Overwrite=True)
        asset_log.append(("ManualNode", name, f"/fintech/manual/{name}"))
        print(f"  ✅ Manual Node: {name}")

def create_infra_nodes():
    ssm = client("ssm")
    for name, meta in {
        "load-balancer":   {"type":"ALB",        "status":"active"},
        "cloudtrail-logs": {"type":"CloudTrail", "status":"enabled"},
        "kms-keys":        {"type":"KMS",        "status":"active"},
    }.items():
        ssm.put_parameter(Name=f"/fintech/infra/{name}",
            Value=json.dumps(meta), Type="String", Overwrite=True)
        asset_log.append(("InfraNode", name, f"/fintech/infra/{name}"))
        print(f"  ✅ Infra Node: {name}")

if __name__ == "__main__":
    for title, fn in [
        ("EC2 Instances",    create_ec2_instances),
        ("S3 Buckets",       create_s3_buckets),
        ("IAM Roles",        create_iam_roles),
        ("Lambda Functions", create_lambda_functions),
        ("SQS Queues",       create_sqs_queues),
        ("API Gateway",      create_api_gateway),
        ("Manual Nodes",     create_manual_nodes),
        ("Infra Nodes",      create_infra_nodes),
    ]:
        print(f"\n🔧 {title}...")
        fn()

    print(f"\n{'='*50}")
    print(f"  TOTAL: {len(asset_log)} assets created")
    print("🎉 Done!" if len(asset_log)==25 else f"⚠️ Expected 25, got {len(asset_log)}")