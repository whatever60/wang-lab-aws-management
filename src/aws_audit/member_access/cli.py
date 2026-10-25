"""Preview live metadata or invoke the serialized deployed reconciler."""

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from .deployment import FUNCTION_NAME, cloudformation_template
from .runtime import build_runtime_package, live_member_manifest, validate_runtime_config


def sync(function_name: str = FUNCTION_NAME) -> dict:
    """Use the same reserved-concurrency Lambda as automatic membership events."""
    import boto3
    from botocore.config import Config
    client = boto3.Session(region_name="us-east-1").client("lambda", config=Config(
        read_timeout=920, connect_timeout=10, retries={"mode": "standard", "max_attempts": 6}))
    response = client.invoke(
        FunctionName=function_name, InvocationType="RequestResponse",
        Payload=json.dumps({"source": "wanglab.member-access", "action": "reconcile"}).encode())
    result = json.loads(response["Payload"].read())
    if response.get("FunctionError"):
        raise RuntimeError("Member lifecycle synchronization failed; inspect its CloudWatch log and error alarm")
    return result


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Manage personal console launch templates and S3-only instance roles")
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan", help="Read live IAM/S3/EC2 metadata and show changes without applying")
    plan_parser.add_argument("--config", type=Path, default=Path("config/member_access.local.json"))
    sync_parser = commands.add_parser("sync", help="Invoke the deployed serialized lifecycle reconciler")
    sync_parser.add_argument("--function-name", default=FUNCTION_NAME)
    package_parser = commands.add_parser("package", help="Build a deterministic source-only Lambda ZIP offline")
    package_parser.add_argument("--source-root", type=Path, default=Path("src"))
    package_parser.add_argument("--output", type=Path, required=True)
    stack_parser = commands.add_parser("render-stack", help="Render CloudFormation offline; never deploys")
    stack_parser.add_argument("--config", type=Path, default=Path("config/member_access.local.json"))
    stack_parser.add_argument("--artifact-bucket", required=True)
    stack_parser.add_argument("--artifact-key", required=True)
    args = parser.parse_args(argv)
    if args.command == "sync":
        result = sync(args.function_name)
    elif args.command == "package":
        payload = build_runtime_package(args.source_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
        args.output.chmod(0o600)
        result = {"output": str(args.output), "bytes": len(payload)}
    else:
        value = json.loads(args.config.read_text())
        if args.command == "render-stack":
            result = cloudformation_template(value, artifact_bucket=args.artifact_bucket, artifact_key=args.artifact_key)
        else:
            import boto3
            from .models import config_from_mapping
            from .reconcile import reconcile
            session = boto3.Session(region_name="us-east-1")
            account = session.client("sts").get_caller_identity()["Account"]
            config = validate_runtime_config(value, account_id=account, region="us-east-1")
            iam, s3 = session.client("iam"), session.client("s3")
            manifest = live_member_manifest(iam, s3, account_id=account)
            parsed = config_from_mapping({**{k: v for k, v in config.items() if k != "native_since"}, "s3_manifest": manifest})
            result = reconcile(iam, {r: session.client("ec2", region_name=r) for r in config["ec2_config"]["regions"]},
                               parsed, s3=s3, execute=False)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
