"""Render one member RunInstances request offline, without credentials or AWS calls.

The approved sources come from the same reviewed configuration as the member
policy. IAM still checks the caller's exact username and the key pair's Owner
tag when the resulting request is submitted. This module cannot verify those
live facts. Root disk settings are inherited from the approved image.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple

from .policy import MemberEc2Config, _validate, config_from_mapping


def _source_id(arns: Tuple[str, ...], region: str, chosen: Optional[str], label: str) -> str:
    approved = [arn.split("/", 1)[1] for arn in arns if arn.split(":")[3] == region]
    if not approved:
        raise ValueError("no approved " + label + " in region " + region)
    if chosen is None:
        return approved[0]
    if chosen not in approved:
        raise ValueError(label + " must be an exact approved ID in region " + region)
    return chosen


def build_launch_request(config: MemberEc2Config, *, username: str, key_name: str,
                         instance_type: str, region: Optional[str] = None,
                         image_id: Optional[str] = None, subnet_id: Optional[str] = None,
                         security_group_id: Optional[str] = None,
                         name: Optional[str] = None) -> Dict[str, Any]:
    """Return AWS CLI RunInstances input for one new personal instance.

    Defaults preserve configuration order: first region, then its first approved
    image, subnet, and security group. The AWS CLI region is an option outside
    this JSON; callers must use the same selected region when submitting it.
    No instance profile, template, market option, placement, existing network
    interface, or custom block-device mapping is accepted. EC2's ordinary
    on-demand and default-tenancy defaults apply.
    """
    _validate(config)
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,64}", username):
        raise ValueError("username must be an exact IAM username, without a path or wildcard")
    if (not isinstance(key_name, str) or not 1 <= len(key_name) <= 255
            or key_name != key_name.strip()
            or any(not 32 <= ord(char) <= 126 for char in key_name)
            or any(char in key_name for char in "*?")):
        raise ValueError("key-name must be an exact printable ASCII name of 1-255 characters, without edge spaces or wildcards")
    if not isinstance(instance_type, str) or instance_type not in config.instance_types:
        raise ValueError("instance-type must be an exact approved type")
    selected_region = config.regions[0] if region is None else region
    if selected_region not in config.regions:
        raise ValueError("region must be an exact approved region")
    if name is not None and (not isinstance(name, str) or not name.strip() or len(name) > 256
                             or any(ord(char) < 32 or ord(char) == 127 for char in name)):
        raise ValueError("name must contain 1-256 characters, without control characters")
    image = _source_id(config.approved_image_arns, selected_region, image_id, "image")
    subnet = _source_id(config.approved_subnet_arns, selected_region, subnet_id, "subnet")
    group = _source_id(config.approved_security_group_arns, selected_region, security_group_id, "security group")
    tags = [{"Key": "Owner", "Value": username}, {"Key": "Project", "Value": "personal"}]
    if name is not None:
        tags.append({"Key": "Name", "Value": name})
    return {
        "ImageId": image,
        "InstanceType": instance_type,
        "KeyName": key_name,
        "MinCount": 1,
        "MaxCount": 1,
        "NetworkInterfaces": [{"DeviceIndex": 0, "SubnetId": subnet, "Groups": [group],
                               "AssociatePublicIpAddress": True, "DeleteOnTermination": True}],
        "TagSpecifications": [{"ResourceType": kind, "Tags": [dict(tag) for tag in tags]}
                              for kind in ("instance", "volume", "network-interface")],
    }


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="Render one tagged member EC2 RunInstances JSON request offline; no AWS calls",
        epilog="Redirect stdout to launch.json. Submit separately using the region reported on stderr; first use --dry-run. "
               "The selected key must already have Owner equal to the exact IAM username. "
               "The approved AMI supplies root disk settings; no disk resize is inferred.")
    parser.add_argument("config", type=Path, help="reviewed member EC2 policy JSON configuration")
    parser.add_argument("--username", required=True, help="exact case-sensitive IAM username")
    parser.add_argument("--key-name", required=True, help="existing personally owned EC2 key pair name")
    parser.add_argument("--instance-type", required=True, help="exact approved instance type")
    parser.add_argument("--region", help="approved region; default: first configured region")
    parser.add_argument("--image-id", help="approved AMI ID; default: first approved image in selected region")
    parser.add_argument("--subnet-id", help="approved subnet ID; default: first approved subnet in selected region")
    parser.add_argument("--security-group-id", help="approved security group ID; default: first approved group in selected region")
    parser.add_argument("--name", help="optional descriptive Name tag on all three resource types")
    args = parser.parse_args(argv)
    try:
        config = config_from_mapping(json.loads(args.config.read_text(encoding="utf-8")))
        request = build_launch_request(config, username=args.username, key_name=args.key_name,
                                       instance_type=args.instance_type, region=args.region,
                                       image_id=args.image_id, subnet_id=args.subnet_id,
                                       security_group_id=args.security_group_id, name=args.name)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    json.dump(request, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    selected_region = args.region or config.regions[0]
    interface = request["NetworkInterfaces"][0]
    print("Offline request: region=%s image=%s subnet=%s security-group=%s; count=1, on-demand/default tenancy."
          % (selected_region, request["ImageId"], interface["SubnetId"], interface["Groups"][0]), file=sys.stderr)
    print("Verify the caller and key Owner match --username. After saving stdout to launch.json, validate separately:", file=sys.stderr)
    print("aws ec2 run-instances --region %s --cli-input-json file://launch.json --dry-run" % selected_region, file=sys.stderr)


if __name__ == "__main__":
    main()
