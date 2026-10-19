"""S3-only instance-role policy state, including already-issued-session revocation."""

from typing import Any, Dict


def trust_policy(active: bool) -> Dict[str, Any]:
    # An inactive trust has no Allow, and an explicit Deny for EC2. This stops
    # new role sessions; role_state(False) also denies existing role sessions.
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "Ec2Only" if active else "InactiveEc2Trust",
        "Effect": "Allow" if active else "Deny",
        "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def role_state(active: bool, home: str = "") -> Dict[str, Any]:
    if not active:
        return {"Version": "2012-10-17", "Statement": [{
            "Sid": "InactiveState", "Effect": "Deny", "Action": "*", "Resource": "*"}]}
    # This is deliberately not an administrative role. Even a mistakenly
    # attached broad Allow cannot confer EC2, IAM, SSM, or other service access.
    # GetCallerIdentity returns only the role's own identity, not another role.
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "ActiveState", "Effect": "Deny", "NotAction": ["s3:*", "sts:GetCallerIdentity"], "Resource": "*"},
        {"Sid": "ReadOwnHomeBucket", "Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
         "Resource": "arn:aws:s3:::" + home},
        {"Sid": "ReadOwnHomeObjects", "Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"],
         "Resource": "arn:aws:s3:::" + home + "/*"},
    ]}


def attached_policy_arns(account_id: str) -> list:
    return ["arn:aws:iam::%s:policy/WangLabS3Access%s" % (account_id, suffix)
            for suffix in ("ReadApproved", "CurrentMemberWriteOwn")]
