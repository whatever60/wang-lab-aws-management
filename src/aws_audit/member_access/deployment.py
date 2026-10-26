"""Build the dedicated member lifecycle stack offline; no deployment side effects."""

import json
import re
from typing import Any, Dict

from .models import COMPONENT, MANAGED_BY, ROLE_PATH
from .runtime import CONFIG_ENV, HANDLER, IAM_EVENTS, validate_runtime_config
from .native import NATIVE_EVENTS, CREATOR_TAG, OWNER_TAG
from ..ec2_access.policy import PROTECTED_KINDS


BOUNDARY_NAME = "WangLabMemberS3Boundary"
FUNCTION_NAME = "wanglab-member-access-sync"


def data_boundary(account_id: str) -> Dict[str, Any]:
    """Cap managed instance roles to account-local S3 data access only.

    This is a ceiling, not a grant. Approved-bucket identity policies and the
    live-validated HomeBucket still decide which data is actually accessible.
    Bucket-policy/ACL/administrative and non-S3 powers are outside the ceiling.
    """
    local = {"StringEquals": {"s3:ResourceAccount": account_id}}
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "ListAccountBucketNames", "Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"},
        {"Sid": "ReadAccountBucketData", "Effect": "Allow", "Action": [
            "s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads",
            "s3:GetBucketAcl", "s3:GetBucketOwnershipControls", "s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration",
            "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectTagging", "s3:GetObjectVersionTagging"],
         "Resource": "arn:aws:s3:::*", "Condition": local},
        {"Sid": "WriteOwnHomeData", "Effect": "Allow", "Action": [
            "s3:AbortMultipartUpload", "s3:DeleteObject", "s3:DeleteObjectTagging", "s3:DeleteObjectVersion",
            "s3:DeleteObjectVersionTagging", "s3:ListMultipartUploadParts", "s3:PutObject", "s3:PutObjectTagging",
            "s3:PutObjectVersionTagging"], "Resource": "arn:aws:s3:::${aws:PrincipalTag/HomeBucket}/*", "Condition": local},
        {"Sid": "IdentifyOwnSession", "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
    ]}


def runtime_permissions(account_id: str, region: str, boundary_arn: str) -> Dict[str, Any]:
    """Direct metadata grants plus trusted delegation of bounded S3-only roles.

    The controller is an IAM provisioner and must be protected accordingly.
    It has no direct object reads or compute-start permission.
    """
    role = "arn:aws:iam::%s:role%s*" % (account_id, ROLE_PATH)
    profile = "arn:aws:iam::%s:instance-profile%s*" % (account_id, ROLE_PATH)
    markers = {"aws:ResourceTag/ManagedBy": MANAGED_BY, "aws:ResourceTag/Component": COMPONENT}
    creation = {"aws:RequestTag/ManagedBy": MANAGED_BY, "aws:RequestTag/Component": COMPONENT}
    managed_keys = ["ManagedBy", "Component", "Owner", "HomeBucket", "AccessRole"]
    policies = ["arn:aws:iam::%s:policy/WangLabS3Access%s" % (account_id, name)
                for name in ("ReadApproved", "CurrentMemberWriteOwn")]
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "ReadIdentityMetadata", "Effect": "Allow", "Action": ["iam:GetGroup", "iam:GetUser",
            "iam:ListUserTags", "iam:ListRoles", "iam:ListInstanceProfiles", "iam:GetRole", "iam:ListRoleTags",
            "iam:GetInstanceProfile", "iam:ListInstanceProfileTags"], "Resource": "*"},
        {"Sid": "ReadManagedRoleMetadata", "Effect": "Allow", "Action": ["iam:GetRole", "iam:ListRoleTags",
            "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:ListInstanceProfilesForRole"], "Resource": role},
        {"Sid": "ReadManagedProfiles", "Effect": "Allow", "Action": ["iam:GetInstanceProfile", "iam:ListInstanceProfileTags"], "Resource": profile},
        {"Sid": "CreateBoundedRoles", "Effect": "Allow", "Action": "iam:CreateRole", "Resource": role,
         "Condition": {"StringEquals": {**creation, "iam:PermissionsBoundary": boundary_arn}}},
        {"Sid": "ManageOwnedRoleState", "Effect": "Allow", "Action": ["iam:PutRolePolicy",
            "iam:UpdateAssumeRolePolicy"], "Resource": role, "Condition": {"StringEquals": markers}},
        {"Sid": "KeepMandatoryBoundary", "Effect": "Allow", "Action": "iam:PutRolePermissionsBoundary", "Resource": role,
         "Condition": {"StringEquals": {**markers, "iam:PermissionsBoundary": boundary_arn}}},
        {"Sid": "TagManagedRoles", "Effect": "Allow", "Action": ["iam:TagRole"], "Resource": role,
         "Condition": {"StringEquals": markers, "ForAllValues:StringEquals": {"aws:TagKeys": managed_keys}}},
        {"Sid": "TagNewManagedRoles", "Effect": "Allow", "Action": "iam:TagRole", "Resource": role,
         "Condition": {"StringEquals": creation, "ForAllValues:StringEquals": {"aws:TagKeys": managed_keys}}},
        {"Sid": "OnlyDataPolicyAttachments", "Effect": "Allow", "Action": ["iam:AttachRolePolicy"],
         "Resource": role, "Condition": {"StringEquals": markers, "ArnEquals": {"iam:PolicyARN": policies}}},
        {"Sid": "CreateManagedProfiles", "Effect": "Allow", "Action": "iam:CreateInstanceProfile", "Resource": profile,
         "Condition": {"StringEquals": creation}},
        {"Sid": "ManageOwnedProfileBinding", "Effect": "Allow", "Action": ["iam:AddRoleToInstanceProfile"],
         "Resource": profile, "Condition": {"StringEquals": markers}},
        {"Sid": "TagManagedProfiles", "Effect": "Allow", "Action": ["iam:TagInstanceProfile"],
         "Resource": profile, "Condition": {"StringEquals": markers, "ForAllValues:StringEquals": {"aws:TagKeys": managed_keys}}},
        {"Sid": "TagNewManagedProfiles", "Effect": "Allow", "Action": "iam:TagInstanceProfile", "Resource": profile,
         "Condition": {"StringEquals": creation, "ForAllValues:StringEquals": {"aws:TagKeys": managed_keys}}},
        {"Sid": "PassManagedDataRolesOnly", "Effect": "Allow", "Action": "iam:PassRole", "Resource": role,
         "Condition": {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}},
        {"Sid": "ReadHomeOwnershipOnly", "Effect": "Allow", "Action": "s3:GetBucketTagging", "Resource": "arn:aws:s3:::*",
         "Condition": {"StringEquals": {"s3:ResourceAccount": account_id}}},
        {"Sid": "ReadComputeMetadata", "Effect": "Allow", "Action": ["ec2:DescribeKeyPairs", "ec2:DescribeInstances", "ec2:DescribeVolumes",
            "ec2:DescribeNetworkInterfaces", "ec2:DescribeSnapshots", "ec2:DescribeImages", "ec2:DescribeSecurityGroups",
            "ec2:DescribeIamInstanceProfileAssociations", "ec2:DescribeTags"], "Resource": "*"},
        {"Sid": "ReadCreatorHistory", "Effect": "Allow", "Action": "cloudtrail:LookupEvents", "Resource": "*"},
        {"Sid": "AttributeNativeResources", "Effect": "Allow", "Action": "ec2:CreateTags",
         "Resource": ["arn:aws:ec2:%s:%s:%s/*" % (region, "" if kind in ("snapshot", "image") else account_id, kind)
                      for kind in PROTECTED_KINDS],
         "Condition": {"ForAllValues:StringEquals": {"aws:TagKeys": [OWNER_TAG, CREATOR_TAG]}}},
        {"Sid": "AttachDataProfileToNewNativeInstance", "Effect": "Allow", "Action": "ec2:AssociateIamInstanceProfile",
         "Resource": "arn:aws:ec2:%s:%s:instance/*" % (region, account_id),
         "Condition": {"Null": {"ec2:ResourceTag/" + CREATOR_TAG: "false"}}},
        {"Sid": "NeverAssumeDelegatedRoles", "Effect": "Deny", "Action": ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"], "Resource": "*"},
    ]}


def cloudformation_template(config: dict, *, artifact_bucket: str, artifact_key: str) -> Dict[str, Any]:
    """Render an isolated, reviewable stack using already-uploaded source code."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]", artifact_bucket):
        raise ValueError("artifact_bucket must be an exact S3 bucket name")
    if not artifact_key.startswith("member-access/releases/") or not artifact_key.endswith(".zip") or ".." in artifact_key:
        raise ValueError("artifact_key must identify a managed release ZIP")
    account = config["ec2_config"]["account_id"]
    region = "us-east-1"
    validate_runtime_config(config, account_id=account, region=region)
    boundary = "arn:aws:iam::%s:policy/%s" % (account, BOUNDARY_NAME)
    if config["permissions_boundary_arn"] != boundary:
        raise ValueError("runtime boundary must be the stack-managed data boundary")
    serialized = json.dumps(config, separators=(",", ":"), sort_keys=True)
    if len(CONFIG_ENV.encode()) + len(serialized.encode()) > 4096:
        raise ValueError("approved configuration exceeds Lambda's 4 KB environment limit")
    tags = [{"Key": "ManagedBy", "Value": MANAGED_BY}, {"Key": "Component", "Value": COMPONENT}]
    permissions = runtime_permissions(account, region, boundary)
    permissions["Statement"].extend([
        {"Sid": "WriteOwnLogs", "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": {"Fn::GetAtt": ["Logs", "Arn"]}},
    ])
    resources: Dict[str, Any] = {
        "Boundary": {"Type": "AWS::IAM::ManagedPolicy", "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain", "Properties": {"ManagedPolicyName": BOUNDARY_NAME, "PolicyDocument": data_boundary(account)}},
        "Logs": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": "/aws/lambda/" + FUNCTION_NAME, "RetentionInDays": 30, "Tags": tags}},
        "RuntimeRole": {"Type": "AWS::IAM::Role", "Properties": {"RoleName": "WangLabMemberAccessSync", "Tags": tags,
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
            "Policies": [{"PolicyName": "MemberLifecycleMetadata", "PolicyDocument": permissions}]}},
        "Function": {"Type": "AWS::Lambda::Function", "DependsOn": ["Boundary", "Logs"], "Properties": {
            "FunctionName": FUNCTION_NAME, "Runtime": "python3.12", "Handler": HANDLER, "Role": {"Fn::GetAtt": ["RuntimeRole", "Arn"]},
            "Code": {"S3Bucket": artifact_bucket, "S3Key": artifact_key}, "Timeout": 900, "MemorySize": 512, "ReservedConcurrentExecutions": 1,
            "Environment": {"Variables": {CONFIG_ENV: serialized}}, "Tags": tags}},
        "Errors": {"Type": "AWS::CloudWatch::Alarm", "Properties": {"AlarmName": "wanglab-member-access-errors", "Namespace": "AWS/Lambda", "MetricName": "Errors",
            "Dimensions": [{"Name": "FunctionName", "Value": {"Ref": "Function"}}], "Statistic": "Sum", "Period": 60, "EvaluationPeriods": 1,
            "Threshold": 1, "ComparisonOperator": "GreaterThanOrEqualToThreshold", "TreatMissingData": "notBreaching"}},
    }
    resources["IdentityChanges"] = {"Type": "AWS::Events::Rule", "Properties": {
        "Name": "wanglab-member-access-identity", "State": "ENABLED", "ScheduleExpression": "rate(5 minutes)",
        "EventPattern": {"source": ["aws.iam", "aws.ec2"], "detail-type": ["AWS API Call via CloudTrail"],
                         "detail": {"eventSource": ["iam.amazonaws.com", "ec2.amazonaws.com"],
                                    "eventName": list(IAM_EVENTS) + list(NATIVE_EVENTS),
                                    "errorCode": [{"exists": False}]}},
        "Targets": [{"Id": "MemberAccess", "Arn": {"Fn::GetAtt": ["Function", "Arn"]}}]}}
    resources["IdentityChangesPermission"] = {"Type": "AWS::Lambda::Permission", "Properties": {
        "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "Function"}, "Principal": "events.amazonaws.com",
        "SourceArn": {"Fn::GetAtt": ["IdentityChanges", "Arn"]}, "SourceAccount": account}}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Native EC2 creator attribution and personal S3 roles with membership-driven revocation",
            "Resources": resources, "Outputs": {"FunctionName": {"Value": {"Ref": "Function"}},
                "BoundaryArn": {"Value": {"Ref": "Boundary"}}}}
