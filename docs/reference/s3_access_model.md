# S3 Access Model

The S3 access model combines identity-side and resource-side metadata.

```text
IAM user tags:
  AccessRole = Admin | CurrentMember | Alumni
  HomeBucket = optional bucket name

S3 bucket tags:
  BucketScope = User | SharedOps | ServiceManaged
  BucketOwner = optional IAM user name
```

Managed IAM policies provide the broad intended permissions. S3 bucket policies add
guardrails where identity policies alone are too broad.

The local manifest is the source of truth for users, roles, buckets, and ownership.
