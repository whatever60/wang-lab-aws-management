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

For alumni, the EC2 policy explicitly allows a fixed set of eleven Describe
actions and explicitly denies other direct EC2 actions. The deny uses `NotAction`
with that exact allowlist, scoped by the presence of `ec2:Region` and
`aws:ViaAWSService=false`. The EC2 service condition keeps it from denying
unrelated services. An `Action=ec2:*` deny would also override the intended
Describe allows and must not be used for this policy.

The manifest is a full-account inventory, rather than a per-user onboarding
delta. User roles and bucket scopes must be recognized values, names must be
unique, and a personal bucket's owner and the user's home bucket must agree in
both directions. IAM group membership is checked against the three roles before
any changes. `HpcUid` is maintained separately and is preserved by this reconciler.
