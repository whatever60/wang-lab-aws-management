# S3 Access Policy Test Results

This archived page records the expected test shape without exposing account-specific
identifiers.

## Test Matrix

For each role, validate representative read/write behavior:

| Actor | Bucket Scope | Read | Write |
| --- | --- | --- | --- |
| Current member | own `User` bucket | allowed | allowed |
| Current member | other `User` bucket | allowed | denied |
| Current member | `SharedOps` bucket | allowed | denied |
| Alumni | historical own `User` bucket | allowed | denied |
| Alumni | other `User` bucket | allowed | denied |
| Admin | own `User` bucket | allowed | allowed |
| Admin | `SharedOps` bucket | allowed | allowed |
| Admin | other `User` bucket | allowed | denied by guardrail |
| Any routine user | `ServiceManaged` bucket | limited/read-only if approved | denied |

## Notes

`aws iam simulate-principal-policy` is useful but should not be the only validation for
S3 because resource-based bucket policy denies can be subtle. Use live temporary-user
tests for final confirmation in a non-production-safe test window.

## Alumni EC2 Regression Checks

The alumni deny must exclude the exact Describe allowlist while still overriding
a competing broad EC2 allow for direct mutation requests. Use read-only
`aws iam simulate-custom-policy` checks with:

- All eleven approved Describe actions: `allowed`.
- Representative instance, volume, snapshot, VPC, key-pair, Spot/Fleet, tag, and
  security-group mutations, with a second test policy allowing `ec2:*`:
  `explicitDeny`.
- EC2 reads outside the approved allowlist, with that competing allow:
  `explicitDeny`.
- Approved S3 `GetObject`: `allowed`; S3 `PutObject`: `implicitDeny` when only the
  alumni policy is supplied.
- S3 and IAM actions granted by a separate test policy: unaffected by the EC2 deny.

For direct EC2 simulations, provide `aws:ViaAWSService` as boolean `false` and
`ec2:Region` as string `us-east-1`. For unrelated-service simulations, omit
`ec2:Region`, as in their real request context. The simulator accepts caller-supplied
context; it does not prove which keys a real service supplies. AWS's
[EC2 IAM documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-policies-for-amazon-ec2.html)
provides the guarantee that all EC2 actions support `ec2:Region`.

Offline tests additionally protect the full-account inventory checks, duplicate
and role/scope rejection, bidirectional home ownership, independent policy builds,
unchanged S3 statements, and preservation of separately managed `HpcUid` tags.
