# S3 Access Enforcement Review

This archived note captures the access-control model without account-specific users,
buckets, or policy ARNs.

## Model

IAM principals are grouped into roles:

- `Admin`
- `CurrentMember`
- `Alumni`

Users can have a `HomeBucket` tag. Buckets can have:

- `BucketScope=User`
- `BucketScope=SharedOps`
- `BucketScope=ServiceManaged`
- optional `BucketOwner=<iam-user-name>`

## Policy Intent

- Current members can read approved buckets and write to their own user bucket.
- Alumni retain limited read access and no write access.
- Admins can write to shared/ops buckets and their own user bucket.
- Service-managed buckets remain protected from routine user writes.
- Bucket policies provide guardrails so broad identity permissions do not accidentally
  bypass the intended model.

## Reconciliation

The reconciler should:

1. Read the local manifest.
2. Create or update managed IAM policies.
3. Attach policies to configured groups.
4. Apply IAM user tags.
5. Apply S3 bucket tags.
6. Apply bucket policy guardrails.

Use the sanitized example manifest as a starting point:

```text
config/s3_access_manifest.example.json
```

Real rosters and bucket names belong in ignored local manifests.
