# S3 Access Reconciliation

The S3 access reconciler manages IAM tags, bucket tags, IAM policies, group policy
attachments, and bucket guardrails from a manifest.

## Local Manifest

The committed file is a redacted example:

```text
config/s3_access_manifest.example.json
```

Copy it to the ignored local path and fill in real account data:

```bash
cp config/s3_access_manifest.example.json config/s3_access_manifest.local.json
```

Do not commit the local manifest.

## Plan And Apply

Plan:

```bash
uv run aws-audit s3-access plan
```

Apply:

```bash
uv run aws-audit s3-access apply
```

Use `--manifest` to point at another local manifest:

```bash
uv run aws-audit s3-access plan --manifest path/to/manifest.local.json
```

## Model

Users have an `AccessRole` and optionally a `HomeBucket`. Buckets have a `BucketScope`
and optionally a `BucketOwner`.

Typical scopes:

- `User`: a user's own bucket.
- `SharedOps`: shared operational data, writable by admins only.
- `ServiceManaged`: service-owned delivery buckets, generally admin-only.

The reconciler is intentionally explicit: ambiguous users or buckets should be fixed in
the manifest instead of guessed.
