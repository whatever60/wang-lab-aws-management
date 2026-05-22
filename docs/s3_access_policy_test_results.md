# S3 Access Policy Test Results

Date: 2026-05-22

No AWS permission changes were applied.

## Live Inventory Signals

- IAM users: 42
- S3 buckets: 57
- IAM groups: `admin`, `alumni`, `lab_members`
- `admin` users: `YimingQu_User`, `Yiming_User`
- `lab_members` users: `Baiyang_User`, `Diego_User`, `Yiwei_Sun`, `LiyuanLin_User`, `Chao_User`, `Yuanyuan_User`, `Matthew_User`, `Liu_Liyuan_User`

Current broad access found:

- `admin` has `AdministratorAccess`
- `lab_members` has `AmazonS3FullAccess`

Required tags are not yet in place:

- `YimingQu_User` has no IAM tags.
- `Baiyang_User` has an unrelated access-key-style tag, not `HomeBucket` / `AccessRole`.
- `baiyang-liu` has no S3 bucket tag set.

## Current Live Policy Simulation

Representative normal user: `Baiyang_User`

| Action | Bucket object | Current decision |
| --- | --- | --- |
| `s3:GetObject` | `baiyang-liu/test.txt` | allowed |
| `s3:GetObject` | `diego-gelsinger/test.txt` | allowed |
| `s3:GetObject` | `seq-backup/test.txt` | allowed |
| `s3:PutObject` | `baiyang-liu/test.txt` | allowed |
| `s3:PutObject` | `diego-gelsinger/test.txt` | allowed |
| `s3:PutObject` | `seq-backup/test.txt` | allowed |
| `s3:DeleteObject` | `baiyang-liu/test.txt` | allowed |
| `s3:DeleteObject` | `diego-gelsinger/test.txt` | allowed |
| `s3:DeleteObject` | `seq-backup/test.txt` | allowed |

Representative manager/admin user: `YimingQu_User`

| Action | Bucket object | Current decision |
| --- | --- | --- |
| `s3:GetObject` | `yiming-qu/test.txt` | allowed |
| `s3:GetObject` | `baiyang-liu/test.txt` | allowed |
| `s3:GetObject` | `seq-backup/test.txt` | allowed |
| `s3:PutObject` | `yiming-qu/test.txt` | allowed |
| `s3:PutObject` | `baiyang-liu/test.txt` | allowed |
| `s3:PutObject` | `seq-backup/test.txt` | allowed |
| `s3:DeleteObject` | `yiming-qu/test.txt` | allowed |
| `s3:DeleteObject` | `baiyang-liu/test.txt` | allowed |
| `s3:DeleteObject` | `seq-backup/test.txt` | allowed |

Conclusion: the desired access model is not currently enforced.

## Proposed Policy Simulation

The proposed model was tested with `aws iam simulate-custom-policy` using synthetic principal-tag context:

- normal user context: `HomeBucket=baiyang-liu`, `AccessRole=User`
- manager context: `HomeBucket=yiming-qu`, `AccessRole=Manager`
- user buckets tested: `baiyang-liu`, `diego-gelsinger`, `yiming-qu`
- shared/ops bucket tested: `seq-backup`

Representative normal user result:

| Action | Bucket object | Proposed decision |
| --- | --- | --- |
| `s3:GetObject` | `baiyang-liu/test.txt` | allowed |
| `s3:GetObject` | `diego-gelsinger/test.txt` | allowed |
| `s3:GetObject` | `seq-backup/test.txt` | allowed |
| `s3:PutObject` | `baiyang-liu/test.txt` | allowed |
| `s3:PutObject` | `diego-gelsinger/test.txt` | explicitDeny |
| `s3:PutObject` | `seq-backup/test.txt` | explicitDeny |
| `s3:DeleteObject` | `baiyang-liu/test.txt` | allowed |
| `s3:DeleteObject` | `diego-gelsinger/test.txt` | explicitDeny |
| `s3:DeleteObject` | `seq-backup/test.txt` | explicitDeny |

Representative manager result:

| Action | Bucket object | Proposed decision |
| --- | --- | --- |
| `s3:GetObject` | `yiming-qu/test.txt` | allowed |
| `s3:GetObject` | `baiyang-liu/test.txt` | allowed |
| `s3:GetObject` | `seq-backup/test.txt` | allowed |
| `s3:PutObject` | `yiming-qu/test.txt` | allowed |
| `s3:PutObject` | `baiyang-liu/test.txt` | explicitDeny |
| `s3:PutObject` | `seq-backup/test.txt` | allowed |
| `s3:DeleteObject` | `yiming-qu/test.txt` | allowed |
| `s3:DeleteObject` | `baiyang-liu/test.txt` | explicitDeny |
| `s3:DeleteObject` | `seq-backup/test.txt` | allowed |

Conclusion: the proposed model works in non-destructive IAM simulation for the representative cases tested.

## Important Simulator Note

For this S3 deny-policy scenario, multi-resource simulator calls reported misleading cross-resource deny matches. Final results above were generated with one action/resource pair per simulator call.

## Applied Enforcement Result

Date: 2026-05-22

The S3 access reconciler was applied with:

```bash
uv run python s3_access_reconcile.py apply
```

The follow-up idempotence check showed no remaining changes:

```bash
uv run python s3_access_reconcile.py plan
```

Applied policy changes:

- Created `WangLabS3AccessReadApproved`
- Created `WangLabS3AccessCurrentMemberWriteOwn`
- Created `WangLabS3AccessAdminWriteSharedOpsAndReadService`
- Created `WangLabS3AccessAlumniBase`
- Detached `AmazonS3FullAccess` from `lab_members`
- Detached legacy `minimal-access` from `alumni`
- Tagged IAM users with `AccessRole` and, where applicable, `HomeBucket`
- Tagged S3 buckets with `BucketScope` and ownership tags
- Added S3 bucket-policy guardrails to user, human-no-account, and shared/ops buckets
- Left service-managed bucket policies unmodified except for bucket tags

Current group policy attachments:

| Group | Attached policies |
| --- | --- |
| `lab_members` | `DenyLargeEbsVolumesForNonManagers`, `AmazonEC2FullAccess`, `WangLabS3AccessReadApproved`, `WangLabS3AccessCurrentMemberWriteOwn` |
| `alumni` | `WangLabS3AccessAlumniBase` |
| `admin` | `AdministratorAccess`, `Billing`, `WangLabS3AccessReadApproved`, `WangLabS3AccessCurrentMemberWriteOwn`, `WangLabS3AccessAdminWriteSharedOpsAndReadService` |

Representative one-action/one-resource IAM simulations:

| Principal | Resource class | Read | Write |
| --- | --- | --- | --- |
| `Baiyang_User` current member | own bucket `baiyang-liu` | allowed | allowed |
| `Baiyang_User` current member | other user bucket `diego-gelsinger` | allowed | implicitDeny |
| `Baiyang_User` current member | shared/ops bucket `seq-backup` | allowed | implicitDeny |
| `Baiyang_User` current member | service bucket `my-787744166714-cloudtrail-audit` | implicitDeny | implicitDeny |
| `Amanda_User` alumni | historical own bucket `amanda-s` | allowed | implicitDeny |
| `Amanda_User` alumni | other user bucket `baiyang-liu` | allowed | implicitDeny |
| `Amanda_User` alumni | shared/ops bucket `seq-backup` | allowed | implicitDeny |
| `Amanda_User` alumni | service bucket `my-787744166714-cloudtrail-audit` | implicitDeny | implicitDeny |

Real object write/delete test with current admin credentials:

| Principal | Bucket | Result |
| --- | --- | --- |
| `YimingQu_User` | own bucket `yiming-qu` | put/delete succeeded |
| `YimingQu_User` | shared/ops bucket `seq-backup` | put/delete succeeded |
| `YimingQu_User` | service bucket `my-787744166714-cloudtrail-audit` | put/delete succeeded |
| `YimingQu_User` | other user bucket `baiyang-liu` | put denied with explicit resource-policy deny |

Note: `aws iam simulate-principal-policy` does not fully reflect S3 bucket-policy explicit denies when a broad identity policy such as `AdministratorAccess` is present. The real S3 write test confirmed the bucket guardrail denied admin writes to another user's bucket.
