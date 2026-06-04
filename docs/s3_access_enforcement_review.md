# S3 Access Enforcement Review

Date: 2026-05-22

No AWS permission changes have been applied from this review.

## Confirmed Model

- Admin group: `admin`
- Current-member group: `lab_members`
- Alumni group: `alumni`
- `alumni`: read-only to approved human/shared S3 buckets.
- `lab_members`: read approved human/shared S3 buckets, write only their own user bucket.
- `admin`: read approved human/shared S3 buckets, write their own user bucket, and write shared/ops buckets.
- Admins should not write another human user's bucket unless using a separate break-glass/admin role.
- Service-managed buckets should be handled separately from human data buckets.

## My Recommendation for Service-Managed Buckets

Do not put service-managed buckets into the normal "everyone can read" bucket set by default.

Reason: CloudTrail, AWS Config, CloudFormation/deployment, and cluster-managed buckets can contain account activity, infrastructure metadata, templates, generated artifacts, or operational details. Those are not the same as lab data buckets.

Recommended classes:

| Class | Human read | Human write | Service write |
| --- | --- | --- | --- |
| `User` | `lab_members`, `alumni`, `admin` | owner only, but only if owner is current member/admin | none |
| `SharedOps` | `lab_members`, `alumni`, `admin` | `admin` only | none |
| `ServiceManaged` | `admin` only by default | `admin` only by default | required AWS service principals only |

Service-managed buckets stay admin-only for human access.

## Users With No Obvious Bucket

After your corrections, these IAM users still have no clear personal bucket:

| IAM user | Group | Proposed access |
| --- | --- | --- |
| `Andrey_User` | `alumni` | read-only |
| `Julia_User` | `alumni` | read-only |
| `Kostya_User` | `alumni` | read-only |
| `Martin_User` | `alumni` | read-only |
| `Rebecca_User` | `alumni` | read-only |
| `Sung_User` | `alumni` | read-only |

Resolved conflict:

| IAM user | Candidate bucket | Why it needs confirmation |
| --- | --- | --- |
| `Thomas_User` | `thomas-moody` | confirmed owner |
| `Tom_User` |  | confirmed orphan IAM user |

## Corrected User-To-Bucket Mapping

`alumni` users are intentionally read-only, even if they have a historical bucket.

| IAM user | Group | Access role | Home bucket | Write status | Note |
| --- | --- | --- | --- | --- | --- |
| `Amanda_User` | `alumni` | `Alumni` | `amanda-s` | read-only | historical user bucket |
| `Andrey_User` | `alumni` | `Alumni` |  | read-only | no obvious bucket |
| `Baiyang_User` | `lab_members` | `User` | `baiyang-liu` | write own | current member |
| `Carlotta_User` | `alumni` | `Alumni` | `carlotta-ronda` | read-only | historical user bucket |
| `Chao_User` | `lab_members` | `User` | `chao-chen` | write own | current member |
| `Christian_User` | `alumni` | `Alumni` | `chrmu` | read-only | Christian Munck |
| `Deirdre_User` | `alumni` | `Alumni` | `deirdre-ricaurte` | read-only | historical user bucket |
| `Diego_User` | `lab_members` | `User` | `diego-gelsinger` | write own | current member |
| `Florencia_User` | `alumni` | `Alumni` | `florencia-velez` | read-only | historical user bucket |
| `Frederik_User` | `alumni` | `Alumni` | `frederik` | read-only | historical user bucket |
| `Grace_User` | `alumni` | `Alumni` | `bukowski-thall` | read-only | Grace's last name |
| `Guillaume_user` | `alumni` | `Alumni` | `guillaume-urtecho` | read-only | historical user bucket |
| `Hazel_User` | `alumni` | `Alumni` | `hazel-zhao` | read-only | historical user bucket |
| `Jaysen_User` | `alumni` | `Alumni` | `jaysen-zhang` | read-only | historical user bucket |
| `Jay_User` | `alumni` | `Alumni` | `jayzhao` | read-only | historical user bucket |
| `Jeongchan_User` | `alumni` | `Alumni` | `jeongchan-lee` | read-only | historical user bucket |
| `Jimin_User` | `alumni` | `Alumni` | `jimin-park` | read-only | historical user bucket |
| `Jonathan_User` | `alumni` | `Alumni` | `jonathan-algoo` | read-only | historical user bucket |
| `Julia_User` | `alumni` | `Alumni` |  | read-only | no obvious bucket |
| `Kostya_User` | `alumni` | `Alumni` |  | read-only | no obvious bucket |
| `Liu_Liyuan_User` | `lab_members` | `User` | `lly-sam` | write own | Liyuan Liu |
| `LiyuanLin_User` | `lab_members` | `User` | `liyuan-lin` | write own | Liyuan Lin |
| `Logan_User` | `alumni` | `Alumni` | `logan-schwanz` | read-only | historical user bucket |
| `Martin_User` | `alumni` | `Alumni` |  | read-only | no obvious bucket |
| `Matthew_User` | `lab_members` | `User` | `matthew-nemeth` | write own | current member |
| `Miles_User` | `alumni` | `Alumni` | `miles-r` | read-only | historical user bucket |
| `Nathan_User` | `alumni` | `Alumni` | `nathan-johns` | read-only | historical user bucket |
| `NSF-Rol-User` | `alumni` | `Alumni` |  | read-only | `nsf-rol-data` treated as shared/project bucket |
| `Rachel_User` | `alumni` | `Alumni` | `rachel-asbury` | read-only | historical user bucket |
| `Ravi_User` | `alumni` | `Alumni` | `ravi_sheth` | read-only | historical user bucket |
| `Rebecca_User` | `alumni` | `Alumni` |  | read-only | no obvious bucket |
| `Ross_User` | `alumni` | `Alumni` | `ross-mcbee-wanglab` | read-only | historical user bucket |
| `Simon_User` | `alumni` | `Alumni` | `simon-kozlov` | read-only | historical user bucket |
| `Stone_User` | `alumni` | `Alumni` | `stone-su` | read-only | historical user bucket |
| `Sung_User` | `alumni` | `Alumni` |  | read-only | no obvious bucket |
| `Thomas_User` | `alumni` | `Alumni` | `thomas-moody` | read-only | confirmed owner |
| `TomBlaze` | `alumni` | `Alumni` | `tom_blaze_bucket` | read-only | TomBlaze |
| `Tom_User` | `alumni` | `Alumni` |  | read-only | confirmed orphan IAM user |
| `YimingQu_User` | `admin` | `Admin` | `yiming-qu` | write own + shared/ops | Yiming Qu |
| `Yiming_User` | `admin` | `Admin` | `yiming-huang` | write own + shared/ops | Yiming Huang; Yiming by itself means Yiming Huang |
| `Yiwei_Sun` | `lab_members` | `User` | `yiwei-sun` | write own | current member |
| `Yuanyuan_User` | `lab_members` | `User` | `yuanyuan-huang` | write own | current member |

## Corrected Bucket Classification

| Bucket | Proposed class | Human write rule | Note |
| --- | --- | --- | --- |
| `amanda-s` | `User` | no human write while owner is alumni | owner `Amanda_User` |
| `baiyang-liu` | `User` | owner current member only | owner `Baiyang_User` |
| `bukowski-thall` | `User` | no human write while owner is alumni | Grace |
| `carlotta-ronda` | `User` | no human write while owner is alumni | owner `Carlotta_User` |
| `chao-chen` | `User` | owner current member only | owner `Chao_User` |
| `chrmu` | `User` | no human write while owner is alumni | Christian Munck |
| `deirdre-ricaurte` | `User` | no human write while owner is alumni | owner `Deirdre_User` |
| `diego-gelsinger` | `User` | owner current member only | owner `Diego_User` |
| `felix-wu` | `SharedOps` | admin only | human bucket without IAM account |
| `florencia-velez` | `User` | no human write while owner is alumni | owner `Florencia_User` |
| `frederik` | `User` | no human write while owner is alumni | owner `Frederik_User` |
| `guillaume-urtecho` | `User` | no human write while owner is alumni | owner `Guillaume_user` |
| `hazel-zhao` | `User` | no human write while owner is alumni | owner `Hazel_User` |
| `hsing-ho` | `SharedOps` | admin only | human bucket without IAM account |
| `jacky-cheung` | `SharedOps` | admin only | human bucket without IAM account |
| `jaysen-zhang` | `User` | no human write while owner is alumni | owner `Jaysen_User` |
| `jayzhao` | `User` | no human write while owner is alumni | owner `Jay_User` |
| `jeongchan-lee` | `User` | no human write while owner is alumni | owner `Jeongchan_User` |
| `jimin-park` | `User` | no human write while owner is alumni | owner `Jimin_User` |
| `jonathan-algoo` | `User` | no human write while owner is alumni | owner `Jonathan_User` |
| `kendall-dabaghi` | `SharedOps` | admin only | human bucket without IAM account |
| `liyuan-lin` | `User` | owner current member only | owner `LiyuanLin_User` |
| `logan-schwanz` | `User` | no human write while owner is alumni | owner `Logan_User` |
| `matthew-nemeth` | `User` | owner current member only | owner `Matthew_User` |
| `miles-r` | `User` | no human write while owner is alumni | owner `Miles_User` |
| `nathan-johns` | `User` | no human write while owner is alumni | owner `Nathan_User` |
| `rachel-asbury` | `User` | no human write while owner is alumni | owner `Rachel_User` |
| `ravi_sheth` | `User` | no human write while owner is alumni | owner `Ravi_User` |
| `ross-mcbee-wanglab` | `User` | no human write while owner is alumni | owner `Ross_User` |
| `simon-kozlov` | `User` | no human write while owner is alumni | owner `Simon_User` |
| `stone-su` | `User` | no human write while owner is alumni | owner `Stone_User` |
| `thomas-moody` | `User` | no human write while owner is alumni | owner `Thomas_User` |
| `tom_blaze_bucket` | `User` | no human write while owner is alumni | owner `TomBlaze` |
| `yiming-huang` | `User` | owner admin only | owner `Yiming_User` |
| `yiming-qu` | `User` | owner admin only | owner `YimingQu_User` |
| `yiwei-sun` | `User` | owner current member only | owner `Yiwei_Sun` |
| `yuanyuan-huang` | `User` | owner current member only | owner `Yuanyuan_User` |
| `bin` | `SharedOps` | admin only | shared/ops or orphan bucket |
| `ccf-sparc-ibd-data` | `SharedOps` | admin only | shared/data bucket |
| `easy-amplicon-camii-test-data` | `SharedOps` | admin only | shared/data bucket |
| `isolate-biobank-server` | `SharedOps` | admin only | shared/ops bucket |
| `izaak-bucket` | `SharedOps` | admin only | orphan bucket unless identified later |
| `lly-sam` | `User` | owner current member only | owner `Liu_Liyuan_User` |
| `novogene-data-upload` | `SharedOps` | admin only | shared/data upload bucket |
| `nsf-rol-data` | `SharedOps` | admin only | project bucket |
| `rm-sra-upload` | `SharedOps` | admin only | shared/data upload bucket |
| `seq-backup` | `SharedOps` | admin only | shared/ops bucket |
| `srasubbucket` | `SharedOps` | admin only | shared/data bucket |
| `wanglab-misc-backups` | `SharedOps` | admin only | shared/ops bucket |
| `wanglab-transition` | `SharedOps` | admin only | shared/ops bucket |
| `amazon-cloudwatch-auto-alar-lambdadeploymentbucket-6oqlxtk3d0jy` | `ServiceManaged` | admin only by default | AWS deployment bucket |
| `bulk-policy-migration-787744166714` | `ServiceManaged` | admin only by default | policy migration bucket |
| `cf-templates-1md7e4zf6elzm-us-east-1` | `ServiceManaged` | admin only by default | CloudFormation template bucket |
| `config-bucket-787744166714` | `ServiceManaged` | admin only by default | AWS Config-style bucket |
| `my-787744166714-cloudtrail-audit` | `ServiceManaged` | admin only by default | CloudTrail delivery bucket |
| `my-787744166714-config-history` | `ServiceManaged` | admin only by default | AWS Config delivery bucket |
| `parallelcluster-a0bb52db9667ad8e-v1-do-not-delete` | `ServiceManaged` | admin only by default | ParallelCluster-managed bucket |

## Proposed Enforcement Steps

1. Tag users:
   - `AccessRole=Admin` for `admin`
   - `AccessRole=CurrentMember` for `lab_members`
   - `AccessRole=Alumni` for `alumni`
   - `HomeBucket=<bucket>` only where a clear home bucket exists
2. Tag buckets:
   - `BucketScope=User`, `BucketOwner=<IAM user>`, `OwnerAccessRole=<current group role>`
   - `BucketScope=SharedOps`
   - `BucketScope=ServiceManaged`
3. Replace broad S3 write access:
   - remove `AmazonS3FullAccess` from `lab_members`
   - give `lab_members` read-all-approved + own-bucket-write
   - give `alumni` read-all-approved only
   - give `admin` read-all-approved + own-bucket-write + shared/ops write
4. Apply guardrail denies:
   - `User`: deny writes unless `HomeBucket` matches and `AccessRole` is `CurrentMember` or `Admin`
   - `SharedOps`: deny writes unless `AccessRole=Admin`
   - `ServiceManaged`: do not apply the shared/ops deny blindly; preserve service-principal delivery policies
5. Run IAM simulation and then real temporary object tests.

## Onboarding and Group-Change Automation

I do not see the human IAM transfer automation in this repo. If it exists elsewhere, the cleanest approach is to make S3 access reconciliation a single idempotent command that the existing automation calls after every user lifecycle change.

Recommended shape:

1. Keep a source-of-truth file, for example `config/s3_access_manifest.yaml`, with:
   - IAM user
   - display name
   - group role: `admin`, `lab_members`, or `alumni`
   - home bucket, if any
   - bucket class overrides for orphan/shared/service buckets
2. Add a Python CLI managed with `uv`, for example `s3_access_reconcile.py`.
3. The CLI should:
   - read the manifest
   - read live IAM users, groups, policies, S3 buckets, bucket policies, and bucket tags
   - print a diff by default
   - apply only with `--apply`
   - fail if any user/bucket is ambiguous
4. Existing onboarding/group-transfer automation should call:
   - `uv run python s3_access_reconcile.py plan`
   - `uv run python s3_access_reconcile.py apply`
5. For new current members, the automation should:
   - create or verify IAM user
   - create or verify home bucket
   - add user to `lab_members`
   - tag user and bucket
   - reconcile policies
   - run a small IAM simulation for that user
6. For alumni transfer, the automation should:
   - move user from `lab_members` to `alumni`
   - keep the home bucket tag for history
   - remove personal write via group/policy reconciliation
   - verify the user is read-only
7. For admin promotion, the automation should:
   - move user to `admin`
   - set `AccessRole=Admin`
   - reconcile policies
   - verify admin can write shared/ops but not other user buckets
