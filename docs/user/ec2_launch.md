# Launch a Personal EC2 Instance

Use your personal **EC2 Launch Templates** in **US East (N. Virginia),
`us-east-1`**. The templates fill in ownership tags, your SSH key, approved
network settings, and your personal S3 instance role. You do not need to enter
three sets of resource tags by hand.

Start with **Launch instance from template**. The member policy requires your
personal template; a plain **Launch instance** request without a template is
denied even if the selected instance type is approved.

## Choose a Template

1. Sign in with your own IAM account and select `us-east-1`.
2. Open **EC2 → Launch Templates**. Search for
   `wanglab-member-<your exact IAM username>-`. For example, `AliceUser` searches
   for `wanglab-member-AliceUser-`.
3. Select the desired flavor, then **Actions → Launch instance from template**.
   Use the template's **Default** version.

IAM usernames containing `@`, `+`, `=`, or `,` use a normalized template name
with a short hash suffix. Find those templates using their Owner tag, which
still contains your unchanged exact IAM username, and select the desired flavor.

| Name suffix | Starting image | Default instance type |
| --- | --- | --- |
| `Ubuntu2404` | Ubuntu 24.04 | `t3.micro` |
| `Al2023` | Amazon Linux 2023 | `t3.micro` |
| `DL2204` | NVIDIA deep learning image on Ubuntu 22.04 | `g6.xlarge` |
| `DL2404` | NVIDIA deep learning image on Ubuntu 24.04 | `g6.xlarge` |

The console lets you review and override template parameters before launching.
The IAM policy still checks the final request.
[AWS console launch-template instructions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/launch-instances-from-launch-template.html)

The flavor selects the operating-system image, rather than fixing the machine
size. For work requiring more RAM, start with the Ubuntu or Amazon Linux
template and select an approved instance type with enough memory. Increasing
the **Storage** volume size increases disk capacity, not RAM; the 1024 GiB
per-volume limit concerns disk storage.

## Review and Launch

The template supplies:

- `Owner=<your exact IAM username>` and `Project=personal` on the instance,
  newly created volumes, and network interface, plus a descriptive `Name`.
- Your personal instance profile, containing the S3 role named exactly like
  your IAM username.
- An existing SSH key pair whose `Owner` tag matches your IAM username.
- An approved subnet and security group, a new network interface with public
  IPv4 enabled, and deletion of that interface when the instance is terminated.
- IMDSv2 with metadata tokens required.

Choose an approved instance type and **one instance**. You may select another
approved image or another key pair owned by you. Multiple personal key pairs
are supported; select one for which you have the private key. The default stays
the same while it remains a valid owned key. A first-time default is selected
deterministically from the owned keys.

Keep the required ownership tags, your personal profile, and IMDSv2 settings.
Choose on-demand/default tenancy, use the existing approved network settings,
and keep each volume at or below 1024 GiB. You may change the descriptive `Name`.
The console may show other choices, but IAM rejects unapproved sources or
types, another person's key/profile/template, and protected-tag changes.
Members cannot edit the managed templates or create their own replacement
templates. Review the summary before choosing **Launch instance**.

Connect by SSH using the private key corresponding to the selected key pair.
Use the login user documented for the selected image: normally `ubuntu` for
the Ubuntu flavors and `ec2-user` for Amazon Linux. Network reachability and
security-group ingress must also permit your connection.

## Use S3 Without Personal AWS Keys on the Instance

The personal instance role provides temporary, automatically refreshed
credentials through EC2 metadata. Current AWS CLI and SDK credential providers
use them automatically. Do not run `aws configure` to store a personal IAM
access key on the instance, copy another person's keys, or retrieve and paste
the role's temporary secrets.
[AWS instance-role credential behavior](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-security-credentials.html)

With a current AWS CLI installed on the instance, check the identity without
printing any credential material:

```bash
aws sts get-caller-identity --query Arn --output text
```

The ARN should identify your personal assumed role, for example
`arn:aws:sts::111122223333:assumed-role/AliceUser/<instance-id>`. If it identifies
an IAM user or a different role, resolve the existing environment/profile
credentials with an administrator before using S3.

The role permits approved lab-bucket reads and writes to your own home bucket.
It does not grant EC2, IAM, or SSM management. For a metadata-only bucket listing,
replace the placeholder with the home bucket assigned to you:

```bash
aws s3 ls "s3://YOUR_HOME_BUCKET/"
```

Processes and users that can reach this instance's metadata service can use
its S3 role. IMDSv2 does not create separate S3 identities for Linux users.
Use these profiles on personal instances; they are unsuitable for shared HPC
nodes or machines shared by people with different S3 access rights.

## Missing Templates or Access Denied

Templates become usable after an administrator has confirmed current-member
status, home-bucket ownership, and at least one personally owned SSH key.
Without an owned key, templates may exist in a pending state but the four
required launch permissions are not published. A familiar key name alone is
not proof of ownership.

If the four templates are missing or a request is denied, give the
administrator your exact IAM username, template name, selected region, and the
AWS error code. Do not send passwords, private keys, or temporary credentials.
An administrator can inspect the plan and invoke synchronization; automatic
reconciliation also runs every five minutes. Delivery, retries, and IAM
propagation can take longer than that interval.

Existing instances keep their current profiles. This launch setup does not
add a role to an older machine. Leaving the member group disables the managed
personal S3 role after reconciliation and IAM propagation, including credentials
already issued to running instances. It does not itself remove Linux accounts,
revoke SSH keys, or terminate instances.
