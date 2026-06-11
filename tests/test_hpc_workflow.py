import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from aws_audit.hpc import workflow as hpc_workflow


class AwsHpcWorkflowTest(unittest.TestCase):
    """Tests for the AWS ParallelCluster workflow helper."""

    def test_family_prefix_parses_common_aws_shapes(self) -> None:
        """Instance family prefixes are parsed before size and generation details."""
        cases = {
            "c7i.4xlarge": "c",
            "g6.4xlarge": "g",
            "p4d.24xlarge": "p",
            "r7i.8xlarge": "r",
            "x2idn.32xlarge": "x",
            "u-6tb1.metal": "u",
            "trn1.32xlarge": "trn",
            "inf2.48xlarge": "inf",
            "hpc7a.96xlarge": "hpc",
        }
        for instance_type, expected in cases.items():
            self.assertEqual(hpc_workflow.family_prefix(instance_type), expected)

    def test_linux_user_from_iam_user_is_deterministic(self) -> None:
        """IAM names map to stable Linux user names."""
        cases = {
            "Baiyang_User": "baiyang",
            "Liu_Liyuan_User": "liu_liyuan",
            "LiyuanLin_User": "liyuan_lin",
            "Yiwei_Sun": "yiwei_sun",
            "YimingQu_User": "yiming_qu",
            "NSF-Rol-User": "nsf_rol",
        }
        for iam_user, expected in cases.items():
            self.assertEqual(hpc_workflow.linux_user_from_iam_user(iam_user), expected)

    def test_compute_resource_name_distinguishes_tiny_memory_shapes(self) -> None:
        """Resource names stay unique for sub-GiB EC2 shapes."""
        self.assertNotEqual(
            hpc_workflow.compute_resource_name("cpu", 1, 512, 0),
            hpc_workflow.compute_resource_name("cpu", 1, 627, 0),
        )

    def test_manifest_is_parallelcluster_first(self) -> None:
        """The manifest captures the requested ParallelCluster decision."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        self.assertEqual(manifest["decision"]["scheduler"], "aws-parallelcluster-slurm")
        self.assertEqual(manifest["decision"]["home_storage"], "efs")
        self.assertEqual(manifest["decision"]["scratch_storage"], "fsx-for-lustre-ssd")
        self.assertEqual(
            manifest["decision"]["head_and_login_policy"],
            "single-combined-head-login-instance",
        )
        self.assertEqual(manifest["parallelcluster"]["cluster_name"], "lab-hpc")
        self.assertEqual(
            manifest["parallelcluster"]["head_node"]["instance_type_by_architecture"]["x86_64"],
            "r6a.xlarge",
        )
        self.assertEqual(
            manifest["parallelcluster"]["head_node"]["instance_type_by_architecture"]["arm64"],
            "r7g.xlarge",
        )
        self.assertNotIn("login_node", manifest["parallelcluster"])

    def test_cluster_architecture_override_selects_matching_head_node(self) -> None:
        """CLI architecture overrides change both compute filtering and head/login type."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        arm_manifest = hpc_workflow.manifest_with_cluster_architecture(
            manifest, "arm64"
        )
        self.assertEqual(hpc_workflow.head_node_instance_type(manifest), "r6a.xlarge")
        self.assertEqual(arm_manifest["ec2_selection"]["cluster_architecture"], "arm64")
        self.assertEqual(hpc_workflow.head_node_instance_type(arm_manifest), "r7g.xlarge")

    def test_manifest_uses_iam_groups_and_deletes_test_storage(self) -> None:
        """User and storage policies match the requested testing behavior."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        self.assertEqual(manifest["iam_user_selection"]["include_groups"], ["lab_members", "admin"])
        self.assertEqual(manifest["iam_user_selection"]["exclude_users"], ["Diego_User"])
        self.assertEqual(manifest["storage"][0]["deletion_policy"], "Delete")
        self.assertEqual(manifest["storage"][1]["deletion_policy"], "Delete")

    def test_manifest_includes_arm_and_small_instances_in_catalog_policy(self) -> None:
        """The catalog policy includes ARM and tiny on-demand Linux instance families."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        ec2_selection = manifest["ec2_selection"]
        self.assertEqual(ec2_selection["cluster_architecture"], "x86_64")
        self.assertEqual(ec2_selection["catalog_architectures"], ["x86_64", "arm64"])
        self.assertIn("a", ec2_selection["cpu_prefixes"])
        self.assertIn("t", ec2_selection["cpu_prefixes"])
        self.assertIn(1, ec2_selection["vcpu_values"])

    def test_selected_users_include_lab_members_and_admins_without_diego(self) -> None:
        """IAM group selection combines current members and admins."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        fake_groups = {
            "lab_members": [
                "Baiyang_User",
                "Diego_User",
                "Chao_User",
            ],
            "admin": [
                "Yiming_User",
                "YimingQu_User",
            ],
        }

        def fake_run_json(command: list[str]) -> list[str]:
            """Return fake IAM group members from the command arguments."""
            group_name = command[command.index("--group-name") + 1]
            return fake_groups[group_name]

        with mock.patch.object(hpc_workflow, "run_json", side_effect=fake_run_json):
            users = hpc_workflow.lab_users_from_iam(manifest)

        self.assertEqual(
            [user["iam_user"] for user in users],
            ["Baiyang_User", "Chao_User", "Yiming_User", "YimingQu_User"],
        )
        self.assertEqual(
            [user["linux_user"] for user in users],
            ["baiyang", "chao", "yiming", "yiming_qu"],
        )
        self.assertNotIn("Diego_User", [user["iam_user"] for user in users])

    def test_generated_cluster_config_contains_core_shape(self) -> None:
        """Generated config uses one head/login node, deletable storage, and generated queues."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        fake_users = [
            {"iam_user": "Baiyang_User", "linux_user": "baiyang", "uid": 2001},
            {"iam_user": "YimingQu_User", "linux_user": "yiming_qu", "uid": 2002},
        ]
        fake_groups = {
            "cpu": [
                [
                    {
                        "InstanceType": "c7i.large",
                        "Vcpus": 2,
                        "MemoryMiB": 4096,
                        "GpuCountNormalized": 0,
                        "HourlyPrice": 0.085,
                    },
                    {
                        "InstanceType": "m7i.large",
                        "Vcpus": 2,
                        "MemoryMiB": 4096,
                        "GpuCountNormalized": 0,
                        "HourlyPrice": 0.096,
                    },
                ]
            ],
            "gpu": [
                [
                    {
                        "InstanceType": "g6.xlarge",
                        "Vcpus": 4,
                        "MemoryMiB": 16384,
                        "GpuCountNormalized": 1,
                        "HourlyPrice": 0.8048,
                    }
                ]
            ],
        }

        with mock.patch.object(hpc_workflow, "lab_users_from_iam", return_value=fake_users):
            with mock.patch.object(hpc_workflow, "grouped_candidates", return_value=fake_groups):
                config = hpc_workflow.generated_cluster_config(manifest)

        self.assertIn("HeadNode", config)
        self.assertNotIn("LoginNodes", config)
        self.assertEqual(config["SharedStorage"][0]["EfsSettings"]["DeletionPolicy"], "Delete")
        self.assertEqual(
            config["HeadNode"]["CustomActions"]["OnNodeStart"]["Args"],
            [
                "--install-slurm-policy-only",
                "s3://${PARALLELCLUSTER_ASSETS_BUCKET}/parallelcluster-assets/bootstrap/parallelcluster_active_instance_types.txt",
            ],
        )
        self.assertEqual(
            config["Scheduling"]["SlurmSettings"]["CustomSlurmSettings"][0],
            {"JobSubmitPlugins": "lua"},
        )
        self.assertEqual(
            config["Scheduling"]["SlurmQueues"][0]["ComputeResources"][0]["Instances"][0],
            {"InstanceType": "c7i.large"},
        )
        self.assertEqual(
            config["Scheduling"]["SlurmQueues"][1]["ComputeResources"][0]["HealthChecks"],
            {"Gpu": {"Enabled": True}},
        )

    def test_generated_cluster_config_uses_arm_head_when_requested(self) -> None:
        """Generated config switches the head/login node with the active architecture."""
        manifest = hpc_workflow.manifest_with_cluster_architecture(
            hpc_workflow.load_manifest(Path("config/hpc_workflow_manifest.json")),
            "arm64",
        )
        fake_users = [
            {"iam_user": "YimingQu_User", "linux_user": "yiming_qu", "uid": 2001},
        ]
        fake_groups = {
            "cpu": [
                [
                    {
                        "InstanceType": "c7g.medium",
                        "Vcpus": 1,
                        "MemoryMiB": 2048,
                        "GpuCountNormalized": 0,
                        "HourlyPrice": 0.0363,
                    },
                ]
            ],
            "gpu": [],
        }

        with mock.patch.object(hpc_workflow, "lab_users_from_iam", return_value=fake_users):
            with mock.patch.object(hpc_workflow, "grouped_candidates", return_value=fake_groups):
                config = hpc_workflow.generated_cluster_config(manifest)

        self.assertEqual(config["HeadNode"]["InstanceType"], "r7g.xlarge")
        self.assertEqual(
            config["Scheduling"]["SlurmQueues"][0]["ComputeResources"][0]["Instances"][0],
            {"InstanceType": "c7g.medium"},
        )

    def test_generic_catalog_includes_arm_and_previous_generation_tiny_instances(self) -> None:
        """Allowed catalog rows include ARM and t1.micro, while active cluster rows stay x86."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        fake_rows = [
            {
                "InstanceType": "t1.micro",
                "Vcpus": 1,
                "MemoryMiB": 627,
                "Architectures": ["i386", "x86_64"],
                "GpuCount": None,
                "GpuManufacturer": None,
                "BareMetal": False,
                "CurrentGeneration": False,
                "SupportedUsageClasses": ["on-demand"],
                "NetworkCards": 1,
            },
            {
                "InstanceType": "c7g.medium",
                "Vcpus": 1,
                "MemoryMiB": 2048,
                "Architectures": ["arm64"],
                "GpuCount": None,
                "GpuManufacturer": None,
                "BareMetal": False,
                "CurrentGeneration": True,
                "SupportedUsageClasses": ["on-demand", "spot"],
                "NetworkCards": 1,
            },
            {
                "InstanceType": "g6.xlarge",
                "Vcpus": 4,
                "MemoryMiB": 16384,
                "Architectures": ["x86_64"],
                "GpuCount": 1,
                "GpuManufacturer": "NVIDIA",
                "BareMetal": False,
                "CurrentGeneration": True,
                "SupportedUsageClasses": ["on-demand"],
                "NetworkCards": 1,
            },
            {
                "InstanceType": "g4ad.xlarge",
                "Vcpus": 4,
                "MemoryMiB": 16384,
                "Architectures": ["x86_64"],
                "GpuCount": 1,
                "GpuManufacturer": "AMD",
                "BareMetal": False,
                "CurrentGeneration": True,
                "SupportedUsageClasses": ["on-demand"],
                "NetworkCards": 1,
            },
            {
                "InstanceType": "m7i.metal-24xl",
                "Vcpus": 48,
                "MemoryMiB": 196608,
                "Architectures": ["x86_64"],
                "GpuCount": None,
                "GpuManufacturer": None,
                "BareMetal": True,
                "CurrentGeneration": True,
                "SupportedUsageClasses": ["on-demand"],
                "NetworkCards": 1,
            },
            {
                "InstanceType": "trn1.2xlarge",
                "Vcpus": 8,
                "MemoryMiB": 32768,
                "Architectures": ["x86_64"],
                "GpuCount": None,
                "GpuManufacturer": None,
                "BareMetal": False,
                "CurrentGeneration": True,
                "SupportedUsageClasses": ["on-demand"],
                "NetworkCards": 1,
            },
        ]
        fake_prices = {
            "t1.micro": 0.02,
            "c7g.medium": 0.036,
            "g6.xlarge": 0.8048,
            "g4ad.xlarge": 0.379,
            "m7i.metal-24xl": 5.0,
            "trn1.2xlarge": 1.34,
        }
        fake_offered = set(fake_prices)

        with mock.patch.object(hpc_workflow, "ec2_instance_type_rows", return_value=fake_rows):
            with mock.patch.object(hpc_workflow, "available_instance_types", return_value=fake_offered):
                with mock.patch.object(hpc_workflow, "linux_on_demand_prices", return_value=fake_prices):
                    full_rows = hpc_workflow.generic_candidate_rows(manifest, False)
                    active_rows = hpc_workflow.generic_candidate_rows(manifest, True)
                    catalog_rows = hpc_workflow.instance_catalog_rows(manifest, False)

        full_types = [row["InstanceType"] for row in full_rows]
        active_types = [row["InstanceType"] for row in active_rows]
        self.assertIn("t1.micro", full_types)
        self.assertIn("c7g.medium", full_types)
        self.assertIn("g6.xlarge", full_types)
        self.assertNotIn("g4ad.xlarge", full_types)
        self.assertNotIn("m7i.metal-24xl", full_types)
        self.assertNotIn("trn1.2xlarge", full_types)
        self.assertNotIn("c7g.medium", active_types)
        t1_row = next(row for row in catalog_rows if row["instance"] == "t1.micro")
        arm_row = next(row for row in catalog_rows if row["instance"] == "c7g.medium")
        self.assertEqual(t1_row["arch"], "x86_64")
        self.assertEqual(t1_row["current"], "False")
        self.assertEqual(arm_row["arch"], "arm64")

    def test_bootstrap_script_has_aggregate_limits_and_job_submit_policy(self) -> None:
        """Bootstrap config enforces aggregate login limits and explicit Slurm requests."""
        text = Path("scripts/parallelcluster_create_lab_users.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("CPUQuota=${HEAD_LOGIN_LIMIT_CPUS}", text)
        self.assertIn("MemoryMax=${HEAD_LOGIN_LIMIT_MEMORY}", text)
        self.assertIn('HEAD_LOGIN_LIMIT_MEMORY="16G"', text)
        self.assertIn("@${LAB_GROUP} hard maxlogins ${HEAD_LOGIN_MAX_SESSIONS}", text)
        self.assertIn("job_submit.lua", text)
        self.assertIn("--cpus-per-task", text)
        self.assertIn("--mem or --mem-per-cpu", text)
        self.assertIn("has_instance_type_constraint", text)
        self.assertIn("aws-audit-sbatch", text)
        self.assertIn("--instance-type", text)
        self.assertIn("active_instance_types.txt", text)
        self.assertIn("not available in this active ParallelCluster config", text)
        self.assertIn("Cross-architecture requests are rejected", text)
        self.assertIn('exec sbatch --constraint="${instance_type}"', text)
        self.assertNotIn("diego", text.lower())

    def test_pcluster_create_command_has_dryrun(self) -> None:
        """The dry-run create command renders the expected pcluster shape."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        command = hpc_workflow.pcluster_create_command(manifest, True)
        self.assertEqual(command[0:2], ["pcluster", "create-cluster"])
        self.assertIn("--dryrun", command)
        self.assertIn("true", command)
        self.assertIn("config/parallelcluster_lab.yaml", command)

    def test_pcluster_delete_command_targets_cluster(self) -> None:
        """The cleanup command targets the configured cluster."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        command = hpc_workflow.pcluster_delete_command(manifest)
        self.assertEqual(command[0:2], ["pcluster", "delete-cluster"])
        self.assertIn("lab-hpc", command)

    def test_bootstrap_upload_command_uses_assets_bucket(self) -> None:
        """The bootstrap upload command writes to the manifest assets prefix."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        command = hpc_workflow.bootstrap_upload_command(manifest)
        self.assertEqual(command[0:3], ["aws", "s3", "cp"])
        self.assertEqual(command[3], "scripts/parallelcluster_create_lab_users.sh")
        self.assertEqual(
            command[4],
            "s3://${PARALLELCLUSTER_ASSETS_BUCKET}/parallelcluster-assets/bootstrap/parallelcluster_create_lab_users.sh",
        )

    def test_active_instance_types_upload_command_uses_assets_bucket(self) -> None:
        """The active instance allowlist upload command writes to the manifest assets prefix."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        command = hpc_workflow.active_instance_types_upload_command(manifest)
        self.assertEqual(command[0:3], ["aws", "s3", "cp"])
        self.assertEqual(command[3], "config/parallelcluster_active_instance_types.txt")
        self.assertEqual(
            command[4],
            "s3://${PARALLELCLUSTER_ASSETS_BUCKET}/parallelcluster-assets/bootstrap/parallelcluster_active_instance_types.txt",
        )

    def test_slurm_submit_commands_filter_gpu_and_expected_failures(self) -> None:
        """Slurm test rendering can include GPU and expected rejection tests explicitly."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        default_commands = hpc_workflow.slurm_submit_commands(manifest, False, False)
        gpu_commands = hpc_workflow.slurm_submit_commands(manifest, True, False)
        all_commands = hpc_workflow.slurm_submit_commands(manifest, True, True)
        self.assertEqual(len(default_commands), 4)
        self.assertEqual(len(gpu_commands), 5)
        self.assertEqual(len(all_commands), 6)
        self.assertFalse(any("gpu_nvidia_smoke" in " ".join(command) for command in default_commands))
        self.assertTrue(any("reject_missing_resources" in " ".join(command) for command in all_commands))

    def test_slurm_job_files_are_real_sbatch_scripts(self) -> None:
        """Every manifest Slurm job script exists and has SBATCH directives."""
        manifest = hpc_workflow.load_manifest(
            Path("config/hpc_workflow_manifest.json")
        )
        for job in manifest["slurm_test_jobs"]:
            text = Path(job["script"]).read_text(encoding="utf-8")
            self.assertIn("#SBATCH", text)
            self.assertIn("#!/bin/bash", text)

    def test_mock_scripts_run_with_small_inputs(self) -> None:
        """The local mock scripts from the previous iteration still run safely."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            commands = [
                [
                    sys.executable,
                    "examples/hpc_jobs/mock_data_preprocess.py",
                    "--rows",
                    "10",
                    "--columns",
                    "4",
                    "--output",
                    str(temp_path / "data.json"),
                ],
                [
                    sys.executable,
                    "examples/hpc_jobs/mock_gpu_training.py",
                    "--epochs",
                    "2",
                    "--batch-size",
                    "4",
                    "--feature-count",
                    "16",
                    "--checkpoint",
                    str(temp_path / "gpu.json"),
                ],
                [
                    sys.executable,
                    "examples/hpc_jobs/mock_high_memory_join.py",
                    "--fact-rows",
                    "100",
                    "--dimension-rows",
                    "10",
                    "--output",
                    str(temp_path / "memory.json"),
                ],
            ]
            for command in commands:
                subprocess.run(command, check=True, capture_output=True, text=True)
            self.assertEqual(
                json.loads((temp_path / "data.json").read_text())["job"],
                "mock-data-preprocess",
            )
            self.assertEqual(
                json.loads((temp_path / "gpu.json").read_text())["job"],
                "mock-gpu-training",
            )
            self.assertEqual(
                json.loads((temp_path / "memory.json").read_text())["job"],
                "mock-high-memory-join",
            )


if __name__ == "__main__":
    unittest.main()
