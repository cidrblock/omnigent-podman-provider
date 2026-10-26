"""Contract tests for the managed Podman lifecycle and secret-safe exec path."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import click
from omnigent.community import sandbox as sandbox_namespace
from omnigent.onboarding.sandboxes.base import SandboxGoneError
from pydantic import ValidationError

# The host may already have an older wheel installed. Exercise this checkout's
# source first without replacing the running Omnigent service's plugin.
sandbox_namespace.__path__.insert(
    0, str(Path(__file__).resolve().parents[1] / "src/omnigent/community/sandbox")
)

from omnigent.community.sandbox.podman.config import PodmanConfig
from omnigent.community.sandbox.podman.launcher import PodmanSandboxLauncher
from omnigent.community.sandbox.podman.plugin import get_contribution


def completed(args, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args, code, stdout, stderr)


class PodmanLauncherTests(unittest.TestCase):
    def setUp(self):
        self.launcher = PodmanSandboxLauncher(
            config=PodmanConfig(image="localhost/omnigent-host:test", env=["GH_TOKEN"])
        )

    def test_contribution_uses_current_registry_contract(self):
        contribution = get_contribution()
        metadata = contribution.providers["podman"]
        self.assertIs(metadata.config_model, PodmanConfig)
        self.assertTrue(self.launcher.capabilities.managed_launch)
        self.assertTrue(self.launcher.capabilities.resume_stopped)
        self.assertTrue(self.launcher.capabilities.git_clone_options)

    def test_config_rejects_values_disguised_as_env_names(self):
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", env=["GH_TOKEN=secret"])
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", env=["GH_TOKEN", "GH_TOKEN"])

    def test_mounts_require_absolute_nonoverlapping_paths(self):
        for source, target in (("relative", "/root/scratch"), ("/tmp/one", "../scratch"),
                               ("/tmp/one:rw", "/root/scratch")):
            with self.subTest(source=source, target=target), self.assertRaises(ValidationError):
                PodmanConfig(image="test", mounts=[{"source": source, "target": target}])
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", mounts=[{"source": "/tmp/one", "target": "/root/scratch",
                                                 "per_session": True}])
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", mounts=[
                {"source": "/tmp/one", "target": "/root/.agents/skills"},
                {"source": "/tmp/two", "target": "/root/.agents/skills/live"},
            ])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    @patch("omnigent.community.sandbox.podman.launcher.secrets.token_hex", return_value="aabbccdd")
    def test_mounts_are_scoped_and_per_session_scratch_persists(self, _token, run):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skills = root / "live-skills"
            scratch = root / "scratch"
            skills.mkdir()
            scratch.mkdir()
            launcher = PodmanSandboxLauncher(config=PodmanConfig(image="test", mounts=[
                {"source": skills, "target": "/root/.agents/skills/live", "mode": "ro", "relabel": "z"},
                {"source": scratch, "target": "/root/scratch", "mode": "rw", "relabel": "Z",
                 "per_session": True},
            ]))
            run.side_effect = [completed([], stdout="container-id"), completed([]), completed([])]
            launcher.provision("session")
            create = run.call_args_list[0].args[0]
            volumes = [create[index + 1] for index, item in enumerate(create) if item == "--volume"]
            self.assertEqual(volumes, [
                f"{skills}:/root/.agents/skills/live:ro,z",
                f"{scratch / 'omni-session-aabbccdd'}:/root/scratch:rw,Z",
            ])
            self.assertTrue((scratch / "omni-session-aabbccdd").is_dir())
            self.assertEqual((scratch / "omni-session-aabbccdd").stat().st_mode & 0o777, 0o700)

    @patch("omnigent.community.sandbox.podman.launcher.shutil.which", return_value="/usr/bin/podman")
    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_prepare_rejects_rootful_podman(self, run, _which):
        run.return_value = completed([], stdout="false\n")
        with self.assertRaisesRegex(click.ClickException, "not running rootless"):
            self.launcher.prepare()
        self.assertEqual(run.call_count, 1)

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_exec_keeps_host_launch_token_out_of_argv_and_errors(self, run):
        run.return_value = completed([], code=7, stderr="private diagnostic")
        token = "launch-token-sample"
        with self.assertRaisesRegex(click.ClickException, "exit 7") as failure:
            self.launcher.run("container-id", f"OMNIGENT_HOST_TOKEN={token} omnigent host")
        args = run.call_args.args[0]
        self.assertEqual(args, ["podman", "exec", "-i", "container-id", "/bin/sh", "-s"])
        self.assertIn(token, run.call_args.kwargs["input"])
        self.assertNotIn(token, str(args) + str(failure.exception))

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    @patch("omnigent.community.sandbox.podman.launcher.os.environ", {"GH_TOKEN": "sample-secret"})
    def test_provision_forwards_only_env_names_and_starts(self, run):
        run.side_effect = [completed([], stdout="container-id\n"), completed([]), completed([])]
        self.assertEqual(self.launcher.provision("an example"), "container-id")
        create = run.call_args_list[0].args[0]
        self.assertEqual(create[0:2], ["podman", "create"])
        self.assertIn("--network", create)
        self.assertIn("host", create)
        self.assertIn("--env", create)
        self.assertIn("GH_TOKEN", create)
        self.assertNotIn("sample-secret", str(create))
        self.assertNotIn("--entrypoint", create)
        self.assertEqual(run.call_args_list[1].args[0], ["podman", "start", "container-id"])
        self.assertEqual(run.call_args_list[2].args[0][1:3], ["exec", "container-id"])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_start_failure_cleans_up(self, run):
        run.side_effect = [completed([], stdout="container-id"), completed([], code=1), completed([])]
        with self.assertRaisesRegex(click.ClickException, "could not start"):
            self.launcher.provision("session")
        self.assertEqual(run.call_args_list[2].args[0], ["podman", "rm", "--force", "container-id"])

    @patch("omnigent.community.sandbox.podman.launcher.time.sleep")
    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_provision_waits_for_guest_bootstrap(self, run, _sleep):
        run.side_effect = [
            completed([], stdout="container-id"), completed([]),
            completed([], code=1), completed([]),
        ]
        self.assertEqual(self.launcher.provision("session"), "container-id")
        self.assertEqual(run.call_args_list[2].args[0][1:3], ["exec", "container-id"])
        self.assertEqual(run.call_args_list[3].args[0][1:3], ["exec", "container-id"])

    @patch("omnigent.community.sandbox.podman.launcher.time.sleep")
    @patch("omnigent.community.sandbox.podman.launcher.time.monotonic", side_effect=[0, 0, 2])
    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_bootstrap_timeout_removes_container(self, run, _clock, _sleep):
        launcher = PodmanSandboxLauncher(config=PodmanConfig(image="test", startup_timeout_s=1))
        run.side_effect = [
            completed([], stdout="container-id"), completed([]),
            completed([], code=1), completed([]),
        ]
        with self.assertRaisesRegex(click.ClickException, "bootstrap did not complete"):
            launcher.provision("session")
        self.assertEqual(run.call_args_list[3].args[0], ["podman", "rm", "--force", "container-id"])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_terminate_refuses_unowned_container(self, run):
        run.return_value = completed([], stdout='[{"Config":{"Labels":{}},"State":{"Running":true}}]')
        with self.assertRaisesRegex(click.ClickException, "without our label"):
            self.launcher.terminate("unowned")
        self.assertEqual(run.call_count, 1)

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_resume_stopped_container(self, run):
        run.side_effect = [
            completed([], stdout='[{"Config":{"Labels":{"io.omnigent.podman-provider":"true"}},"State":{"Running":false}}]'),
            completed([]),
        ]
        self.launcher.resume("container-id")
        self.assertEqual(run.call_args_list[1].args[0], ["podman", "start", "container-id"])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_missing_container_is_gone_on_resume_and_noop_on_terminate(self, run):
        run.side_effect = [completed([], code=125), completed([], code=1)]
        with self.assertRaises(SandboxGoneError):
            self.launcher.resume("missing")
        run.reset_mock(side_effect=True)
        run.side_effect = [completed([], code=125), completed([], code=1)]
        self.launcher.terminate("missing")

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_socket_failure_is_not_misclassified_as_missing_container(self, run):
        run.side_effect = [completed([], code=125), completed([], code=125)]
        with self.assertRaisesRegex(click.ClickException, "could not inspect"):
            self.launcher.resume("container-id")


if __name__ == "__main__":
    unittest.main()
