"""Contract tests for the managed Podman lifecycle and secret-safe exec path."""

import os
import json
import subprocess
import sys
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

from omnigent.community.sandbox.podman.config import BindMount, PodmanConfig
from omnigent.community.sandbox.podman.config import profile_config_model
from omnigent.community.sandbox.podman.launcher import PodmanSandboxLauncher
from omnigent.community.sandbox.podman.launcher import _keyring_label_password
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

    def test_configured_aliases_have_independent_launcher_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text("""sandbox:
  providers:
    - provider: podman-python
      podman-python: {image: localhost/python:latest}
    - provider: podman-node
      podman-node: {image: localhost/node:latest}
    - provider: microsandbox
""")
            with patch.dict(os.environ, {"OMNIGENT_CONFIG": str(config_path)}):
                providers = get_contribution().providers
            self.assertEqual(set(providers), {"podman", "podman-python", "podman-node"})
            for alias in ("podman-python", "podman-node"):
                metadata = providers[alias]
                self.assertEqual(metadata.config_model.__module__, "omnigent.community.sandbox.podman.config")
                config = metadata.config_model(image="example")
                self.assertEqual(PodmanSandboxLauncher(config=config).provider, alias)
                with self.assertRaises(ValidationError):
                    metadata.config_model(image="example", provider_id="podman")

    def test_profile_registration_rejects_duplicate_names(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text("sandbox:\n  providers:\n    - provider: podman-python\n    - provider: podman-python\n")
            with patch.dict(os.environ, {"OMNIGENT_CONFIG": str(config_path)}):
                with self.assertRaisesRegex(ValueError, "duplicate Podman profile"):
                    get_contribution()

    def test_aliases_resolve_through_omnigent_deployment_parser(self):
        import yaml
        from omnigent.onboarding.sandboxes import registry
        from omnigent.server.managed_hosts import parse_sandbox_config

        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.yaml"
            config_path.write_text("""sandbox:
  providers:
    - provider: podman-python
      server_url: http://127.0.0.1:6767
      podman-python: {image: localhost/python:test}
    - provider: podman-node
      server_url: http://127.0.0.1:6767
      podman-node: {image: localhost/node:test}
""")
            with patch.dict(os.environ, {"OMNIGENT_CONFIG": str(config_path)}):
                registry.reset_plugin_state_for_tests()
                try:
                    deployment = parse_sandbox_config(yaml.safe_load(config_path.read_text())["sandbox"])
                    self.assertEqual(deployment.launchable_providers(), ("podman-python", "podman-node"))
                    for alias in deployment.launchable_providers():
                        self.assertEqual(deployment.for_provider(alias).launcher_factory().provider, alias)
                finally:
                    registry.reset_plugin_state_for_tests()

    def test_config_rejects_values_disguised_as_env_names(self):
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", env=["GH_TOKEN=secret"])
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", env=["GH_TOKEN", "GH_TOKEN"])

    def test_keyring_config_rejects_duplicate_or_persisted_env_names(self):
        key = {"key_name": "enmaas", "env_var": "ENMAAS_KEY"}
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", keys=[{"env_var": "SAMPLE_KEY"}])
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", keys=[{**key, "env_var": "BAD=VALUE"}])
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", keys=[key, key])
        with self.assertRaises(ValidationError):
            PodmanConfig(image="test", env=["ENMAAS_KEY"], keys=[key])

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
    @patch("omnigent.community.sandbox.podman.launcher.keyring.get_password")
    def test_keyring_secret_is_shell_quoted_over_stdin_only(self, get_password, run):
        secret = "a'$(touch /tmp/not-executed)"
        get_password.return_value = secret
        run.return_value = completed([], stdout="ok")
        launcher = PodmanSandboxLauncher(config=PodmanConfig(
            image="test", keys=[{"service": "work", "key_name": "api", "env_var": "WORK_API_KEY"}]
        ))
        with patch.dict("omnigent.community.sandbox.podman.launcher.os.environ", {}, clear=True):
            self.assertEqual(launcher.run("container-id", 'printf %s "$WORK_API_KEY"').stdout, "ok")
            self.assertNotIn("WORK_API_KEY", os.environ)
        get_password.assert_called_once_with("work", "api")
        args = run.call_args.args[0]
        script = run.call_args.kwargs["input"]
        self.assertNotIn(secret, str(args))
        self.assertNotIn(secret, script)
        self.assertIn("export WORK_API_KEY=", script)
        self.assertIn("'\"'\"'", script)

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    @patch("omnigent.community.sandbox.podman.launcher.keyring.get_password", return_value=None)
    def test_missing_key_fails_before_container_creation(self, _get_password, run):
        launcher = PodmanSandboxLauncher(config=PodmanConfig(
            image="test", keys=[{"key_name": "missing", "env_var": "MISSING_KEY"}]
        ))
        with self.assertRaisesRegex(click.ClickException, "Missing or invalid keyring entry"):
            launcher.provision("session")
        run.assert_not_called()

    @patch("omnigent.community.sandbox.podman.launcher.keyring.get_password", side_effect=RuntimeError("private backend detail"))
    def test_keyring_backend_errors_do_not_expose_backend_details(self, _get_password):
        launcher = PodmanSandboxLauncher(config=PodmanConfig(
            image="test", keys=[{"service": "work", "key_name": "api", "env_var": "WORK_KEY"}]
        ))
        with self.assertRaises(click.ClickException) as failure:
            launcher.provision("session")
        self.assertNotIn("private backend detail", str(failure.exception))

    @patch("omnigent.community.sandbox.podman.launcher._keyring_label_password", return_value="label-secret")
    @patch("omnigent.community.sandbox.podman.launcher.keyring.get_password")
    def test_visible_label_uses_secret_service_instead_of_service_attributes(self, get_password, lookup):
        launcher = PodmanSandboxLauncher(config=PodmanConfig(
            image="test", keys=[{"env_var": "SAMPLE_KEY", "item_label": "Sample secret"}]
        ))
        self.assertEqual(launcher._keys()["SAMPLE_KEY"], "label-secret")
        lookup.assert_called_once_with("Sample secret")
        get_password.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "Secret Service labels are Linux-only")
    def test_visible_label_rejects_multiple_matches(self):
        from unittest.mock import Mock
        from omnigent.community.sandbox.podman.launcher import _keyring_description_password

        items = []
        for _ in range(2):
            item = Mock()
            item.get_label.return_value = "duplicate"
            items.append(item)
        collection = Mock()
        collection.get_label.return_value = "Agents"
        collection.is_locked.return_value = False
        collection.get_all_items.return_value = items
        secretstorage = Mock()
        secretstorage.dbus_init.return_value = Mock(close=Mock())
        secretstorage.get_all_collections.return_value = [collection]
        with patch.dict("sys.modules", {"secretstorage": secretstorage}), self.assertRaisesRegex(
            ValueError, "ambiguous"
        ):
            _keyring_description_password("duplicate", "Agents")

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
    def test_alias_container_records_identity_and_rejects_cross_profile_cleanup(self, run):
        config = profile_config_model("podman-python")(image="example")
        launcher = PodmanSandboxLauncher(config=config)
        run.side_effect = [completed([], stdout="container-id"), completed([]), completed([])]
        launcher.provision("session")
        create = run.call_args_list[0].args[0]
        self.assertIn("io.omnigent.podman-profile=podman-python", create)
        run.reset_mock(side_effect=True)
        run.return_value = completed([], stdout=json.dumps([{"Config": {"Labels": {
            "io.omnigent.podman-provider": "true", "io.omnigent.podman-profile": "podman-node"
        }}, "State": {"Running": True}}]))
        with self.assertRaisesRegex(click.ClickException, "another Podman profile"):
            launcher.terminate("container-id")
        self.assertEqual(run.call_count, 1)

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    @patch("omnigent.community.sandbox.podman.launcher.keyring.get_password", return_value="host-secret")
    def test_bootstrap_receives_key_without_storing_it_in_podman_config(self, _get_password, run):
        launcher = PodmanSandboxLauncher(config=PodmanConfig(
            image="test", keys=[{"key_name": "enmaas", "env_var": "ENMAAS_KEY"}],
            bootstrap_command="/usr/local/bin/omnigent-guest-init /bin/true",
        ))
        run.side_effect = [completed([], stdout="container-id"), completed([]),
                           completed([]), completed([])]
        launcher.provision("session")
        create = run.call_args_list[0].args[0]
        # The value never reaches podman create; the *name* may appear once, in
        # the derived OMNIGENT_RUNNER_ENV_PASSTHROUGH line, so the harness can
        # still inherit it.
        self.assertNotIn("host-secret", str(create))
        env_args = [create[i + 1] for i, a in enumerate(create) if a == "--env"]
        self.assertEqual(env_args, ["OMNIGENT_RUNNER_ENV_PASSTHROUGH=ENMAAS_KEY"])
        bootstrap = run.call_args_list[3]
        self.assertEqual(bootstrap.args[0][1:3], ["exec", "-i"])
        self.assertIn("export ENMAAS_KEY=host-secret", bootstrap.kwargs["input"])
        self.assertIn("omnigent-guest-init /bin/true", bootstrap.kwargs["input"])

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

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_pasta_network_with_options_skips_named_network_lookup(self, run):
        """A ``pasta:…`` value is a mode plus options, not a named network."""
        config = PodmanConfig(
            image="example", network="pasta:--map-host-loopback=169.254.170.2"
        )
        launcher = PodmanSandboxLauncher(config=config)
        run.side_effect = [completed([], stdout="true"), completed([])]
        launcher.prepare()
        self.assertNotIn("network", run.call_args_list[1].args[0][1:2])
        self.assertEqual(run.call_args_list[1].args[0][1:3], ["image", "exists"])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_unknown_named_network_still_fails(self, run):
        launcher = PodmanSandboxLauncher(config=PodmanConfig(image="example", network="mynet"))
        run.side_effect = [completed([], stdout="true"), completed([]), completed([], code=1)]
        with self.assertRaisesRegex(click.ClickException, "network is unavailable"):
            launcher.prepare()

    def test_deny_cidrs_requires_a_private_netns_mode(self):
        with self.assertRaisesRegex(ValidationError, "requires network"):
            PodmanConfig(image="example", deny_cidrs=["192.168.0.0/24"])

    def test_deny_cidrs_rejects_shell_metacharacters(self):
        for bad in ["192.168.0.0/24 ; rm -rf /", "$(id)", "192.168.0.0/33", "1.2.3.999"]:
            with self.assertRaisesRegex(ValidationError, "deny_cidrs"):
                PodmanConfig(
                    image="example", network="pasta", deny_cidrs=[bad]
                )

    def test_host_loopback_addresses_are_parsed_from_the_network_string(self):
        config = PodmanConfig(
            image="example",
            network="pasta:--map-host-loopback=169.254.170.2 --map-host-loopback=169.254.170.3",
        )
        self.assertEqual(
            config.host_loopback_addresses, ["169.254.170.2", "169.254.170.3"]
        )
        self.assertEqual(PodmanConfig(image="example", network="pasta").host_loopback_addresses, [])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_fence_is_installed_before_the_bootstrap_command(self, run):
        config = PodmanConfig(
            image="example",
            network="pasta:--map-host-loopback=169.254.170.2",
            deny_cidrs=["192.168.0.0/24"],
            bootstrap_command="/usr/local/bin/omnigent-guest-init /bin/true",
        )
        launcher = PodmanSandboxLauncher(config=config)
        run.side_effect = [
            completed([], stdout="container-id"),
            completed([]),  # start
            completed([], stdout="sleep"),  # readiness probe
            completed([]),  # fence
            completed([]),  # bootstrap
        ]
        launcher.provision("session")
        create = run.call_args_list[0].args[0]
        self.assertIn("--cap-add", create)
        self.assertEqual(create[create.index("--cap-add") + 1], "NET_ADMIN")
        fence_call, bootstrap_call = run.call_args_list[3], run.call_args_list[4]
        self.assertIn("nft add rule inet omnigent_egress out ip daddr 169.254.170.2 accept", fence_call.kwargs["input"])
        self.assertIn("nft add rule inet omnigent_egress out ip daddr 192.168.0.0/24 drop", fence_call.kwargs["input"])
        self.assertIn("omnigent-guest-init", bootstrap_call.kwargs["input"])

    def test_cap_add_is_allowlisted(self):
        for bad in ["SYS_ADMIN", "ALL", "net_admin"]:
            with self.assertRaisesRegex(ValidationError, "cap_add"):
                PodmanConfig(image="example", cap_add=[bad])
        self.assertEqual(PodmanConfig(image="example", cap_add=["NET_ADMIN"]).cap_add, ["NET_ADMIN"])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_cap_add_reaches_create(self, run):
        launcher = PodmanSandboxLauncher(
            config=PodmanConfig(image="example", network="pasta", cap_add=["NET_ADMIN"])
        )
        run.side_effect = [
            completed([], stdout="container-id"), completed([]), completed([], stdout="sleep")
        ]
        launcher.provision("session")
        create = run.call_args_list[0].args[0]
        self.assertEqual(create[create.index("--cap-add") + 1], "NET_ADMIN")
        self.assertEqual(create.count("--cap-add"), 1)

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_run_execs_as_runtime_user_unless_root_is_requested(self, run):
        launcher = PodmanSandboxLauncher(
            config=PodmanConfig(image="example", runtime_user="agent", runtime_home="/root")
        )
        run.return_value = completed([], stdout="")
        launcher.run("container-id", "true")
        unprivileged = run.call_args_list[0].args[0]
        self.assertEqual(unprivileged[1:5], ["exec", "-i", "--user", "agent"])
        self.assertIn("HOME=/root", unprivileged)
        run.reset_mock()
        launcher.run("container-id", "true", as_root=True)
        self.assertEqual(run.call_args_list[0].args[0][1:5], ["exec", "-i", "--user", "root"])

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_fence_install_stays_root_when_a_runtime_user_is_set(self, run):
        config = PodmanConfig(
            image="example",
            network="pasta:--map-host-loopback=169.254.170.2",
            deny_cidrs=["192.168.0.0/24"],
            runtime_user="agent",
        )
        launcher = PodmanSandboxLauncher(config=config)
        run.side_effect = [
            completed([], stdout="container-id"), completed([]),
            completed([], stdout="sleep"), completed([]),
        ]
        launcher.provision("session")
        fence = run.call_args_list[3].args[0]
        self.assertIn("root", fence)
        self.assertNotIn("agent", fence)

    def test_annotations_must_be_plain_dotted_keys(self):
        with self.assertRaisesRegex(ValidationError, "annotation name"):
            PodmanConfig(image="example", annotations={"bad key": "true"})
        config = PodmanConfig(image="example", annotations={"apply-firewall": "true"})
        self.assertEqual(config.annotations, {"apply-firewall": "true"})

    def test_cap_drop_is_allowlisted(self):
        with self.assertRaisesRegex(ValidationError, "cap_drop"):
            PodmanConfig(image="example", cap_drop=["SYS_ADMIN"])
        self.assertEqual(
            PodmanConfig(image="example", cap_drop=["NET_ADMIN", "NET_RAW"]).cap_drop,
            ["NET_ADMIN", "NET_RAW"],
        )

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_annotations_and_cap_drop_reach_create(self, run):
        launcher = PodmanSandboxLauncher(
            config=PodmanConfig(
                image="example",
                network="pasta",
                annotations={"apply-firewall": "true"},
                cap_drop=["NET_ADMIN", "NET_RAW"],
            )
        )
        run.side_effect = [
            completed([], stdout="container-id"), completed([]), completed([], stdout="sleep")
        ]
        launcher.provision("session")
        create = run.call_args_list[0].args[0]
        self.assertEqual(create[create.index("--annotation") + 1], "apply-firewall=true")
        drops = [create[i + 1] for i, arg in enumerate(create) if arg == "--cap-drop"]
        self.assertEqual(drops, ["NET_ADMIN", "NET_RAW"])

    def test_environment_literals_are_validated(self):
        with self.assertRaisesRegex(ValidationError, "environment key"):
            PodmanConfig(image="example", environment={"bad key": "x"})
        config = PodmanConfig(
            image="example", environment={"OMNIGENT_CONFIG_HOME": "/opt/provider"}
        )
        self.assertEqual(config.environment["OMNIGENT_CONFIG_HOME"], "/opt/provider")

    @patch("omnigent.community.sandbox.podman.launcher.subprocess.run")
    def test_environment_literals_reach_create(self, run):
        launcher = PodmanSandboxLauncher(
            config=PodmanConfig(
                image="example",
                network="pasta",
                environment={"OMNIGENT_CONFIG_HOME": "/opt/provider"},
            )
        )
        run.side_effect = [
            completed([], stdout="container-id"), completed([]), completed([], stdout="sleep")
        ]
        launcher.provision("session")
        create = run.call_args_list[0].args[0]
        self.assertIn("OMNIGENT_CONFIG_HOME=/opt/provider", create)

    def test_mount_source_may_be_a_file(self):
        with tempfile.TemporaryDirectory() as directory:
            host_file = Path(directory) / "AGENTS.md"
            host_file.write_text("instructions\n")
            config = PodmanConfig(
                image="example",
                network="pasta",
                mounts=[{"source": str(host_file), "target": "/root/workspace/AGENTS.md", "mode": "ro"}],
            )
            launcher = PodmanSandboxLauncher(config=config)
            with patch(
                "omnigent.community.sandbox.podman.launcher.subprocess.run"
            ) as run:
                run.side_effect = [completed([], stdout="true"), completed([])]
                launcher.prepare()  # must not reject a file source
            self.assertTrue(config.mounts[0].source.is_file())

    def test_per_session_mount_must_be_a_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            host_file = Path(directory) / "AGENTS.md"
            host_file.write_text("x\n")
            with self.assertRaisesRegex(ValidationError, "must be directories"):
                BindMount(source=host_file, target="/root/x", mode="rw", per_session=True)

    def test_runner_passthrough_is_derived_from_env_and_keys(self):
        config = PodmanConfig(
            image="example",
            network="pasta",
            keys=[{"item_label": "EnMaas key", "env_var": "GOOSE_PROVIDER__API_KEY"}],
            environment={
                "GOOSE_PROVIDER__TYPE": "openai",
                "GOOSE_MODEL": "rits/deepseek-ai/DeepSeek-V4.1-Flash-1017",
                "OMNIGENT_RUNNER_ENV_PASSTHROUGH": "GH_TOKEN",
            },
        )
        passthrough = config.resolved_environment["OMNIGENT_RUNNER_ENV_PASSTHROUGH"].split(",")
        self.assertEqual(passthrough[0], "GH_TOKEN")  # explicit value keeps its place
        self.assertIn("GOOSE_PROVIDER__API_KEY", passthrough)
        self.assertIn("GOOSE_PROVIDER__TYPE", passthrough)
        self.assertIn("GOOSE_MODEL", passthrough)
        self.assertNotIn("OMNIGENT_RUNNER_ENV_PASSTHROUGH", passthrough)

    def test_runner_passthrough_includes_env_names(self):
        config = PodmanConfig(image="example", network="pasta", env=["JIRA_USERNAME", "GH_TOKEN"])
        passthrough = config.resolved_environment["OMNIGENT_RUNNER_ENV_PASSTHROUGH"].split(",")
        self.assertIn("JIRA_USERNAME", passthrough)
        self.assertIn("GH_TOKEN", passthrough)

    def test_no_passthrough_when_nothing_to_forward(self):
        config = PodmanConfig(image="example", network="pasta")
        self.assertNotIn("OMNIGENT_RUNNER_ENV_PASSTHROUGH", config.resolved_environment)

    def test_keyring_key_accepts_collection_and_description(self):
        config = PodmanConfig(
            image="example",
            keys=[{"env_var": "OPENAI_API_KEY", "keyring": "Agents", "description": "foo"}],
        )
        key = config.keys[0]
        self.assertEqual((key.keyring, key.description), ("Agents", "foo"))

    def test_keyring_without_description_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, "requires a description"):
            PodmanConfig(image="example", keys=[{"env_var": "X", "keyring": "Agents"}])

    def _fake_secretstorage(self, label, items, locked=False):
        """Build a patched secretstorage module: one collection, given items."""
        from unittest.mock import Mock, patch

        collection = Mock()
        collection.get_label.return_value = label
        collection.is_locked.return_value = locked
        collection.get_all_items.return_value = items
        secretstorage = Mock()
        secretstorage.dbus_init.return_value = Mock(close=Mock())
        secretstorage.get_all_collections.return_value = [collection]
        return patch.dict("sys.modules", {"secretstorage": secretstorage}), secretstorage

    def test_description_lookup_reads_the_matching_item(self):
        from unittest.mock import Mock
        from omnigent.community.sandbox.podman.launcher import _keyring_description_password

        item = Mock()
        item.get_label.return_value = "foo"
        item.is_locked.return_value = False
        item.get_secret.return_value = b"bar"
        patcher, _ = self._fake_secretstorage("Agents", [item])
        with patcher:
            self.assertEqual(_keyring_description_password("foo", "Agents"), "bar")

    def test_description_lookup_skips_stale_items(self):
        from unittest.mock import Mock
        from omnigent.community.sandbox.podman.launcher import _keyring_description_password

        stale, good = Mock(), Mock()
        stale.get_label.side_effect = Exception("Item does not exist")
        good.get_label.return_value = "foo"
        good.is_locked.return_value = False
        good.get_secret.return_value = b"bar"
        patcher, _ = self._fake_secretstorage("Login", [stale, good])
        with patcher:
            self.assertEqual(_keyring_description_password("foo", "Login"), "bar")

    def test_description_lookup_reports_locked_and_missing(self):
        from unittest.mock import Mock
        from omnigent.community.sandbox.podman.launcher import _keyring_description_password

        patcher, _ = self._fake_secretstorage("Agents", [], locked=True)
        with patcher, self.assertRaisesRegex(ValueError, "is locked"):
            _keyring_description_password("foo", "Agents")
        patcher, _ = self._fake_secretstorage("Agents", [])
        with patcher, self.assertRaisesRegex(ValueError, "no keyring item labelled"):
            _keyring_description_password("foo", "Agents")

    def test_no_fence_or_capability_change_without_deny_cidrs(self):
        launcher = PodmanSandboxLauncher(
            config=PodmanConfig(image="example", network="pasta")
        )
        self.assertEqual(launcher._egress_fence_script().count("drop"), 0)



if __name__ == "__main__":
    unittest.main()
