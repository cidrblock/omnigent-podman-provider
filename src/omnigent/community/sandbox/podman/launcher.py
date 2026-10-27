"""Managed Omnigent hosts in rootless Podman containers.

Uses the Podman CLI rather than a Docker socket. This works with local Fedora
rootless Podman and can use the host's configured Podman machine on macOS.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import time
from contextlib import closing

import click
import keyring
from omnigent.onboarding.sandboxes.base import (
    ExecModelHostLauncher,
    RemoteCommandResult,
    SandboxGoneError,
)
from omnigent.onboarding.sandboxes.types import SandboxCapabilities

from .config import PodmanConfig, is_passthrough_network


_MANAGED_LABEL = "io.omnigent.podman-provider"
_PROFILE_LABEL = "io.omnigent.podman-profile"


def _keyring_label_password(label: str) -> str:
    """Read one GNOME Login item by its visible label, never by a fuzzy match."""
    if sys.platform != "linux":
        raise ValueError("item-label lookup requires Linux Secret Service")
    import secretstorage

    with closing(secretstorage.dbus_init()) as bus:
        collection = secretstorage.get_default_collection(bus)
        if collection.is_locked():
            raise ValueError("Login collection is locked")
        matches = [item for item in collection.get_all_items() if item.get_label() == label]
        if len(matches) != 1:
            raise ValueError("item label must match exactly one Login item")
        item = matches[0]
        if item.is_locked():
            raise ValueError("keyring item is locked")
        return item.get_secret().decode("utf-8")


class PodmanSandboxLauncher(ExecModelHostLauncher):
    """Provision, exec into, resume, and remove managed Podman sandboxes."""

    provider = "podman"

    def __init__(self, *, config: PodmanConfig):
        self.config = config
        self.provider = config.provider_id
        self._key_values: dict[str, str] | None = None

    def _keys(self) -> dict[str, str]:
        """Read each requested credential without exporting it on the host."""
        if self._key_values is not None:
            return self._key_values
        values: dict[str, str] = {}
        for key in self.config.keys:
            try:
                if key.item_label is None:
                    assert key.key_name is not None  # validated by KeyringKey
                value = (
                    _keyring_label_password(key.item_label)
                    if key.item_label is not None
                    else keyring.get_password(key.service, key.key_name)
                )
            except Exception:
                raise click.ClickException(
                    f"Cannot read keyring entry for {key.env_var}"
                ) from None
            if not value or "\x00" in value:
                raise click.ClickException(
                    f"Missing or invalid keyring entry for {key.env_var}"
                )
            values[key.env_var] = value
        self._key_values = values
        return values

    @property
    def capabilities(self) -> SandboxCapabilities:
        return SandboxCapabilities(
            managed_launch=True,
            programmatic_terminate=True,
            resume_stopped=True,
            multi_repo=True,
            git_clone_options=True,
        )

    def _podman(
        self, *args: str, input: str | None = None, timeout: int | None = 30
    ) -> subprocess.CompletedProcess[str]:
        """Run Podman without exposing command contents in its argv or errors."""
        try:
            return subprocess.run(
                [self.config.binary, *args],
                input=input,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise click.ClickException(f"Podman command could not complete ({type(exc).__name__})") from None

    def prepare(self) -> None:
        """Check CLI access, local image, and any named network."""
        if shutil.which(self.config.binary) is None:
            raise click.ClickException(f"Podman CLI not found: {self.config.binary}")
        info = self._podman("info", "--format", "{{.Host.Security.Rootless}}")
        if info.returncode:
            raise click.ClickException("Podman is unavailable; check the local user or Podman machine")
        if self.config.require_rootless and info.stdout.strip().lower() != "true":
            raise click.ClickException("Podman is not running rootless; use a rootless user or Podman machine")
        image = self._podman("image", "exists", self.config.image)
        if image.returncode:
            raise click.ClickException(f"Podman image is unavailable: {self.config.image}")
        if not is_passthrough_network(self.config.network):
            if self._podman("network", "exists", self.config.network).returncode:
                raise click.ClickException(f"Podman network is unavailable: {self.config.network}")
        for mount in self.config.mounts:
            if not mount.source.is_dir() or mount.source.is_symlink():
                raise click.ClickException(f"Podman mount source must be an existing directory: {mount.source}")
        self._keys()

    def provision(self, name: str) -> str:
        """Create a stopped container and boot its long-lived placeholder PID 1."""
        self._keys()
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-.")[:48] or "session"
        container_name = f"omni-{safe_name}-{secrets.token_hex(4)}"
        args = [
            "create", "--name", container_name,
            "--label", f"{_MANAGED_LABEL}=true",
            "--label", f"{_PROFILE_LABEL}={self.provider}",
            "--label", f"io.omnigent.session-name={safe_name}",
            "--network", self.config.network,
        ]
        # The fence is installed by an exec after the container is up, so the
        # process that runs nft needs NET_ADMIN. The sandbox therefore keeps
        # that capability for its lifetime: the fence is an accident guardrail
        # for a trusted agent, not a boundary against a hostile one.
        if self.config.deny_cidrs:
            args.extend(["--cap-add", "NET_ADMIN"])
        args.extend(option for key in self.config.env if key in os.environ for option in ("--env", key))
        for mount in self.config.mounts:
            source = mount.source
            if mount.per_session:
                source = source / container_name
                source.mkdir(mode=0o700)
                source.chmod(0o700)
            options = mount.mode + (f",{mount.relabel}" if mount.relabel else "")
            args.extend(["--volume", f"{source}:{mount.target}:{options}"])
        if self.config.entrypoint:
            args.extend(["--entrypoint", self.config.entrypoint])
        args.extend([self.config.image, "/bin/sh", "-lc", "exec sleep infinity"])
        created = self._podman(*args, timeout=120)
        if created.returncode:
            raise click.ClickException("Podman could not create the managed sandbox")
        container_id = created.stdout.strip()
        if not container_id:
            raise click.ClickException("Podman returned no container ID")
        started = self._podman("start", container_id, timeout=120)
        if started.returncode:
            self._podman("rm", "--force", container_id)
            raise click.ClickException("Podman could not start the managed sandbox")
        deadline = time.monotonic() + self.config.startup_timeout_s
        # The image's entrypoint may first write credentials and Git settings.
        # The final `exec sleep infinity` marks bootstrap completion.
        try:
            while time.monotonic() < deadline:
                ready = self._podman(
                    "exec", container_id, "/bin/sh", "-c",
                    'test "$(cat /proc/1/comm)" = sleep', timeout=10,
                )
                if ready.returncode == 0:
                    if self.config.deny_cidrs:
                        self.run(container_id, self._egress_fence_script())
                    if self.config.bootstrap_command:
                        self.run(container_id, self.config.bootstrap_command)
                    return container_id
                time.sleep(0.5)
        except BaseException:
            self._podman("rm", "--force", container_id)
            raise
        self._podman("rm", "--force", container_id)
        raise click.ClickException("Podman sandbox bootstrap did not complete")

    def _egress_fence_script(self) -> str:
        """Build the nft script that blocks ``deny_cidrs`` inside the sandbox.

        Runs once, from :meth:`provision`, before the image bootstrap and before
        any agent command. The rules live in the container's network namespace,
        so they disappear with the container and cannot leak into the host's.
        Host-loopback mappings from ``network`` are accepted ahead of the drops
        so the Omnigent bridge keeps working while the LAN is fenced off.

        :returns: A POSIX shell script for :meth:`run`.
        """
        table = "inet omnigent_egress"
        lines = [
            "set -eu",
            f"nft add table {table} 2>/dev/null || true",
            f"nft flush table {table}",
            f"nft add chain {table} out '{{ type filter hook output priority 0 ; }}'",
        ]
        for address in self.config.host_loopback_addresses:
            lines.append(f"nft add rule {table} out ip daddr {address} accept")
        for cidr in self.config.deny_cidrs:
            lines.append(f"nft add rule {table} out ip daddr {cidr} drop")
        return "\n".join(lines)

    def run(
        self, sandbox_id: str, command: str, *, check: bool = True
    ) -> RemoteCommandResult:
        """Execute a shell script over stdin, keeping launch tokens out of argv."""
        exports = "".join(
            f"export {name}={shlex.quote(value)}\n" for name, value in self._keys().items()
        )
        result = self._podman(
            "exec", "-i", sandbox_id, "/bin/sh", "-s",
            input=exports + command + "\n", timeout=None,
        )
        completed = RemoteCommandResult(
            returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
        )
        if check and completed.returncode:
            raise click.ClickException(
                f"Podman sandbox command failed (exit {completed.returncode})"
            )
        return completed

    def _owned_state(self, sandbox_id: str) -> bool | None:
        """Return running state, or None if absent; reject non-provider containers."""
        result = self._podman("inspect", "--type", "container", sandbox_id)
        if result.returncode:
            exists = self._podman("container", "exists", sandbox_id)
            if exists.returncode == 1:
                return None
            raise click.ClickException("Podman could not inspect the managed sandbox")
        try:
            details = json.loads(result.stdout)[0]
            if details["Config"]["Labels"].get(_MANAGED_LABEL) != "true":
                raise click.ClickException("Refusing to manage a container without our label")
            if details["Config"]["Labels"].get(_PROFILE_LABEL, "podman") != self.provider:
                raise click.ClickException("Refusing to manage another Podman profile's container")
            return bool(details["State"]["Running"])
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise click.ClickException("Podman returned invalid container metadata") from exc

    def is_running(self, sandbox_id: str) -> bool:
        """Return whether an existing managed container is running."""
        return self._owned_state(sandbox_id) is True

    def resume(self, sandbox_id: str) -> None:
        """Start a stopped container without discarding its writable layer."""
        state = self._owned_state(sandbox_id)
        if state is None:
            raise SandboxGoneError("Managed Podman sandbox no longer exists")
        if not state and self._podman("start", sandbox_id, timeout=120).returncode:
            raise click.ClickException("Podman could not resume the managed sandbox")

    def terminate(self, sandbox_id: str) -> None:
        """Remove an owned container; an already-removed container is fine."""
        if self._owned_state(sandbox_id) is None:
            return
        if self._podman("rm", "--force", sandbox_id, timeout=120).returncode:
            raise click.ClickException("Podman could not remove the managed sandbox")
