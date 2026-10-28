"""Managed Omnigent hosts in rootless Podman containers.

Uses the Podman CLI rather than a Docker socket. This works with local Fedora
rootless Podman and can use the host's configured Podman machine on macOS.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

import click
import keyring
from omnigent.onboarding.sandboxes.base import (
    ExecModelHostLauncher,
    RemoteCommandResult,
    SandboxGoneError,
)
from omnigent.onboarding.sandboxes.types import SandboxCapabilities

from .config import PodmanConfig, is_passthrough_network


_LOGGER = logging.getLogger(__name__)

#: Annotation carrying the generated egress ruleset to the OCI hook, so the
#: hook applies exactly the policy the provider rendered (and the same file is
#: re-applied after a resume).
EGRESS_RULESET_ANNOTATION = "omnigent-egress-ruleset"

_MANAGED_LABEL = "io.omnigent.podman-provider"
_PROFILE_LABEL = "io.omnigent.podman-profile"

#: Upper bound on the Podman output quoted back in a user-facing error. Enough
#: to identify the failing path or capability, short enough to stay readable in
#: the session banner.
_MAX_DETAIL_CHARS = 500


def _redact(text: str, secrets_to_hide: list[str]) -> str:
    """Remove known credential values from Podman output.

    Podman echoes parts of its own command line in some failures (an invalid
    ``--env`` value, a bad volume spec), so the detail that makes an error
    diagnosable is exactly the detail that can leak a secret. Every value the
    provider injects is scrubbed before the text is returned.
    """
    for secret in secrets_to_hide:
        if secret:
            text = text.replace(secret, "***")
    return text


def _error_detail(
    result: subprocess.CompletedProcess[str], secrets_to_hide: list[str]
) -> str:
    """Condense a failed Podman invocation's stderr into one diagnosable clause.

    Podman prints its reason on the last stderr line and may precede it with
    warnings; keeping the tail preserves the reason. Returns an empty string
    when Podman said nothing, so callers can fall back to a plain message.
    """
    lines = [line.strip() for line in (result.stderr or "").splitlines() if line.strip()]
    if not lines:
        return ""
    detail = _redact(" ".join(lines[-3:]), secrets_to_hide)
    if len(detail) > _MAX_DETAIL_CHARS:
        detail = detail[:_MAX_DETAIL_CHARS] + "…"
    return detail


#: How many directories ``prepare()`` inspects inside a mount source before it
#: stops looking. Rootless crun opens the bind source tree, so an unsearchable
#: directory below a readable one still fails the launch — but the scan must not
#: walk a large ``agent_work`` tree on every launch.
_MOUNT_SCAN_LIMIT = 1000


def _unsearchable_entry(source: Path) -> str | None:
    """Describe the first directory under ``source`` this user cannot traverse.

    A mount source that *is* readable is not enough: with ``:z`` relabelling
    Podman walks the tree, and rootless crun opens each directory it meets. A
    directory owned by another user (a stray ``root:root`` 0700 entry created by
    a tool run under ``sudo``) then fails the container start with nothing but
    ``open <path>: permission denied`` on stderr — and the launch error the user
    sees names no path at all.

    Only directory *search* permission is checked, because that is what blocks
    resolution; a file's own mode is irrelevant to a bind mount. Symlinks are
    skipped: ``os.access`` follows them, so a dangling link inside a source
    (harmless here) would otherwise report the whole mount as broken.

    :param source: Bind-mount source validated as an existing path.
    :returns: ``"<path> (mode 0o700, uid 0)"`` for the first bad directory, or
        ``None`` when every directory is traversable.
    """
    if not source.is_dir():
        return None
    pending = [source]
    seen = 0
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    seen += 1
                    if seen > _MOUNT_SCAN_LIMIT:
                        return None
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                    if os.access(entry.path, os.X_OK):
                        pending.append(Path(entry.path))
                        continue
                    try:
                        mode = entry.stat(follow_symlinks=False).st_mode & 0o7777
                        owner = entry.stat(follow_symlinks=False).st_uid
                    except OSError:  # pragma: no cover - raced or unreadable parent
                        return str(entry.path)
                    return f"{entry.path} (mode 0o{mode:o}, uid {owner})"
        except OSError:
            # The source itself cannot be listed; prepare() already rejected a
            # missing source, so treat this as unreadable rather than crashing.
            return str(directory)
    return None


def _secret_service_items(bus: object, collection_label: str | None) -> list[object]:
    """Return the items of one Secret Service collection (or of every one).

    Enumeration is defensive on purpose: a collection can hold a *stale* item
    path (the item was deleted while the collection index still listed it), and
    ``get_all_items()`` then raises ``ItemNotFoundException`` for that entry,
    aborting the whole scan. That made every label lookup in the Login
    collection fail once, because a single vanished item sat ahead of the one
    being looked for. Skip the bad entries, keep the good ones.

    :param bus: Open Secret Service bus from ``secretstorage.dbus_init()``.
    :param collection_label: Exact collection label to search (e.g. ``"Agents"``),
        or ``None`` to search every collection.
    :returns: Items from the matching, unlocked collections.
    :raises ValueError: When a named collection is missing or locked.
    """
    import secretstorage

    all_collections = list(secretstorage.get_all_collections(bus))
    if collection_label is None:
        collections = all_collections
    else:
        collections = [c for c in all_collections if c.get_label() == collection_label]
        if not collections:
            raise ValueError(f"no keyring collection named {collection_label!r}")
    items: list[object] = []
    for collection in collections:
        if collection.is_locked():
            if collection_label is None:
                continue
            raise ValueError(
                f"keyring collection {collection_label!r} is locked; unlock it and retry"
            )
        try:
            candidates = list(collection.get_all_items())
        except Exception:  # noqa: BLE001 — index unreadable: skip this collection
            continue
        for item in candidates:
            try:
                item.get_label()
            except Exception:  # noqa: BLE001 — stale item path
                continue
            items.append(item)
    return items


def _keyring_description_password(description: str, collection_label: str | None = None) -> str:
    """Read one item by its visible label, optionally inside a named collection.

    :param description: The item's label, matched exactly, e.g. ``"app"``.
    :param collection_label: Collection to search (e.g. ``"Agents"``); ``None``
        searches every unlocked collection.
    :returns: The stored secret as text.
    :raises ValueError: Missing/locked collection, no match, or several matches.
    """
    if sys.platform != "linux":
        raise ValueError("keyring lookups require Linux Secret Service")
    import secretstorage

    with closing(secretstorage.dbus_init()) as bus:
        matches = []
        for item in _secret_service_items(bus, collection_label):
            try:
                if item.get_label() == description:
                    matches.append(item)
            except Exception:  # noqa: BLE001 — stale item path
                continue
        where = f"collection {collection_label!r}" if collection_label else "any collection"
        if not matches:
            raise ValueError(f"no keyring item labelled {description!r} in {where}")
        if len(matches) != 1:
            raise ValueError(
                f"keyring item label {description!r} is ambiguous ({len(matches)} matches)"
            )
        item = matches[0]
        if item.is_locked():
            raise ValueError(f"keyring item {description!r} is locked")
        return item.get_secret().decode("utf-8")


def _keyring_label_password(label: str) -> str:
    """Read one item by label from any unlocked collection (legacy form)."""
    return _keyring_description_password(label, None)


class PodmanSandboxLauncher(ExecModelHostLauncher):
    """Provision, exec into, resume, and remove managed Podman sandboxes."""

    provider = "podman"

    def __init__(self, *, config: PodmanConfig):
        self.config = config
        self.provider = config.provider_id
        self._key_values: dict[str, str] | None = None

    def egress_ruleset_path(self) -> Path | None:
        """Write the rendered egress policy to a cache file and return its path.

        The OCI hook runs in the host mount namespace, so the ruleset must live
        on the host. It is written under ``$XDG_RUNTIME_DIR`` (per-user tmpfs,
        gone at logout) rather than ``~/.cache`` so a shutdown cannot leave a
        stale policy behind, and the hook pipes its contents into ``nft -f -``
        — nft runs in the ``iptables_t`` SELinux domain and cannot open user
        state files itself.

        The file is content-addressed and mode 0600; it is also what
        :meth:`resume` re-applies, so the hook and the resume path cannot drift.

        :returns: Path to the ruleset, or ``None`` when no ``egress`` policy is set.
        """
        ruleset = self.config.render_egress_ruleset()
        if ruleset is None:
            return None
        runtime_dir = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
        cache_root = Path(runtime_dir)
        if not cache_root.is_dir():
            cache_root = Path(tempfile.gettempdir())
        cache_root = cache_root / "omnigent-podman-provider"
        digest = hashlib.sha256(ruleset.encode("utf-8")).hexdigest()[:16]
        path = cache_root / f"egress-{digest}.nft"
        if not path.exists():
            cache_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary = path.with_suffix(f".tmp{os.getpid()}")
            temporary.write_text(ruleset, encoding="utf-8")
            temporary.chmod(0o600)
            os.replace(temporary, path)
        return path

    def _keys(self) -> dict[str, str]:
        """Read each requested credential without exporting it on the host."""
        if self._key_values is not None:
            return self._key_values
        values: dict[str, str] = {}
        for key in self.config.keys:
            try:
                if key.description is not None:
                    value = _keyring_description_password(key.description, key.keyring)
                elif key.item_label is not None:
                    value = _keyring_label_password(key.item_label)
                else:
                    assert key.key_name is not None  # validated by KeyringKey
                    value = keyring.get_password(key.service, key.key_name)
            except Exception as exc:
                # The message stays generic on purpose: keyring backends echo
                # lookups and paths, and this string reaches the UI/logs.
                _LOGGER.debug(
                    "keyring lookup failed for %s: %s: %s",
                    key.env_var,
                    type(exc).__name__,
                    exc,
                )
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
        except subprocess.TimeoutExpired:
            raise click.ClickException(
                f"Podman command did not finish within {timeout}s"
            ) from None
        except OSError as exc:
            # The reason (a missing binary, a permission error) is what makes
            # this actionable, and it contains no command arguments.
            raise click.ClickException(
                f"Podman command could not run: {exc.strerror or type(exc).__name__}"
            ) from None

    def _secrets(self) -> list[str]:
        """Values that must never reach a user-facing error message."""
        values = [
            value
            for name, value in self.config.resolved_environment.items()
            # The passthrough is a list of *names* derived from the config, not a
            # secret, and redacting it would mangle any message quoting it.
            if name != "OMNIGENT_RUNNER_ENV_PASSTHROUGH" and value
        ]
        try:
            values.extend(self._keys().values())
        except click.ClickException:
            # A keyring miss is reported on its own path; the error we are
            # building must not turn into a different failure.
            pass
        # Short values would redact unrelated words in Podman's output.
        return [value for value in values if len(value) >= 6]

    def _detail_suffix(self, result: subprocess.CompletedProcess[str]) -> str:
        """Return ``": <reason>"`` for a failed call, or ``""`` if Podman was silent."""
        detail = _error_detail(result, self._secrets())
        return f": {detail}" if detail else ""

    def _failed(
        self, action: str, result: subprocess.CompletedProcess[str]
    ) -> click.ClickException:
        """Build an error that says what failed *and* why Podman failed.

        Losing Podman's stderr turns every launch failure into the same
        unsupported report ("Podman could not start the managed sandbox"), so
        the reason is appended whenever Podman supplied one.
        """
        return click.ClickException(f"{action}{self._detail_suffix(result)}")

    def _container_failure_detail(self, container_id: str) -> str:
        """Best-effort reason a just-created container never became ready.

        Reads the exit state and the tail of the container's own log, which is
        where an entrypoint that crashed during bootstrap says why (the managed
        host log path in the generic message is only written once the host
        starts, so a failure before that leaves nothing else to go on).
        """
        parts: list[str] = []
        state = self._podman(
            "inspect", "--format", "{{.State.Status}} exit {{.State.ExitCode}}", container_id
        )
        if state.returncode == 0 and state.stdout.strip():
            parts.append(f"state: {state.stdout.strip()}")
        logs = self._podman("logs", "--tail", "20", container_id)
        if logs.returncode == 0:
            tail = [
                line.strip()
                for line in f"{logs.stdout}\n{logs.stderr}".splitlines()
                if line.strip()
            ]
            if tail:
                parts.append("last output: " + " | ".join(tail[-10:]))
        return _redact(
            "; ".join(parts)[:_MAX_DETAIL_CHARS], self._secrets()
        )

    def prepare(self) -> None:
        """Check CLI access, local image, and any named network."""
        if shutil.which(self.config.binary) is None:
            raise click.ClickException(f"Podman CLI not found: {self.config.binary}")
        info = self._podman("info", "--format", "{{.Host.Security.Rootless}}")
        if info.returncode:
            raise self._failed("Podman is unavailable; check the local user or Podman machine", info)
        if self.config.require_rootless and info.stdout.strip().lower() != "true":
            raise click.ClickException("Podman is not running rootless; use a rootless user or Podman machine")
        image = self._podman("image", "exists", self.config.image)
        if image.returncode:
            raise self._failed(f"Podman image is unavailable: {self.config.image}", image)
        if not is_passthrough_network(self.config.network):
            network = self._podman("network", "exists", self.config.network)
            if network.returncode:
                raise self._failed(
                    f"Podman network is unavailable: {self.config.network}", network
                )
        for mount in self.config.mounts:
            # A file source mounts one file (Podman creates the target path and
            # its parents); a directory source is the usual case.
            if not (mount.source.is_dir() or mount.source.is_file()) or mount.source.is_symlink():
                raise click.ClickException(
                    f"Podman mount source must be an existing file or directory: {mount.source}"
                )
            # A readable source directory can still hold a directory the
            # rootless userns cannot open, which crun only reports at start.
            # Say so here, while the message can still name the path and owner.
            unsearchable = _unsearchable_entry(mount.source)
            if unsearchable is not None:
                raise click.ClickException(
                    f"Podman mount source is not fully accessible to this user: {unsearchable}"
                )
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
        if self.config.deny_cidrs and "NET_ADMIN" not in self.config.cap_add:
            args.extend(["--cap-add", "NET_ADMIN"])
        for capability in self.config.cap_add:
            args.extend(["--cap-add", capability])
        for capability in self.config.cap_drop:
            args.extend(["--cap-drop", capability])
        for name, value in self.config.annotations.items():
            args.extend(["--annotation", f"{name}={value}"])
        ruleset = self.egress_ruleset_path()
        if ruleset is not None:
            args.extend(["--annotation", f"{EGRESS_RULESET_ANNOTATION}={ruleset}"])
        args.extend(option for key in self.config.env if key in os.environ for option in ("--env", key))
        for key, value in self.config.resolved_environment.items():
            args.extend(["--env", f"{key}={value}"])
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
            raise self._failed("Podman could not create the managed sandbox", created)
        container_id = created.stdout.strip()
        if not container_id:
            raise click.ClickException("Podman returned no container ID")
        started = self._podman("start", container_id, timeout=120)
        if started.returncode:
            self._podman("rm", "--force", container_id)
            raise self._failed("Podman could not start the managed sandbox", started)
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
                        self.run(container_id, self._egress_fence_script(), as_root=True)
                    if self.config.bootstrap_command:
                        self.run(container_id, self.config.bootstrap_command)
                    return container_id
                time.sleep(0.5)
        except BaseException:
            self._podman("rm", "--force", container_id)
            raise
        # The container is still here, so its state and own log still exist:
        # read them before removing it, or the reason for a crashed entrypoint
        # is deleted along with the container.
        detail = self._container_failure_detail(container_id)
        self._podman("rm", "--force", container_id)
        suffix = f": {detail}" if detail else ""
        raise click.ClickException(f"Podman sandbox bootstrap did not complete{suffix}")

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
        self, sandbox_id: str, command: str, *, check: bool = True, as_root: bool = False
    ) -> RemoteCommandResult:
        """Execute a shell script over stdin, keeping launch tokens out of argv.

        When ``runtime_user`` is configured, every command runs as that
        unprivileged user — including the managed host that Omnigent starts
        through this method, and therefore the runners, harness, and agent
        shells below it. Privileged setup that must stay root (installing an
        egress fence) passes ``as_root=True`` explicitly.
        """
        exports = "".join(
            f"export {name}={shlex.quote(value)}\n" for name, value in self._keys().items()
        )
        exec_args = ["exec", "-i"]
        if self.config.runtime_user is not None:
            if as_root:
                exec_args += ["--user", "root"]
            else:
                exec_args += [
                    "--user",
                    self.config.runtime_user,
                    "--env",
                    f"HOME={self.config.runtime_home}",
                ]
        result = self._podman(
            *exec_args, sandbox_id, "/bin/sh", "-s",
            input=exports + command + "\n", timeout=None,
        )
        completed = RemoteCommandResult(
            returncode=result.returncode, stdout=result.stdout, stderr=result.stderr
        )
        if check and completed.returncode:
            raise click.ClickException(
                f"Podman sandbox command failed (exit {completed.returncode})"
                f"{self._detail_suffix(result)}"
            )
        return completed

    def _owned_state(self, sandbox_id: str) -> bool | None:
        """Return running state, or None if absent; reject non-provider containers."""
        result = self._podman("inspect", "--type", "container", sandbox_id)
        if result.returncode:
            exists = self._podman("container", "exists", sandbox_id)
            if exists.returncode == 1:
                return None
            raise self._failed("Podman could not inspect the managed sandbox", result)
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
        """Start a stopped container without discarding its writable layer.

        Starting a container **recreates its network namespace** when the old one
        is gone (a host reboot), while the OCI hook only runs at creation — so an
        ``egress`` profile re-applies its ruleset here. Idempotent: the ruleset
        flushes and rebuilds the table, so a still-live netns is fine too.
        """
        state = self._owned_state(sandbox_id)
        if state is None:
            raise SandboxGoneError("Managed Podman sandbox no longer exists")
        if not state:
            started = self._podman("start", sandbox_id, timeout=120)
            if started.returncode:
                raise self._failed("Podman could not resume the managed sandbox", started)
        self._reapply_egress_fence(sandbox_id)

    def _reapply_egress_fence(self, sandbox_id: str) -> None:
        """Re-apply the profile's egress ruleset inside the container netns.

        Runs the host's ``nft`` through ``podman unshare nsenter`` so no
        capability is required inside the container. Fail closed: a container
        must not come back with the policy missing.

        :param sandbox_id: Running container to fence.
        :raises click.ClickException: When the ruleset cannot be applied.
        """
        ruleset = self.egress_ruleset_path()
        if ruleset is None:
            return
        inspected = self._podman("inspect", "--format", "{{.State.Pid}}", sandbox_id)
        pid = inspected.stdout.strip() if inspected.returncode == 0 else ""
        if not pid or pid == "0":
            raise click.ClickException(
                f"Cannot re-apply the egress fence: {sandbox_id} has no running pid"
                f"{self._detail_suffix(inspected)}"
            )
        applied = self._podman(
            "unshare", "nsenter", "-n", "-t", pid, "--", "nft", "-f", "-",
            input=ruleset.read_text(encoding="utf-8"),
        )
        if applied.returncode:
            raise click.ClickException(
                "Cannot re-apply the egress fence to the resumed sandbox; refusing to "
                f"start it unfenced{self._detail_suffix(applied)}"
            )

    def terminate(self, sandbox_id: str) -> None:
        """Remove an owned container; an already-removed container is fine."""
        if self._owned_state(sandbox_id) is None:
            return
        removed = self._podman("rm", "--force", sandbox_id, timeout=120)
        if removed.returncode:
            raise self._failed("Podman could not remove the managed sandbox", removed)
