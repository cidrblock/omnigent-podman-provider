"""Operator-authored configuration for a managed Podman sandbox."""

import re
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator, model_validator


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_IPV4_CIDR = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\Z")
#: Capabilities an operator may grant. Deliberately tiny: NET_ADMIN is what an
#: entrypoint needs to install an egress fence, NET_RAW for diagnostic tooling.
_ALLOWED_CAP_ADD = frozenset({"NET_ADMIN", "NET_RAW"})
#: Annotation names an operator may set. Podman passes these to the OCI spec,
#: where hooks can gate on them (e.g. ``apply-firewall=true``).
_ANNOTATION_NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,126}\Z")
# Podman forwards everything after ``mode:`` to the mode's own process, so a
# network value may carry options (``pasta:--map-host-loopback=169.254.170.2``).
_NETWORK_WITH_OPTIONS = re.compile(r"(?:pasta|slirp4netns):\S+\Z")
_PASTA_HOST_LOOPBACK = re.compile(r"--map-host-loopback(?:=|\s+)([0-9.]+)")


def is_passthrough_network(network: str) -> bool:
    """Return whether *network* is a mode that carries its own options.

    :param network: The configured ``network`` value, e.g. ``"pasta"`` or
        ``"pasta:--map-host-loopback=169.254.170.2"``.
    :returns: ``True`` for a bare or option-carrying pasta/slirp4netns mode,
        i.e. a value Podman accepts verbatim rather than a named Podman network.
    """
    return network in {"host", "bridge", "pasta", "slirp4netns"} or bool(
        _NETWORK_WITH_OPTIONS.fullmatch(network)
    )


class BindMount(BaseModel):
    """One host directory exposed at an explicit container path."""

    model_config = ConfigDict(extra="forbid")

    source: Path
    target: str
    mode: Literal["ro", "rw"] = "ro"
    relabel: Literal["z", "Z"] | None = None
    per_session: bool = False

    @model_validator(mode="after")
    def validate_paths(self) -> "BindMount":
        """Reject path traversal, volume-option injection, and read-only scratch."""
        target = PurePosixPath(self.target)
        if not self.source.is_absolute() or ".." in self.source.parts:
            raise ValueError("mount source must be an absolute directory without '..'")
        if not target.is_absolute() or self.target == "/" or ".." in self.target.split("/"):
            raise ValueError("mount target must be an absolute directory without '..'")
        if any(character in str(self.source) + self.target for character in ":\r\n\x00"):
            raise ValueError("mount paths cannot contain colon or control characters")
        if self.per_session and self.mode != "rw":
            raise ValueError("per-session mounts must be writable")
        return self


class KeyringKey(BaseModel):
    """Map a host keyring credential to a container process variable."""

    model_config = ConfigDict(extra="forbid")

    key_name: str | None = Field(default=None, min_length=1)
    env_var: str
    service: str = Field(default="omnigent-podman-provider", min_length=1)
    item_label: str | None = Field(default=None, min_length=1)

    @field_validator("env_var")
    @classmethod
    def validate_env_var(cls, name: str) -> str:
        if not _ENV_NAME.fullmatch(name):
            raise ValueError("env_var must be an environment variable name")
        return name

    @model_validator(mode="after")
    def validate_lookup(self) -> "KeyringKey":
        if self.key_name is None and self.item_label is None:
            raise ValueError("key_name or item_label is required")
        return self


class PodmanConfig(BaseModel):
    """Image, networking, and explicitly forwarded host environment names."""

    model_config = ConfigDict(extra="forbid")

    image: str = Field(min_length=1)
    provider_id: Literal["podman"] = Field(default="podman", exclude=True)
    network: str = Field(default="host", min_length=1)
    deny_cidrs: list[str] = Field(default_factory=list)
    cap_add: list[str] = Field(default_factory=list)
    cap_drop: list[str] = Field(default_factory=list)
    annotations: dict[str, str] = Field(default_factory=dict)
    runtime_user: str | None = Field(default=None, min_length=1)
    runtime_home: str = Field(default="/root", min_length=2)
    env: list[str] = Field(default_factory=list)
    binary: str = Field(default="podman", min_length=1)
    entrypoint: str | None = None
    require_rootless: bool = True
    startup_timeout_s: int = Field(default=60, ge=1, le=300)
    mounts: list[BindMount] = Field(default_factory=list)
    keys: list[KeyringKey] = Field(default_factory=list)
    bootstrap_command: str | None = Field(default=None, min_length=1)

    @field_validator("env")
    @classmethod
    def validate_env(cls, names: list[str]) -> list[str]:
        """Only variable names belong in config; values stay in the server env."""
        if len(names) != len(set(names)) or any(not _ENV_NAME.fullmatch(name) for name in names):
            raise ValueError("env must contain unique environment variable names")
        return names

    @field_validator("mounts")
    @classmethod
    def validate_mounts(cls, mounts: list[BindMount]) -> list[BindMount]:
        """Do not let one bind hide another inside the same container."""
        targets = [PurePosixPath(mount.target) for mount in mounts]
        if any(
            left == right or left in right.parents or right in left.parents
            for index, left in enumerate(targets)
            for right in targets[index + 1 :]
        ):
            raise ValueError("mount targets must be distinct and non-overlapping")
        return mounts

    @model_validator(mode="after")
    def validate_keys(self) -> "PodmanConfig":
        """Prevent a keyring value from also entering Podman's stored env."""
        names = [key.env_var for key in self.keys]
        if len(names) != len(set(names)):
            raise ValueError("keyring env_var names must be unique")
        if set(names) & set(self.env):
            raise ValueError("keyring env_var names cannot also appear in env")
        return self

    @field_validator("cap_drop")
    @classmethod
    def validate_cap_drop(cls, caps: list[str]) -> list[str]:
        """Dropping is always safe, so anything Podman accepts is allowed here."""
        if len(caps) != len(set(caps)):
            raise ValueError("cap_drop must be unique")
        unknown = set(caps) - _ALLOWED_CAP_ADD
        if unknown:
            raise ValueError(f"cap_drop only accepts {sorted(_ALLOWED_CAP_ADD)}")
        return caps

    @field_validator("annotations")
    @classmethod
    def validate_annotations(cls, values: dict[str, str]) -> dict[str, str]:
        """Keep annotation names and values free of argv/spec surprises."""
        for name, value in values.items():
            if not _ANNOTATION_NAME.fullmatch(name):
                raise ValueError(f"annotation name is not a plain dotted key: {name!r}")
            if "\x00" in value or "\n" in value:
                raise ValueError(f"annotation {name!r} value cannot contain NUL or newline")
        return values

    @field_validator("runtime_user")
    @classmethod
    def validate_runtime_user(cls, name: str | None) -> str | None:
        """Keep the value safe for argv and for ``podman exec --user``."""
        if name is not None and not _ENV_NAME.fullmatch(name):
            raise ValueError("runtime_user must be a plain user name")
        return name

    @field_validator("runtime_home")
    @classmethod
    def validate_runtime_home(cls, path: str) -> str:
        if not path.startswith("/") or ".." in path.split("/"):
            raise ValueError("runtime_home must be an absolute path without '..'")
        return path

    @field_validator("cap_add")
    @classmethod
    def validate_cap_add(cls, caps: list[str]) -> list[str]:
        """Only allow the two capabilities a sandbox fence or probes need."""
        if len(caps) != len(set(caps)):
            raise ValueError("cap_add must be unique")
        unknown = set(caps) - _ALLOWED_CAP_ADD
        if unknown:
            raise ValueError(f"cap_add only accepts {sorted(_ALLOWED_CAP_ADD)}")
        return caps

    @field_validator("deny_cidrs")
    @classmethod
    def validate_deny_cidrs(cls, cidrs: list[str]) -> list[str]:
        """Keep the fence script free of anything a shell or nft could misread."""
        if len(cidrs) != len(set(cidrs)):
            raise ValueError("deny_cidrs must be unique")
        for cidr in cidrs:
            if not _IPV4_CIDR.fullmatch(cidr):
                raise ValueError(f"deny_cidrs entry must be an IPv4 address or CIDR: {cidr!r}")
            octets, _, prefix = cidr.partition("/")
            if any(octet > 255 for octet in (int(part) for part in octets.split("."))):
                raise ValueError(f"deny_cidrs entry has an invalid octet: {cidr!r}")
            if prefix and not 0 <= int(prefix) <= 32:
                raise ValueError(f"deny_cidrs entry has an invalid prefix length: {cidr!r}")
        return cidrs

    @model_validator(mode="after")
    def validate_fence_network(self) -> "PodmanConfig":
        """Refuse a fence that would land outside this sandbox's own netns.

        ``deny_cidrs`` is installed inside the container's network namespace.
        With ``network: host`` (rootless) the container joins the per-user
        rootless namespace instead, so a drop rule there would fence every
        rootless container on the machine, not just this session.
        """
        if self.deny_cidrs and not self.network.startswith(("pasta", "slirp4netns")):
            raise ValueError("deny_cidrs requires network: pasta:… or slirp4netns:…")
        return self

    @property
    def host_loopback_addresses(self) -> list[str]:
        """Addresses the network string maps to the host's loopback interface.

        Connections the sandbox makes to these addresses reach services bound
        to ``127.0.0.1`` on the host (the Omnigent server and its per-session
        tool relay), so they must survive the egress fence.

        :returns: De-duplicated addresses from ``--map-host-loopback`` options,
            in configuration order.
        """
        seen: list[str] = []
        for address in _PASTA_HOST_LOOPBACK.findall(self.network):
            if address not in seen:
                seen.append(address)
        return seen


def profile_config_model(provider_id: str) -> type[PodmanConfig]:
    """Bind the registered identity into an alias's validated config model."""
    return create_model(
        f"PodmanConfig_{provider_id.replace('-', '_')}",
        __base__=PodmanConfig,
        __module__=__name__,
        provider_id=(Literal[provider_id], Field(default=provider_id, exclude=True)),
    )
