"""Operator-authored configuration for a managed Podman sandbox."""

import re
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


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


class PodmanConfig(BaseModel):
    """Image, networking, and explicitly forwarded host environment names."""

    model_config = ConfigDict(extra="forbid")

    image: str = Field(min_length=1)
    network: str = Field(default="host", min_length=1)
    env: list[str] = Field(default_factory=list)
    binary: str = Field(default="podman", min_length=1)
    entrypoint: str | None = None
    require_rootless: bool = True
    startup_timeout_s: int = Field(default=60, ge=1, le=300)
    mounts: list[BindMount] = Field(default_factory=list)

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
