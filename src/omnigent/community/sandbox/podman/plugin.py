"""Register the Podman launcher with Omnigent's community provider registry."""

import os
from pathlib import Path
import re

import yaml
from omnigent.onboarding.sandboxes.registry import (
    SandboxProviderContribution,
    SandboxProviderMetadata,
)

from .config import PodmanConfig, profile_config_model


_PROFILE_ID = re.compile(r"podman[-_][a-z0-9][a-z0-9_-]{0,38}\Z")
_LAUNCHER = "omnigent.community.sandbox.podman.launcher:PodmanSandboxLauncher"


def _configured_profiles() -> list[str]:
    """Read only alias IDs from the explicit, pre-start server config path."""
    path = os.environ.get("OMNIGENT_CONFIG")
    if not path:
        return []
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("sandbox"), dict):
        return []
    entries = data["sandbox"].get("providers", [])
    if not isinstance(entries, list):
        return []
    profiles: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name = entry.get("provider")
        if isinstance(name, str) and name.startswith(("podman-", "podman_")):
            if not _PROFILE_ID.fullmatch(name):
                raise ValueError(f"invalid Podman profile ID: {name!r}")
            if name in profiles:
                raise ValueError(f"duplicate Podman profile ID: {name!r}")
            profiles.append(name)
    return profiles


def get_contribution() -> SandboxProviderContribution:
    """Register the base provider and each configured, stable profile ID."""
    providers = {
        "podman": SandboxProviderMetadata(
            name="podman", launcher_class=_LAUNCHER, config_model=PodmanConfig
        ),
    }
    for name in _configured_profiles():
        providers[name] = SandboxProviderMetadata(
            name=name, launcher_class=_LAUNCHER, config_model=profile_config_model(name)
        )
    return SandboxProviderContribution(
        name="omnigent-podman-provider",
        providers=providers,
    )
