"""Register the Podman launcher with Omnigent's community provider registry."""

from omnigent.onboarding.sandboxes.registry import (
    SandboxProviderContribution,
    SandboxProviderMetadata,
)

from .config import PodmanConfig


def get_contribution() -> SandboxProviderContribution:
    """Describe the managed Podman provider to Omnigent 0.19.x."""
    return SandboxProviderContribution(
        name="omnigent-podman-provider",
        providers={
            "podman": SandboxProviderMetadata(
                name="podman",
                launcher_class="omnigent.community.sandbox.podman.launcher:PodmanSandboxLauncher",
                config_model=PodmanConfig,
            ),
        },
    )
