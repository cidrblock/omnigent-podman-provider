# Omnigent Podman provider

A community sandbox provider for **Omnigent 0.19.x**. This is a Fedora-first,
rootless-Podman alternative to managed Microsandbox VMs. It uses the Podman CLI
for its lifecycle, so a configured Podman machine on macOS is supported by the
same code path, but **macOS has not been tested**.

The [ai-development-sandbox Podman provider](https://github.com/djdanielsson/ai-development-sandbox/tree/main/podman-provider)
informed the entry-point and managed-host design. This implementation targets
the newer 0.19.x contract and runs against the local Podman CLI rather than a
Docker-compatible socket. Nothing in this repository installs into or changes
a running Omnigent service by itself.

## Current status

- The plugin registers `podman` plus any named `podman_*` / `podman-*` entries
  found in the server config before startup. Each alias has its own image and
  validated settings; the ID is recorded on its managed hosts.
- On Fedora rootless Podman, container create, exec, detached processes, stop,
  resume, and removal have been smoke-tested using disposable containers. A
  container on the `host` network also reached this installation's Omnigent
  `/health` endpoint on `127.0.0.1:6767`.
- The provider waits for the image's bootstrap entrypoint to finish before
  handing a new container to Omnigent. A managed OpenCode session launched on
  Podman, bound an online runner, and completed both an OpenAI turn and an
  EnMaaS GLM 5.3 turn. The disposable session and container were removed.
- Fedora trials of `podman_python`, `podman_node`, and `podman_nomount` each
  launched a managed OpenCode session and completed a turn. Their images
  contain Python 3.11–3.14, Node/TypeScript tooling, and no host mounts,
  respectively.
- Multi-repository cloning and macOS Podman-machine operation have not yet been
  exercised end-to-end.

## Configuration

Install the package in the **same Python environment as the Omnigent server**
(the running installation on this host is `0.19.1`). Use a matching Omnigent
host image in Podman; the Microsandbox image cache reference is not itself a
Podman registry. Do not install this plugin by downgrading Omnigent.

Example for this Fedora host's loopback-bound Omnigent server:

```yaml
sandbox:
  provider: podman
  server_url: http://127.0.0.1:6767
  podman:
    image: localhost/omnigent-host:opencode-podman-mount1
    network: host
    mounts:
      - source: /home/bthornto/.agents/skills
        target: /root/.agents/skills
        mode: ro
        relabel: z
      - source: /home/bthornto/docs/omnigent/scratch
        target: /root/scratch
        mode: rw
        relabel: Z
        per_session: true
    keys:
      - key_name: enmaas
        env_var: ENMAAS_KEY
    bootstrap_command: /usr/local/bin/omnigent-guest-init /bin/true
    env:
      - OPENAI_API_KEY
      - GH_TOKEN
      - GIT_TOKEN
      - JIRA_USERNAME
      - JIRA_API_TOKEN
      - OMNIGENT_GWS_CREDENTIALS_B64
      - OMNIGENT_GWS_KEY_B64
      - OMNIGENT_GWS_CLIENT_B64
      - OMNIGENT_GIT_SSH_PRIVATE_KEY_B64
      - OMNIGENT_GIT_SSH_PUBLIC_KEY_B64
      - OMNIGENT_GIT_USER_NAME
      - OMNIGENT_GIT_USER_EMAIL
```

This is a **single-provider example**. `network: host` lets a Linux container
reach a server bound to `127.0.0.1:6767`, but also shares the host network
namespace. For tighter network separation, use a named Podman network and a
`sandbox.server_url` reachable from that network, then test the callback before
selecting the provider. On macOS, `host` means the Podman **machine's** network
namespace, not the Mac's loopback; supply a reachable server URL and network.

`sandbox.podman.image` is required. The Podman CLI must be installed and able
to access the image. `network` defaults to `host`; `require_rootless` defaults
to `true`. `startup_timeout_s` defaults to 60 seconds while the provider waits
for the image's `sleep infinity` process to take over PID 1. `binary`
optionally selects a non-default Podman executable.
`entrypoint` is optional: when absent, the image's entrypoint is preserved so
an image-specific guest-init can set up credentials before `sleep infinity`.
Set `entrypoint: /bin/sh` for an image whose default entrypoint is unsuitable.

`mounts` is an optional list of absolute host directories and absolute guest
targets. Each mount uses `mode: ro` (default) or `rw`; `relabel: z` is for
shared SELinux access and `relabel: Z` is for a private container label.
`per_session: true` requires `rw` and creates a mode-0700 host subdirectory
below `source` named after that container. This subdirectory and its files
remain on the host when the managed session ends. Sources must already exist,
and symlink sources and overlapping guest targets are rejected. The configured
Podman image does not bake skills: mounting `~/.agents/skills` read-only makes
new host skills available to new managed sessions without rebuilding the image.

Only names in `env` that exist in Omnigent's server process are forwarded.
The provider passes **names** to `podman create --env`, never values on the CLI
command line. The values are still accessible inside each container and in
Podman's container configuration; avoid sharing `podman inspect` output for
credential-bearing containers. The underlying guest init must understand any
credential bootstrap variables it receives.

### Keys from the host keyring

`keys` optionally maps a keyring entry to a runtime environment variable.
Each entry has `key_name`, `env_var`, and an optional `service` (default:
`omnigent-podman-provider`). For example, store the EnMaaS key through a
hidden prompt on the host:

```bash
python -m keyring set omnigent-podman-provider enmaas
```

The provider reads the entry with `keyring.get_password(service, key_name)`
and fails a new launch if it is unavailable. It passes an appropriately
shell-quoted `export` over `podman exec -i` **stdin** for commands run in the
container. Unlike `env`, the key does not appear in `podman create` arguments
or Podman's stored container environment. The key is still available in the
environment of the launched process and any children it starts. `keys`
rejects duplicate `env_var` names and names also listed under `env`.

If an image must store the secret in its private credential files before
Omnigent starts, configure `bootstrap_command` as shown above. It runs once
after the image's normal entrypoint has finished, with the key available only
to that command's process. The example re-runs this host image's guest init to
write its mode-0600 OpenCode auth file. This is an image-specific command; do
not use it with an image that lacks that script. Replacing a keyring entry
affects new launches; already-running hosts keep their existing credentials.
On Fedora the tested backend is Secret Service through the user's D-Bus
session. macOS Keychain support follows Python keyring's platform backend but
has not been tested here.

On Fedora, entries created in **Passwords and Keys** may have only a visible
description and no service/username attributes. For those, use an exact label
lookup instead of `key_name`:

```yaml
keys:
  - item_label: "My API key"
    env_var: APP_API_KEY
```

The provider searches the default Login collection and requires exactly one
item with that description. This uses the Linux Secret Service backend;
service/`key_name` lookup remains the portable option for macOS. Descriptions
and service identifiers are configuration values, not hard-coded in the
provider. Neither the item value nor its description is logged by the lookup.

### Several images and mount policies

Omnigent needs a unique registered ID for each selectable image. The plugin
reads `sandbox.providers` from the path in `OMNIGENT_CONFIG` *during plugin
discovery* and registers IDs beginning `podman_` or `podman-`:

```yaml
sandbox:
  providers:
    - provider: podman
      server_url: http://127.0.0.1:6767
      podman: &base
        image: localhost/omnigent-host:opencode-podman-mount1
        network: host
        mounts:
          - {source: /home/user/.agents/skills, target: /root/.agents/skills, mode: ro, relabel: z}
    - provider: podman_python
      server_url: http://127.0.0.1:6767
      podman_python:
        <<: *base
        image: localhost/omnigent-host:python-multi
    - provider: podman_node
      server_url: http://127.0.0.1:6767
      podman_node:
        <<: *base
        image: localhost/omnigent-host:node-typescript
    - provider: podman_nomount
      server_url: http://127.0.0.1:6767
      podman_nomount:
        <<: *base
        mounts: []
```

YAML anchors keep shared settings in one place. Provide all the required
`env`, `keys`, and `bootstrap_command` settings in `&base` as appropriate to
your deployment. The first configured provider is the default; clients can
select the others by ID. Omnigent 0.19.x does not expose a separate friendly
display name. Keep profile IDs stable for existing sessions, and restart the
server when adding or removing profiles.

Set `OMNIGENT_CONFIG` to the **same absolute YAML path** before starting
`omnigent` (not only through a later `--config` argument): CLI imports may
cache provider registrations before `--config` is processed. The plugin reads
only profile IDs from that file; images, mounts, and credentials remain in the
Omnigent YAML. It does not need an external provider-config file.

On Fedora, build the optional images from a matching base image already in
rootless Podman storage:

```bash
podman build -t localhost/omnigent-host:python-multi -f images/Containerfile.python-multi .
podman build -t localhost/omnigent-host:node-typescript -f images/Containerfile.node-typescript .
```

The Python image adds 3.11, 3.13, and 3.14 alongside the base image's 3.12.
The Node image adds TypeScript, tsx, and pnpm to its existing Node 22.
Their builds and runtime checks have been exercised on Fedora; macOS remains
untested.

## Development checks

From a checkout with Omnigent 0.19.1 available in Python:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Installing the wheel registers the provider but does not change Omnigent's
chosen sandbox by itself. The local server lists Podman first, the three
named profiles next, and Microsandbox for existing VM sessions and rollback. Host-specific
deployment notes and test results are in `~/docs/omnigent/podman.md` on this
workstation.
