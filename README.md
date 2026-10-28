# Omnigent Podman provider

A community sandbox provider for **Omnigent 0.19.x**: rootless Podman containers
as managed agent sandboxes, driven through the Podman CLI. Nothing in this
repository changes a running Omnigent service by itself; installing the wheel only
registers the provider.

The [ai-development-sandbox Podman provider](https://github.com/djdanielsson/ai-development-sandbox/tree/main/podman-provider)
informed the entry-point and managed-host design. This implementation targets the
0.19.x contract, runs against the local Podman CLI rather than a Docker-compatible
socket, and adds network isolation, credential plumbing, and unprivileged-runtime
support described below.

Fedora is the tested platform. A Podman machine on macOS uses the same code path
but has **not** been tested.

## What it supports

| Area | Features |
|---|---|
| Lifecycle | create, exec, detached host start, stop, resume (same container, writable layer retained), removal, per-session profile aliases |
| Networking | any Podman network value, including `pasta:<options>` and `slirp4netns:<options>` passed through verbatim; `deny_cidrs` for an in-sandbox egress fence |
| Isolation | `annotations` (OCI-hook gating), `cap_add`/`cap_drop` (allowlisted), `runtime_user`/`runtime_home` for an unprivileged harness tree |
| Filesystem | directory **or single-file** bind mounts, read-only or read-write, SELinux `z`/`Z` relabel, `per_session` scratch directories |
| Credentials | `env:` name passthrough, `environment:` literals, `keys:` from the Secret Service keyring (three lookup shapes), automatic runner env passthrough |
| Images | one image per provider alias; no image changes required by the provider itself |

Network isolation is the one area that needs a second component: an **OCI hook**
fenced at container creation. See [`examples/oci-hook/`](examples/oci-hook/) — it
documents the hook's requirements in full (stage choice, ruleset, install steps,
lifetime, verification, limits). The in-provider `deny_cidrs` option is the
alternative when an OCI hook is not an option; it is weaker, because the rules are
installed from inside the container by a `bootstrap_command` and therefore need
`cap_add: [NET_ADMIN]` for the sandbox's lifetime.

## Install

Install into the **same Python environment as the Omnigent server**; do not
downgrade Omnigent to satisfy this package.

```bash
uv pip install --python ~/.local/share/uv/tools/omnigent/bin/python -e .
# or, from a wheel:
uv pip install --python ~/.local/share/uv/tools/omnigent/bin/python dist/*.whl
```

A forced `uv tool install` of Omnigent removes this package again — reinstall it
afterwards. Set `OMNIGENT_CONFIG` to the server's absolute config path *before*
starting `omnigent` if you use provider aliases: plugin discovery reads profile
IDs from `sandbox.providers` and may run before `--config` is processed.

The provider appears in the sandbox picker once the server restarts.

## Configuration

A minimal rootless provider entry:

```yaml
sandbox:
  server_url: http://127.0.0.1:6767      # how the sandbox host reaches Omnigent
  providers:
    - provider: podman
      podman:
        image: localhost/omnigent-host:latest
        network: pasta
```

`server_url` matters: the in-sandbox host and its runner must reach the server.
A server bound to `127.0.0.1` is unreachable from the container's namespace, so
either use `--network=host`, or a pasta network with a host-loopback mapping and
point `server_url` at the mapped address:

```yaml
sandbox:
  server_url: http://169.254.170.2:6767
  providers:
    - provider: podman
      podman:
        image: localhost/omnigent-host:latest
        network: pasta:--map-host-loopback=169.254.170.2
        server_url: http://169.254.170.2:6767
```

### Full field reference

| Field | Default | Meaning |
|---|---|---|
| `image` | required | Podman image reference, already present in local storage |
| `network` | `host` | Podman network value. A bare mode (`host`, `bridge`, `pasta`, `slirp4netns`) or a mode plus options (`pasta:--map-host-loopback=…,--ipv4-only`) is passed verbatim; anything else must name an existing Podman network |
| `env` | `[]` | Environment variable **names** forwarded from the server process (`podman create --env NAME`). Names absent from the server env are not set |
| `environment` | `{}` | Literal `NAME: value` pairs set on the container |
| `keys` | `[]` | Keyring entries exported into the provider's own `podman exec` shells; see below |
| `mounts` | `[]` | Bind mounts; see below |
| `annotations` | `{}` | OCI annotations (`--annotation NAME=VALUE`), e.g. `apply-firewall: "true"` |
| `cap_add` | `[]` | Capabilities to add, allowlist: `NET_ADMIN`, `NET_RAW` |
| `cap_drop` | `[]` | Capabilities to drop, same allowlist |
| `deny_cidrs` | `[]` | IPv4 CIDRs blocked by an in-sandbox nft ruleset installed from `bootstrap_command`. Requires a `pasta`/`slirp4netns` network and adds `NET_ADMIN` |
| `runtime_user` | `null` | When set, every exec runs as this unprivileged user — including the managed host Omnigent starts, and therefore the runners and harness under it. Privileged setup passes `as_root=True` internally |
| `runtime_home` | `/root` | `$HOME` exported to those execs |
| `entrypoint` | `null` | `--entrypoint` override; absent preserves the image's own init |
| `bootstrap_command` | `null` | Shell command run once, as root, after the image init has finished and before Omnigent starts the host |
| `binary` | `podman` | Podman executable |
| `require_rootless` | `true` | Refuse to use a rootful Podman |
| `startup_timeout_s` | `60` | How long to wait for the image's placeholder process to take over PID 1 |

### Mounts

```yaml
mounts:
  - {source: /home/USER/.agents/skills, target: /root/.agents/skills, mode: ro, relabel: z}
  - {source: /srv/agent-work, target: /root/agent-work, mode: rw, relabel: z}
  - {source: /srv/known_hosts, target: /root/.ssh/known_hosts, mode: ro, relabel: z}
```

- `source` must exist. It may be a **directory** or a **single file**; Podman
  creates the target path and any missing parent directories, so a file mount
  works even when the image has no such directory. This is how a single
  `AGENTS.md` or `known_hosts` reaches a sandbox without a bootstrap copy step.
- `relabel: z` is the shared SELinux label — use it for anything several
  containers read. `relabel: Z` assigns a **container-private** MCS label: a second
  container then cannot read the path, and the host directory keeps that private
  label afterwards (`restorecon` reports it as customized).
- `per_session: true` (rw only, directories only) creates a mode-0700 host
  subdirectory per container under `source`; it survives session teardown.
- Sources that are symlinks and overlapping targets are rejected.

### Credentials

Three shapes, most specific first:

```yaml
keys:
  # 1. Named Secret Service collection + item label (recommended on Linux)
  - {env_var: APP_API_KEY, keyring: Agents, description: app}

  # 2. Item label in any unlocked collection
  - {item_label: "My API key", env_var: OTHER_KEY}

  # 3. keyring module service/account (portable, incl. macOS)
  - {service: my-provider, key_name: app, env_var: THIRD_KEY}
```

- `keyring` requires `description`; both are configuration values, not hard-coded
  in the provider. The lookup matches the item label exactly and requires exactly
  one match. A missing, locked, or ambiguous collection fails the launch with a
  generic message (`Cannot read keyring entry for NAME`); the detail goes to the
  debug log so backend paths and identifiers cannot leak into the UI.
- Enumeration tolerates **stale** Secret Service items: a collection can list an
  item path whose item is gone, and `get_all_items()` raises for the whole
  collection when it hits one, which would otherwise abort every later lookup.
- Values are exported into the provider's `podman exec` shells only — never into
  `podman create` arguments or the container's stored environment. They are
  visible in the environment of the launched process and its children.
- `bootstrap_command` runs once as root with those exports available, so an image
  whose init wants a secret in a private credential file can be served without
  putting the secret in the container spec.

### Runner environment passthrough is derived

Omnigent's runner spawns the harness with a filtered environment (an allowlist
plus harness-credential names plus anything named in
`OMNIGENT_RUNNER_ENV_PASSTHROUGH`). A harness that reads its own variables would
otherwise lose them between container and harness.

The provider therefore derives `OMNIGENT_RUNNER_ENV_PASSTHROUGH` from the
container environment it builds: every `keys:` variable, every `environment:`
name, and every `env:` name, merged after any explicit value you set. You never
have to maintain that list by hand, and secret values still never appear on the
`podman create` command line — only names.

### Ordered egress policy

``egress`` is an ordered list of ``allow``/``deny`` entries, each an IP address
or CIDR. nftables is first-match, so order is precedence — an ``allow`` above a
broader ``deny`` is a deliberate hole; one below it is dead code::

    sandbox:
      server_url: http://169.254.170.2:6767
      providers:
        - provider: podman
          podman:
            image: localhost/omnigent-host:latest
            network: pasta:--map-host-loopback=169.254.170.2
            egress:
              - deny: 192.168.0.0/16
              - deny: 10.0.0.0/8
              - deny: 172.16.0.0/12
              - deny: 100.64.0.0/10        # CGNAT
              - deny: 224.0.0.0/4          # multicast
              - deny: fe80::/10
              - deny: fd00::/8
              - allow: 0.0.0.0/0           # explicit opt-in to the internet
              - allow: ::/0

The provider renders that into an nftables ruleset and:

- **prepends the control plane** — loopback, the pasta DNS resolver
  (``169.254.1.1``) and every host-loopback mapping named in ``network``. Those
  are not operator-editable: losing them breaks the sandbox rather than the
  policy.
- **appends a default deny** —
  ``counter reject comment "omnigent: default deny"``. With no ``allow:
  0.0.0.0/0`` the sandbox has no unlisted egress; with one, the appended rule is
  unreachable and its counter reads zero, which is the confirmation that the
  operator opted in. Nothing falls back to "internet open" by accident.
- **requires its own network namespace** — ``egress`` is rejected with
  ``network: host`` (rootless host networking joins the per-user rootless
  namespace, where a rule would fence every container, not this one).
- **writes the ruleset to ``$XDG_RUNTIME_DIR``** and passes its path to the OCI
  hook through the ``omnigent-egress-ruleset`` annotation. The hook pipes the
  contents into ``nft -f -`` (nft itself cannot open user state files under
  ``iptables_t``) and fails closed if the file is unreadable, empty, or the
  table is absent afterwards.
- **re-applies it on resume** — see below.

Older ``deny_cidrs`` still works: it installs the same shape of ruleset from a
``bootstrap_command`` inside the container, which needs ``cap_add: [NET_ADMIN]``
for the sandbox's lifetime and is therefore only a fallback for environments
without OCI hooks.

### Aliases: several images or postures

Each selectable sandbox needs its own registered provider id, matching
`podman[-_]<name>`. Aliases are read from `sandbox.providers` during plugin
discovery:

```yaml
sandbox:
  providers:
    - provider: podman
      podman: &base
        image: localhost/omnigent-host:goose
        network: pasta:--map-host-loopback=169.254.170.2,--ipv4-only
        annotations: {apply-firewall: "true"}
        cap_drop: [NET_ADMIN, NET_RAW]
        env: [GH_TOKEN, GIT_TOKEN]
        keys: [{env_var: APP_API_KEY, keyring: Agents, description: app}]
        environment:
          HARNESS_PROVIDER: gateway
          HARNESS_MODEL: your-model-id
        mounts:
          - {source: /home/USER/.agents/skills, target: /root/.agents/skills, mode: ro, relabel: z}
    - provider: podman-open
      podman-open:
        <<: *base
        annotations: {}
    - provider: podman-alias
      podman-alias:
        <<: *base
        image: localhost/omnigent-host:python
```

The first entry is the default; clients pick the others by id. Keep ids stable
for existing sessions, and restart the server when profiles change.

## Unprivileged runtime (`runtime_user`)

`podman exec` runs as the container's default user. When `runtime_user` is set,
every exec runs as that user instead, which covers the managed host Omnigent
starts through `run()` — and therefore the runners, harness, and agent shells.
Combined with an entrypoint that installs a firewall as root and then drops to
that user with the network capabilities removed from the **bounding set**, the
sandbox cannot lift its own fence:

```yaml
podman:
  runtime_user: agent
  cap_add: [NET_ADMIN]
  entrypoint: /opt/entrypoint/start.sh    # root: install rules, then drop caps
```

Dropping from the bounding set (`setpriv --bounding-set=-net_admin,-net_raw`) is
the part that matters: a merely non-root process can be handed a capability back
by a setuid binary. A `poststart` OCI hook does *not* re-run on restart, so prefer
the `createContainer` hook described in [`examples/oci-hook/`](examples/oci-hook/),
which needs no privileges inside the container at all.

## Operational notes

- **Resume**: a stopped container is resumed with `podman start` on the same
  container, so the writable layer is retained. If the container is gone the
  provider raises `SandboxGoneError` and Omnigent provisions a fresh generation.
- **Restart policy**: none is set, so containers stay stopped after a host reboot
  until something starts them.
- **Sandbox lifetime**: nothing in this provider expires a container.
- **Egress fence lifetime**: a stop/start keeps the container's network namespace,
  so the hook's rules survive it. A **host reboot** recreates the namespace and
  the OCI hook does not run again (hooks fire at creation only; adding
  ``poststart`` does not change that), so an ``egress`` profile re-applies its
  ruleset in ``resume()`` — the only path that starts a container after a
  reboot. That re-apply is fail-closed: a container that cannot be fenced is not
  started.
- **Secret hygiene**: values provided through `env:` do appear in the container
  environment, so do not share `podman inspect` output for credential-bearing
  containers. `keys:` avoids that for the entries it resolves.
- **One image per alias** keeps a session's runtime predictable. Nothing here
  inspects or changes an image.

## Development checks

From a checkout, with Omnigent 0.19.x importable:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The suite runs without Podman, a keyring, or an Omnigent server: it patches
`subprocess.run` and the Secret Service client, and asserts on the argv and stdin
the provider would use.

## License

MIT — see [LICENSE](LICENSE).
