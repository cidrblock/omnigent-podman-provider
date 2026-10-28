# OCI-hook egress fence

A `createContainer` OCI hook that gives a rootless Podman sandbox a
**default-allow internet, no-LAN** network posture the container itself cannot
undo. Pair it with `--cap-drop NET_ADMIN,NET_RAW` (the provider's `cap_drop`) and
the agent never has the capability to inspect, flush, or extend the rules.

Two files plus one line of Podman configuration:

| File | Purpose |
|---|---|
| `fence.sh` | installs the ruleset with the **host's** `nft`, inside the container's network namespace |
| `fence.json` | the hook descriptor: `createContainer` stage, gated on the `apply-firewall=true` annotation |

## Install (rootless, no root required)

```bash
install -D -m 0755 fence.sh ~/.local/bin/podman-egress-fence.sh
install -D -m 0644 fence.json ~/.config/containers/oci/hooks.d/egress-fence.json
# edit the "path" inside the installed JSON to your absolute path
```

Rootless Podman does **not** scan the XDG hooks directory by default, so
register it in `~/.config/containers/containers.conf`:

```toml
[engine]
hooks_dir = [
  "/home/USER/.config/containers/oci/hooks.d",
]
```

Then annotate the containers that should be fenced. The provider does this from
the agent YAML (`annotations: {apply-firewall: "true"}`), or by hand:

```bash
podman run --rm --annotation apply-firewall=true \
  --cap-drop=NET_ADMIN --cap-drop=NET_RAW <image> <cmd>
```

## Two ways to supply the ruleset

1. **Annotation (used with the provider).** The container carries
   ``omnigent-egress-ruleset=/path/to/ruleset.nft`` and the hook pipes that file
   into ``nft -f -``. The provider renders the file from the profile's
   ``egress:`` policy, which keeps hook, re-apply, and config in sync.
2. **Built-in defaults.** No annotation: the hook builds a ruleset from
   ``FENCE_ALLOW_V4`` / ``FENCE_DENY_V4`` / ``FENCE_DENY_V6`` (set in the hook's
   ``env``), which is what the standalone example uses.

The rendered ruleset is port-scoped where possible — the proxy on one port, the
resolver on 53 — so the hook applies a policy that names destinations *and*
the ports they are reachable on.

The hook reads the file itself and pipes it: nft runs in the ``iptables_t``
SELinux domain and cannot open user state files. It fails closed when the file
is missing, empty, or unreadable, and re-checks that the table exists after
applying — otherwise a failed read would hand nft an empty stdin, which exits 0
and leaves the container silently unfenced.

## Why `createContainer`

Measured on Podman 5.8.4 / crun 1.28:

| Stage | Behaviour |
|---|---|
| `createContainer` | hook runs as uid 0 **in the container's network namespace**; OCI state `"pid"` is still `0`, so pid-based `nsenter` is neither needed nor possible |
| `createRuntime` | hook runs before the container joins its namespaces, so the same work needs `nsenter -n -t <pid>` (and *not* `-U`: entering the container's user namespace fails with `EINVAL`, because crun already runs hooks inside Podman's rootless user namespace) |
| `poststart` | does **not** re-run on `podman stop`/`start` or `podman restart` |

Because the hook path and the binaries it runs resolve in the **runtime**
namespace, the fence is installed by the host's `nft` even though the process
sits in the container's network namespace. A malicious image shipping a fake
`nft`/`iptables` cannot weaken it.

## What the ruleset does

- accepts loopback (`lo`, `127.0.0.0/8`, `::1`),
- accepts `FENCE_ALLOW_V4`/`FENCE_ALLOW_V6` destinations — put the address a
  share-network mapping uses here (e.g. `169.254.170.2` for a host-loopback map
  to a loopback-bound host service) so that path keeps working,
- **rejects** `FENCE_DENY_V4` (default RFC1918) and `FENCE_DENY_V6` (default
  link-local + ULA). IPv6 is included deliberately: a v4-only fence is bypassed
  by a link-local neighbour,
- everything else falls through, so public egress works.

Rejection (not drop) is intentional: the agent gets an immediate error instead of
a hang. `nft` is fed the ruleset on stdin because nft runs in the `iptables_t`
SELinux domain and cannot read user state directories.

## Verify

```bash
# from inside the container
curl -sS -m4 -o /dev/null -w 'lan:%{http_code}\n' http://192.168.0.1/   # fails
curl -sS -m4 -o /dev/null -w 'inet:%{http_code}\n' https://example.com/ # succeeds

# from the host, in the container's network namespace
PID=$(podman inspect -f '{{.State.Pid}}' <container>)
podman unshare nsenter -n -t "$PID" -- nft list chain inet omnigent_fence out
```

## Lifetime: a stop/start keeps the fence, a reboot does not

Podman keeps a container's network namespace across `stop`/`start` (the same
netns inode before and after), so the rules survive and the hook — which only
runs at creation — is not needed again.

A **host reboot** destroys the namespace (it lives under `/run/user/<uid>/netns`)
and the restarted container gets a fresh one, so the fence is gone until it is
re-applied:

```bash
PID=$(podman inspect -f '{{.State.Pid}}' <container>)
podman unshare nsenter -n -t "$PID" -- nft -f -   # same ruleset as the hook
```

Two ways to make that automatic: re-apply after the sandbox provider resumes a
container, or run a small timer that re-applies the ruleset to every managed
container (self-healing, at the cost of a short unfenced window).

## Limits

- The fence lives in the container's network namespace, so it is only as strong
  as the namespace. It stops lateral movement on the LAN; it does not prevent
  data leaving over the allowed public egress, and it is not a defence against a
  kernel/userns escape.
- Rootless `--network=host` containers share one per-user rootless namespace:
  rules installed there would apply to every such container, not just one.
- Host-enforced filtering (for example cgroup- or uid-matched firewall rules on
  the host) needs root and gives up rootless.
