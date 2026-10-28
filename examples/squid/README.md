# Putting an authenticated CONNECT proxy in front of the fence

The egress fence is L3/L4: it can express "this address, these ports" and
nothing about hostnames, because nftables cannot see TLS SNI. If a profile needs
internet access, the narrow shape is not `allow: 0.0.0.0/0` — it is **one
address, one port**, with a proxy behind it deciding which *hosts* are
reachable.

This example is the tested configuration: rootless Squid on the pasta
host-loopback address, allowlist by hostname, authentication required, no TLS
interception.

```
sandbox ──► 169.254.170.2:3128 ──► squid ──► allowlisted hosts
   (fence permits exactly that address and port)
```

## 1. Run the proxy (rootless, loopback only)

Squid publishes on `127.0.0.1:3128`; the sandbox reaches it through pasta's
`--map-host-loopback`, so it never listens on the LAN. A rootless Podman
quadlet keeps it alive without root:

`~/.config/containers/systemd/squid-egress.container`

```ini
[Unit]
Description=Sandbox egress CONNECT proxy (squid)
After=network-online.target

[Container]
ContainerName=squid-egress
Image=docker.io/ubuntu/squid:latest
PublishPort=127.0.0.1:3128:3128
Volume=%h/.config/squid/squid.conf:/etc/squid/squid.conf:ro,Z
Volume=%h/.config/squid/passwd:/etc/squid/passwd:ro,Z
LogDriver=journald

[Service]
Restart=always

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload && systemctl --user start squid-egress.service
journalctl --user -u squid-egress -f      # the audit trail: every hostname
```

Config: [`squid.conf`](squid.conf). Notes that matter:

- **`http_access deny all` last** is the policy; the `dstdomain` list is the
  entire internet the sandbox has.
- **`acl SSL_ports port 443`** with `http_access deny CONNECT !SSL_ports` means
  CONNECT is only ever allowed to 443 — port 22, 9418 and UDP 443 are simply not
  expressible. There is no unencrypted egress path either, because plain HTTP
  never matches `SSL_ports`.
- **`proxy_auth REQUIRED`** is not ceremony: `127.0.0.1:3128` is reachable by
  every local process, so without auth the allowlist is an open relay for
  anything on the machine.
- **No TLS interception.** The proxy sees `CONNECT host:443`, byte counts and
  status codes. It cannot see paths or payloads, so do not expect URL-level
  policy from it.
- **`strip_query_terms on`** keeps tokens out of the access log.

## 2. Give it a credential

`basic_ncsa_auth` reads an `htpasswd` file. It runs as the unprivileged `proxy`
user inside the container, so the file must be world-readable — it holds a
bcrypt hash of a random password, not the password:

```bash
NEW=$(python3 -c 'import secrets,string;print("".join(secrets.choice(string.ascii_letters+string.digits) for _ in range(32)))')
htpasswd -nbB sandbox "$NEW" > ~/.config/squid/passwd
chmod 644 ~/.config/squid/passwd
```

Keep the resulting URL (`http://sandbox:$NEW@169.254.170.2:3128`) in a secret
store, not in the profile. This provider can read a Secret Service item and
inject it as an environment variable, so the credential never appears in
`config.yaml`:

```yaml
keys:
  - env_var: HTTPS_PROXY
    keyring: Agents
    description: squid-proxy
```

One secret, one variable: every client worth configuring (Goose, `gh`, `git`,
`pip`, `npm`, `gws`) honours `HTTPS_PROXY`. Rotate by rewriting both the
`htpasswd` file and the keyring item, then restarting the unit.

## 3. Point the profile at it

```yaml
sandbox:
  providers:
    - provider: podman
      podman:
        image: localhost/omnigent-host:latest
        # the proxy is reached at the mapped loopback address
        network: pasta:--map-host-loopback=169.254.170.2,--ipv4-only
        egress:
          # one destination, one port — this is the whole internet
          - allow: 169.254.170.2
            ports: [3128, 6767, 8765]      # proxy, server, tool relay
            protocols: [tcp]
        annotations:
          apply-firewall: 'true'
        environment:
          # the control plane must bypass the proxy
          NO_PROXY: 169.254.170.2
          no_proxy: 169.254.170.2
          GIT_TERMINAL_PROMPT: '0'
        keys:
          - env_var: HTTPS_PROXY
            keyring: Agents
            description: squid-proxy
```

`NO_PROXY` is load-bearing: without it the sandbox tries to proxy its own
connection to the Omnigent server, which Squid will refuse.

## 4. Make git HTTPS-only

SSH clone URLs cannot work — port 22 is not on the allowlist — so rewrite them
instead of letting them fail. Mount a system gitconfig (a user `~/.gitconfig`
may be rewritten at runtime by the image's init, a system one is not):

`~/.omnigent/sandbox/gitconfig` → mounted read-only at `/etc/gitconfig`

```gitconfig
[url "https://github.com/"]
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
[credential]
	# token from the environment, never written into a URL or .git/config
	helper = "!f() { test \\"$1\\" = get && echo username=x-access-token && echo password=$GH_TOKEN; }; f"
```

Do not put the proxy URL here — it would duplicate the secret outside the
keyring.

## 5. Verify

```bash
# from the host: auth is enforced, allowlist is enforced
curl -sS -x http://127.0.0.1:3128 https://api.github.com/meta        # 407
curl -sS -x http://sandbox:PASS@127.0.0.1:3128 https://api.github.com/meta   # 200
curl -sS -x http://sandbox:PASS@127.0.0.1:3128 https://example.org   # 403

# from inside the sandbox
podman exec <sandbox> sh -c 'env -u HTTPS_PROXY curl -sS --max-time 8 https://pypi.org'
#   → fails in ~30 ms: the fence rejects, it is not a DNS problem
podman exec <sandbox> curl -sS -x http://169.254.170.2:3128 https://api.github.com/meta
#   → 407: reachable, but not without the credential
pid=$(podman inspect -f '{{.State.Pid}}' <sandbox>)
podman unshare nsenter -n -t "$pid" -- nft list chain inet omnigent_fence out
```

A working sandbox does real work through the proxy: `pip download`, `npm view`,
`gh api user`, `git ls-remote https://…` and the agent's own model calls all
traverse it.

## 6. Tell the agent what it may reach

An agent that discovers the policy by failing wastes turns and may invent a
workaround. Derive a read-only view of the allowlist from the proxy config, so
the two cannot drift, and hand it to the sandbox:

```bash
#!/usr/bin/env bash
# Render `acl allowed_sites ...` from squid.conf into a plain hostname list.
awk '
    /^[[:space:]]*acl[[:space:]]+allowed_sites[[:space:]]/ { collecting = 1 }
    collecting {
        line = $0; sub(/#.*/, "", line); gsub(/\\/, " ", line)
        n = split(line, w, /[[:space:]]+/)
        for (i = 1; i <= n; i++)
            if (w[i] != "" && w[i] != "acl" && w[i] != "allowed_sites" && w[i] != "dstdomain") print w[i]
    }
    collecting && $0 !~ /\\[[:space:]]*$/ { collecting = 0 }
' "${SQUID_CONF:-$HOME/.config/squid/squid.conf}" | sort -u > "$HOME/.omnigent/sandbox/egress-allowlist.txt"
```

Re-run it whenever `squid.conf` changes — a systemd path unit on
`PathChanged=%h/.config/squid/squid.conf` is enough — and mount the output
read-only:

```yaml
mounts:
  # mount the DIRECTORY, not the file: a single-file bind mount pins the inode,
  # so a regenerated list is invisible to an already-running sandbox (measured:
  # the container kept the old content, and with :Z the file mount was not even
  # readable). A directory mount follows the rename immediately.
  - source: /home/USER/.omnigent/sandbox/egress
    target: /etc/sandbox-egress
    mode: ro
    relabel: z
```

Verified end to end: editing `squid.conf` on the host changed
`/etc/sandbox-egress/allowlist` inside a *running* sandbox within seconds, and
reverting it removed the entry again.

Then say so in the agent's instructions (an `AGENTS.md` mounted into the
workspace works well), because the file is only useful if the agent reads it
*first*:

- the list is the whole internet it has; matching is by domain suffix
- `403` from the proxy = policy denial, do not retry; `407` = credential fault,
  not a permission; a refusal in ~30 ms = the tool bypassed `HTTPS_PROXY`
- if a task needs a host that is not listed, ask the operator to add it rather
  than routing around the policy
- exhaust in-policy sources first: the upstream repo (including docs sources and
  changelogs), the package page on PyPI/npm, and the forge API

Do not mount the proxy's access log for this. It contains every session's
destinations and byte counts; policy is shareable, traffic history is not.

## Adding a destination

One `dstdomain` line plus `systemctl --user restart squid-egress`. The fence
needs no change — it only knows the proxy's address.

Watch for entries that are really an API surface rather than a host:
`.googleapis.com` covers hundreds of Google APIs, and GitHub's API is writable.
The proxy only decides *whether* a service is reachable; the token's scope
decides *what* is possible within it.

## Known limits

- Hostname granularity only. An allowlisted host can exfiltrate through a URL
  path; cap that with nft `quota` on the proxy hop or accept it deliberately.
- Downloading from an allowlisted host is not distinguished from uploading to it.
- The proxy becomes a single point of failure for anything that needs the
  network — including the model endpoint, if you route it through the proxy.
- DNS: the guest can still resolve through the pasta resolver. If you want name
  resolution gone too, deny port 53 and point `--dns-host` at an address that is
  not listening, so lookups fail fast rather than time out.
