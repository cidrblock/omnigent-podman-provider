#!/bin/bash
# OCI createContainer hook: fence a container's egress to loopback plus the
# public internet, before any process inside the container starts.
#
# Install (rootless):
#   install -D -m 0755 fence.sh ~/.local/bin/podman-egress-fence.sh
#   install -D -m 0644 fence.json ~/.config/containers/oci/hooks.d/egress-fence.json
#   # and register that directory, see README.md in this directory
#
# Why this stage: at createContainer the hook runs as uid 0 *inside the
# container's network namespace* (so the rules land in the container with no
# nsenter; the OCI state's "pid" is still 0), while the hook path and the
# binaries it runs resolve in the *runtime* (host) namespace — so a lying
# nft/iptables inside a malicious image cannot weaken the fence.
#
# The ruleset is piped to `nft -f -` rather than read from a file: nft runs in
# the iptables_t SELinux domain and cannot read user state directories.
#
# Two modes:
#   1. The container carries an ``omnigent-egress-ruleset`` annotation naming a
#      host file (a provider that renders the policy writes one). That file is
#      applied verbatim, piped on stdin, so the hook and the provider's
#      resume-time re-apply cannot drift.
#   2. No such annotation: fall back to the built-in defaults below.
#
# Tuning (mode 2, via the hook's "env" in the JSON, all optional):
#   FENCE_ALLOW_V4  extra v4 destinations to allow (e.g. a host-loopback mapping)
#   FENCE_ALLOW_V6  extra v6 destinations to allow
#   FENCE_DENY_V4   v4 CIDRs to reject (default: RFC1918)
#   FENCE_DENY_V6   v6 CIDRs to reject (default: link-local + ULA)
set -uo pipefail

NFT=""
for candidate in /usr/sbin/nft /usr/bin/nft /sbin/nft /bin/nft; do
    if [ -x "$candidate" ]; then NFT=$candidate; break; fi
done
if [ -z "$NFT" ]; then
    echo "egress-fence: nft not found on the host" >&2
    exit 1
fi

# The OCI state (stdin) may name a pre-rendered ruleset file to apply instead.
# The state JSON escapes "/" as "\/", so the extracted path is unescaped before
# use — the OCI runtime is not required to emit an unescaped form.
STATE_JSON=$(cat)
RULESET_FILE=$(printf '%s' "$STATE_JSON" | tr -d '\n' \
    | sed -n 's/.*"omnigent-egress-ruleset"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | sed 's|\\/|/|g')

if [ -n "$RULESET_FILE" ]; then
    if [ ! -s "$RULESET_FILE" ]; then
        echo "egress-fence: ruleset $RULESET_FILE is missing, empty, or unreadable" >&2
        exit 1
    fi
    # Feed the ruleset through a variable, not a redirect: if the file cannot be
    # read (SELinux label, permissions) nft would otherwise receive empty stdin
    # and exit 0 — a silent no-fence.
    RULESET_TEXT=$(cat "$RULESET_FILE") || {
        echo "egress-fence: cannot read ruleset $RULESET_FILE" >&2
        exit 1
    }
    if [ -z "$RULESET_TEXT" ]; then
        echo "egress-fence: ruleset $RULESET_FILE is empty" >&2
        exit 1
    fi
    OUTPUT=$(printf '%s\n' "$RULESET_TEXT" | "$NFT" -f - 2>&1)
    if [ $? -ne 0 ]; then
        echo "egress-fence: applying $RULESET_FILE failed: $OUTPUT" >&2
        exit 1
    fi
    # Fail closed unless the table actually exists afterwards.
    if ! "$NFT" list table inet omnigent_fence > /dev/null 2>&1; then
        echo "egress-fence: ruleset $RULESET_FILE applied but the fence table is absent" >&2
        exit 1
    fi
    exit 0
fi

ALLOW_V4=${FENCE_ALLOW_V4:-""}
ALLOW_V6=${FENCE_ALLOW_V6:-""}
DENY_V4=${FENCE_DENY_V4:-"192.168.0.0/16 10.0.0.0/8 172.16.0.0/12"}
DENY_V6=${FENCE_DENY_V6:-"fe80::/10 fd00::/8"}

RULESET=$(
    printf '%s\n' \
        'add table inet omnigent_fence' \
        'flush table inet omnigent_fence' \
        'add chain inet omnigent_fence out { type filter hook output priority 0 ; }' \
        'add rule inet omnigent_fence out oifname "lo" accept' \
        'add rule inet omnigent_fence out ip daddr 127.0.0.0/8 accept' \
        'add rule inet omnigent_fence out ip6 daddr ::1 accept'
    for addr in $ALLOW_V4; do
        printf 'add rule inet omnigent_fence out ip daddr %s accept\n' "$addr"
    done
    for addr in $ALLOW_V6; do
        printf 'add rule inet omnigent_fence out ip6 daddr %s accept\n' "$addr"
    done
    for cidr in $DENY_V6; do
        printf 'add rule inet omnigent_fence out ip6 daddr %s reject\n' "$cidr"
    done
    for cidr in $DENY_V4; do
        printf 'add rule inet omnigent_fence out ip daddr %s reject\n' "$cidr"
    done
)

OUTPUT=$(printf '%s\n' "$RULESET" | "$NFT" -f - 2>&1)
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
    # Fail closed: a container that asked for a fence must not start without one.
    echo "egress-fence: nft failed (exit $STATUS): $OUTPUT" >&2
    exit 1
fi
exit 0
