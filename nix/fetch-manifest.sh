#!/usr/bin/env bash
# Fetch and verify the cohort member manifest named by the launch parameter.
#
# Same integrity pattern as iron-fetch-artifacts: the bytes come off the
# untrusted network, the hash that judges them arrives out of band (the
# provider's user data, next to the URL), and a mismatch stops the boot. Both
# the Orchestrator and the provider are untrusted: the worst a wrong manifest
# can do is denial of service, never admission of a non-member -- /enroll still
# requires an Apple-signed identity and StoreKit receipt that hash into the
# presented manifest entry.
#
# User data must be exactly: {"manifest_url": "https://...", "manifest_sha256": "<64 hex>"}
# (emitted by Orchestrator/scripts/launch-cohort.sh via cohorts-admin/launch).
#
# Usage: iron-fetch-manifest <output-path>

set -euo pipefail

OUT="${1:?usage: iron-fetch-manifest <output-path>}"

die() { echo "iron-manifest: FATAL: $*" >&2; exit 1; }

# Provider metadata endpoints, tried in order. Which flavor the chosen provider
# answers is confirmed on the first real boot; prune the rest then.
fetch_user_data() {
  local out
  # EC2 / IMDS style
  if out=$(curl -fsS --max-time 5 http://169.254.169.254/latest/user-data 2>/dev/null); then
    echo "$out"
    return 0
  fi
  # GCE style
  if out=$(curl -fsS --max-time 5 -H "Metadata-Flavor: Google" \
      http://169.254.169.254/computeMetadata/v1/instance/attributes/user-data 2>/dev/null); then
    echo "$out"
    return 0
  fi
  # OpenStack config-drive-over-HTTP style
  if out=$(curl -fsS --max-time 5 http://169.254.169.254/openstack/latest/user_data 2>/dev/null); then
    echo "$out"
    return 0
  fi
  return 1
}

user_data=""
for attempt in $(seq 1 30); do
  if user_data=$(fetch_user_data); then
    break
  fi
  echo "iron-manifest: metadata not answering yet (attempt $attempt/30)" >&2
  sleep 2
done
[[ -n "$user_data" ]] || die "no metadata endpoint answered with user data"

url=$(jq -er '.manifest_url' <<<"$user_data") || die "user data has no manifest_url"
want=$(jq -er '.manifest_sha256' <<<"$user_data") || die "user data has no manifest_sha256"
[[ "$url" == https://* ]] || die "manifest_url is not https"
[[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "manifest_sha256 is not 64 lowercase hex chars"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsS --max-time 60 --retry 10 --retry-delay 6 "$url" -o "$tmp" || die "manifest fetch failed"

got=$(sha256sum "$tmp" | cut -d' ' -f1)
[[ "$got" == "$want" ]] || die "manifest hash mismatch: got $got want $want -- refusing to start"

install -D -m 0444 "$tmp" "$OUT"
echo "iron-manifest: verified manifest ($want) -> $OUT"
