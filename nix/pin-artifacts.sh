#!/usr/bin/env bash
# Pin the vLLM image + model weights into pinned/artifacts.json.
#
# Run this ONCE per release, before building the image. It resolves the model revision to an
# immutable commit, records a sha256 for every file, and resolves the vLLM tag to a digest.
# Those hashes then live inside the measured image, and boot-time verification is mechanical.
#
# Usage:
#   ./nix/pin-artifacts.sh <hf-repo> [revision] [vllm-tag]
#   ./nix/pin-artifacts.sh nvidia/Kimi-K2.7-Code-NVFP4 main latest
#
# ## Where the hashes come from (and why we do not download 595 GB)
#
# For LFS files -- which is every weight shard -- HuggingFace's API exposes `lfs.oid`, and that
# oid IS the sha256 of the file content. So we take it straight from the API. Small non-LFS
# files (configs, tokenizer, python) have only a git blob SHA-1, so those we download and hash
# ourselves; they are a couple hundred KB.
#
# ## Honest caveat about the pin ceremony
#
# Pinning trusts HuggingFace *at this moment* — if you download-and-hash, you hash whatever they
# served you; if you take lfs.oid, you take what they claim. Either way the trust is at pin time.
# What the hash pin buys you is that EVERY LATER FETCH, on every boot, is verified against a
# value frozen inside a measured, published image. To harden the ceremony itself, verify the
# resulting hashes against an independent copy before you publish the measurement.

set -euo pipefail

REPO="${1:?usage: pin-artifacts.sh <hf-repo> [revision] [vllm-tag]}"
REVISION="${2:-main}"
VLLM_TAG="${3:-latest}"
VLLM_IMAGE="docker.io/vllm/vllm-openai"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../pinned/artifacts.json"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> Resolving ${REPO}@${REVISION} to an immutable commit"
COMMIT=$(curl --fail --silent "https://huggingface.co/api/models/${REPO}/revision/${REVISION}" | jq -r '.sha')
[[ -n "$COMMIT" && "$COMMIT" != "null" ]] || { echo "could not resolve revision" >&2; exit 1; }

GATED=$(curl --fail --silent "https://huggingface.co/api/models/${REPO}" | jq -r '.gated')
if [[ "$GATED" != "false" ]]; then
  # A gated repo needs an HF token at boot — a secret, inside a public measured image. No.
  echo "REFUSING: ${REPO} is gated (${GATED}). Boot would need an HF token, which cannot live" >&2
  echo "in a public, measured image. Pick an ungated model." >&2
  exit 1
fi
echo "    commit ${COMMIT} (ungated)"

echo "==> Resolving ${VLLM_IMAGE}:${VLLM_TAG} to a digest"
if command -v skopeo >/dev/null 2>&1; then
  DIGEST=$(skopeo inspect "docker://${VLLM_IMAGE}:${VLLM_TAG}" | jq -r '.Digest')
else
  # Registry API fallback: anonymous pull token, then read the manifest digest.
  REPO_PATH="${VLLM_IMAGE#docker.io/}"
  TOKEN=$(curl --fail --silent \
    "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPO_PATH}:pull" | jq -r '.token')
  DIGEST=$(curl --fail --silent --head \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.oci.image.index.v1+json" \
    -H "Accept: application/vnd.docker.distribution.manifest.list.v2+json" \
    -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "https://registry-1.docker.io/v2/${REPO_PATH}/manifests/${VLLM_TAG}" \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="docker-content-digest"{print $2}')
fi
[[ "$DIGEST" == sha256:* ]] || { echo "could not resolve vLLM digest" >&2; exit 1; }
echo "    ${DIGEST}"

echo "==> Listing files at that commit"
curl --fail --silent "https://huggingface.co/api/models/${REPO}/tree/${COMMIT}?recursive=1" > "${WORK}/tree.json"

# Skip repo furniture we never load. Everything else — weights, configs, tokenizer, and the
# remote-code .py files — is pinned, because --trust-remote-code EXECUTES those .py files.
EXCLUDE='^(\.gitattributes|README\.md|LICENSE.*|USE_POLICY.*)$'

echo "==> Collecting sha256 (LFS: from lfs.oid; small files: downloaded and hashed)"
ENTRIES="[]"
LFS_N=0; SMALL_N=0

while IFS=$'\t' read -r path lfsoid; do
  [[ "$path" =~ $EXCLUDE ]] && continue
  url="https://huggingface.co/${REPO}/resolve/${COMMIT}/${path}"

  if [[ -n "$lfsoid" && "$lfsoid" != "null" ]]; then
    sha="$lfsoid"                       # lfs.oid IS the file's sha256
    LFS_N=$((LFS_N + 1))
  else
    curl --fail --location --silent --retry 5 --output "${WORK}/blob" "$url"
    sha=$(sha256sum "${WORK}/blob" | cut -d' ' -f1)
    rm -f "${WORK}/blob"
    SMALL_N=$((SMALL_N + 1))
  fi

  [[ ${#sha} -eq 64 ]] || { echo "bad sha256 for ${path}: ${sha}" >&2; exit 1; }
  ENTRIES=$(jq --arg p "$path" --arg u "$url" --arg s "$sha" \
               '. + [{path: $p, url: $u, sha256: $s}]' <<<"$ENTRIES")
  printf '    %s  %s\n' "${sha:0:12}…" "$path"
done < <(jq -r '.[] | select(.type=="file") | [.path, (.lfs.oid // "")] | @tsv' "${WORK}/tree.json")

TOTAL=$(jq -r '[.[] | select(.type=="file") | .size] | add' "${WORK}/tree.json")

echo "==> Writing ${OUT}"
jq --arg img "$VLLM_IMAGE" --arg dig "$DIGEST" \
   --arg repo "$REPO" --arg rev "$COMMIT" \
   --argjson files "$ENTRIES" \
   '.vllm.image = $img
    | .vllm.digest = $dig
    | .model.repo = $repo
    | .model.revision = $rev
    | .model.files = $files' \
   "$OUT" > "${WORK}/artifacts.json"
mv "${WORK}/artifacts.json" "$OUT"

cat <<EOF

Pinned.
  vLLM   ${VLLM_IMAGE}@${DIGEST}
  model  ${REPO}@${COMMIT}
  files  $((LFS_N + SMALL_N))  (${LFS_N} via lfs.oid, ${SMALL_N} downloaded+hashed)
  size   $(awk "BEGIN{printf \"%.1f\", ${TOTAL}/1e9}") GB

pinned/artifacts.json is part of the image, so the measurement now covers exactly these bytes.
Rebuild the image; the measurement WILL change.
EOF
