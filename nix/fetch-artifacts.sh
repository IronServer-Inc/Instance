#!/usr/bin/env bash
# Fetch and verify the pinned artifacts, then (with --run-vllm) exec the model server.
#
# THIS SCRIPT IS THE INTEGRITY BOUNDARY. Every byte we pull off the public internet is checked
# against a sha256 that is baked into the measured image. If a byte is wrong we refuse to run.
# That is what makes public mirrors safe: a hostile CDN can withhold bytes (denial of service)
# but can never substitute them (compromise).
#
# Usage:
#   iron-fetch-artifacts <artifacts.json> <data-dir>
#   iron-fetch-artifacts --run-vllm <artifacts.json> <data-dir>

set -euo pipefail

RUN_VLLM=0
if [[ "${1:-}" == "--run-vllm" ]]; then
  RUN_VLLM=1
  shift
fi

ARTIFACTS="${1:?usage: iron-fetch-artifacts [--run-vllm] <artifacts.json> <data-dir>}"
DATA_DIR="${2:?usage: iron-fetch-artifacts [--run-vllm] <artifacts.json> <data-dir>}"
MODEL_DIR="${DATA_DIR}/model"

die() { echo "iron-artifacts: FATAL: $*" >&2; exit 1; }

IMAGE=$(jq -r '.vllm.image' "$ARTIFACTS")
DIGEST=$(jq -r '.vllm.digest' "$ARTIFACTS")
REPO=$(jq -r '.model.repo' "$ARTIFACTS")
REVISION=$(jq -r '.model.revision' "$ARTIFACTS")
FILE_COUNT=$(jq -r '.model.files | length' "$ARTIFACTS")

# Fail closed on an unpinned image. An empty digest or file list means nobody ran
# pin-artifacts.sh, and we must never "helpfully" fetch whatever is latest.
[[ -n "$DIGEST" && "$DIGEST" == sha256:* ]] || die "vllm.digest is not pinned (run nix/pin-artifacts.sh)"
[[ "$FILE_COUNT" -gt 0 ]] || die "model.files is empty (run nix/pin-artifacts.sh)"
[[ -n "$REPO" && -n "$REVISION" ]] || die "model.repo/revision not pinned"

if [[ "$RUN_VLLM" == "1" ]]; then
  # iron-artifacts.service already verified everything; just run the pinned image.
  # One argv entry per JSON array element -- an arg containing a space stays one arg.
  mapfile -t VLLM_ARGS < <(jq -r '.vllm.args[]' "$ARTIFACTS")
  exec podman run --rm \
    --name vllm \
    --network=host \
    --device nvidia.com/gpu=all \
    --security-opt=label=disable \
    -v "${MODEL_DIR}:/model:ro" \
    "${IMAGE}@${DIGEST}" \
    --model /model \
    "${VLLM_ARGS[@]}"
fi

echo "iron-artifacts: model ${REPO}@${REVISION}, ${FILE_COUNT} file(s)"
mkdir -p "$MODEL_DIR"

# ---------------------------------------------------------------------------
# 1. vLLM, by digest. podman verifies the manifest digest itself; pinning by digest (never by
#    tag) is what makes that a hash pin rather than a promise.
# ---------------------------------------------------------------------------
echo "iron-artifacts: pulling ${IMAGE}@${DIGEST}"
podman pull "${IMAGE}@${DIGEST}" \
  || die "could not pull the pinned vLLM image (digest mismatch, or upstream is down)"

# ---------------------------------------------------------------------------
# 2. Model weights, one file at a time, each verified against its pinned sha256.
# ---------------------------------------------------------------------------
for i in $(seq 0 $((FILE_COUNT - 1))); do
  path=$(jq -r ".model.files[$i].path"   "$ARTIFACTS")
  url=$(jq -r  ".model.files[$i].url"    "$ARTIFACTS")
  want=$(jq -r ".model.files[$i].sha256" "$ARTIFACTS")
  dest="${MODEL_DIR}/${path}"

  [[ -n "$want" ]] || die "no sha256 pinned for ${path}"
  mkdir -p "$(dirname "$dest")"

  if [[ -f "$dest" ]] && [[ "$(sha256sum "$dest" | cut -d' ' -f1)" == "$want" ]]; then
    echo "iron-artifacts: ${path} already present and verified"
    continue
  fi

  echo "iron-artifacts: fetching ${path}"
  # --location: HF redirects to its CDN. Transport security is irrelevant to integrity here
  # (the hash decides), but we still use HTTPS so a MITM cannot even cause a wasted download.
  curl --fail --location --silent --show-error --retry 5 --retry-delay 5 \
       --output "$dest" "$url" \
    || die "download failed for ${path}"

  got=$(sha256sum "$dest" | cut -d' ' -f1)
  if [[ "$got" != "$want" ]]; then
    rm -f "$dest"
    # This is the line that makes public mirrors safe. Do not soften it.
    die "sha256 MISMATCH for ${path}: pinned ${want}, got ${got} -- refusing to start"
  fi
  echo "iron-artifacts: ${path} verified"
done

echo "iron-artifacts: all artifacts verified against the measured image"
