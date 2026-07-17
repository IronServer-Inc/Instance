# IronServer Instance

An immutable, reproducible NixOS image for an HGX B200 running in a confidential VM
(**Intel TDX** for the CPU, **NVIDIA Confidential Computing** for the 8 GPUs). It serves four
endpoints on `:443`, lives 30 days, then powers itself off. **No SSH, no login, no admin plane,
no outbound network** except one hash-checked artifact fetch at boot.

The folder is self-contained and meant to be **published**: anyone can rebuild the image, confirm
it hashes to the measurement in the release notes, and read every line that runs against their
plaintext. There are no dev flags, no stub code paths, and no secrets in the tree — that is the
whole point of the trust model (§1).

> Historically the code lived in two hand-mirrored folders (`Instance/` = real attestation +
> real vLLM; a `DevInstance/` twin = synthetic attestation + echo model for Mac-side app
> testing). `Instance/` is now standalone. If you keep a dev twin, keep only `attestation.rs`
> and `chat.rs` divergent and every other `src/` file byte-identical — nothing here depends on
> that twin existing.

---

## 1. Security model in one paragraph

The iOS app trusts exactly three things, pinned into it at build time: the **code measurement**
(the TDX `MRTD` of this image), **NVIDIA's attestation root key**, and **Intel's SGX/TDX root
key**. On first connect the app sends a random nonce; the hardware returns a signed report
proving *this exact image* is running and that it controls *this exact TLS key*. Nothing else is
trusted — not us, not GCP, not the Orchestrator. If the measurement does not match, the app
refuses to talk.

**Why fetching weights from public HuggingFace is safe.** Every artifact is verified at boot
against a sha256 that lives *inside the measured image* ([pinned/artifacts.json](pinned/artifacts.json)).
Wrong bytes → the instance refuses to start. So it does not matter who serves the bytes: a hostile
mirror can **deny service, never substitute weights or code**. That is also why the design needs
**zero credentials** — and why a private bucket would be *worse*: its credentials could not be
baked into a public, measured image, so they would arrive as launch parameters handed to GCP and
the Orchestrator, both of which we define as untrusted. The integrity boundary is
[nix/fetch-artifacts.sh](nix/fetch-artifacts.sh); do not soften its hash check or add a `--force`.

---

## 2. How it boots — the image sets itself up

The image is a closed appliance. [nix/configuration.nix](nix/configuration.nix) wires a linear
systemd chain that runs unattended:

```
iron-datadisk   format + mount the largest non-root disk        -> /var/lib/iron
      |
iron-artifacts  fetch + sha256-verify vLLM image + ~595 GB weights (fail-closed, <=3h)
      |
vllm            podman-run the pinned OCI image, TP=8, on 127.0.0.1:8000
      |
iron-manifest   read {manifest_url, manifest_sha256} from provider user-data,
                fetch + hash-verify the cohort manifest         -> /etc/iron/manifest.json
      |
iron-instance   generate the boot TLS key in RAM, bind :443 (mTLS, manifest-gated)

iron-terminate  timer OnBootSec=30d -> systemctl poweroff
```

Every step fails **closed**: a hash mismatch, a missing manifest, or an absent data disk stops the
boot rather than degrading it. The image is self-sustaining **given two things the launcher must
supply**, both of which also fail closed:

1. **Provider user-data** = exactly `{"manifest_url":"https://…","manifest_sha256":"<64 hex>"}`
   (emitted by `Orchestrator/scripts/launch-cohort.sh`). Missing → `iron-manifest` fails →
   `iron-instance` never starts.
2. **An ephemeral data disk.** The 595 GB model cannot live in RAM; `iron-datadisk` auto-selects
   the largest non-root, filesystem-less block device and reformats it every boot. The weights are
   public, so this disk needs integrity (the sha256 check), not secrecy — no user plaintext ever
   touches it. User prompts and KV cache live only in TDX-encrypted RAM and CC-encrypted GPU memory.

**Endpoints (443 only, inbound only):**

```
GET   /attestation?nonce=<64 hex>   CPU + 8 GPU reports bound to the current TLS key
POST  /enroll                       verify Apple JWT + StoreKit JWS + manifest -> session_token
POST  /v1/chat/completions          OpenAI-compatible, bearer-auth, SSE, proxied to loopback vLLM
POST  /manage                       Orchestrator-signed admin ops (revoke a slot); DoS-only worst case
```

**RAM-only state** (gone at power-off): the allowlist `client_pubkey -> {member_hash,
session_token, rate_limits}` and the `originalTransactionId -> device_count` dedup table (cap 3).
`sub` is verified at enroll and immediately discarded.

---

## 3. Attestation bindings (read before touching `src/attestation.rs`)

One CPU report and **eight** GPU reports (envelope version 2), all bound to one client nonce.

**CPU — Intel TDX.** `REPORTDATA` is 64 bytes and entirely caller-supplied, fetched through the
kernel's `configfs-tsm` ABI (Linux >= 6.7, `CONFIG_TSM_REPORTS`): write `inblob`, read the quote
from `outblob`. No vendor SDK.

```
report_data = client_nonce(32) || SHA-256(boot TLS SPKI)(32)
```

**GPU — NVIDIA CC.** NVML's attestation request takes a **32-byte nonce and nothing else**. The
model is served `--tensor-parallel-size 8`, so **every** GPU holds a shard of the KV cache — the
user's plaintext — and all eight must be proven, one report each, challenged with an index-bound
nonce:

```
gpu_nonce_i = SHA-256( client_nonce || SHA-256(boot TLS SPKI) || u8(i) )
```

The iOS client re-derives all eight and additionally requires **exactly 8 reports**, each in CC
mode (signed `FEATURE_FLAG == MPT`), from **8 pairwise-distinct GPU device keys**. That last check
is load-bearing: one CC-mode GPU can sign all eight index-bound nonces, so distinct device
identities are what actually prove eight real GPUs answered. Full reasoning:
[../architecture.md](../architecture.md) § Multi-GPU attestation.

[nix/gpu-report.py](nix/gpu-report.py) is the single vendor seam (NVML). It derives nothing — the
caller passes the eight nonces — and it refuses unless the system is in CC + NVLE mode. If a B200
disagrees with a constant here, fix it **there** and in the iOS verifier together; nothing upstream
depends on how the bytes are obtained.

> Two SPDM-framing facts, either of which fails *every* real report if missed: the P-384 signature
> covers the GET_MEASUREMENTS **request ‖ response** (not the response alone), and the client's
> challenge is the **request** nonce. The one value still unvalidated on a B200 is that NVLE mode
> emits per-GPU `FEATURE_FLAG == MPT`; if wrong, the verifier fails closed and the fix is a
> one-constant change here and in `gpu-report.py`.

---

## 4. Build the image

### 4.0 Where — x86_64 Linux only, never a Mac

The image is a NixOS system closure for `x86_64-linux`, and `systemd-repart` assembles it
**offline in the Nix build sandbox** — no QEMU VM, no `/dev/kvm`, no VM system-features to enable.
Building the closure still needs an `x86_64-linux` builder, and an Apple-Silicon Mac has none (the
nix-darwin `linux-builder` is disabled under Determinate Nix, and Nix cannot come from Homebrew —
both dead ends explained below). Use a plain x86_64 Linux box (no GPU needed to *build*; ~100 GB disk).

```sh
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
# log out/in, then from this directory:
nix build .#image                    # -> result/iron-instance.raw  (raw, ~40 GB sparse)
```

**One build-host prerequisite** (replaces the old KVM one): repart assembles the partitions in a
nested user namespace (`unshare --map-root-user fakeroot systemd-repart`). Ubuntu 23.10+ blocks
unprivileged userns by default, so the build fails with `unshare: write failed /proc/self/uid_map:
Operation not permitted`. Clear it on the build host (not in the image — it has no effect on the
output):

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0    # persist: /etc/sysctl.d/
```

Distros without that restriction (or building as real root) need nothing.

On a Mac you can still *evaluate* the flake (host-agnostic) to catch errors and refresh
`flake.lock` — `cargo clean` first (a non-git flake copies its whole dir into the store), then
`nix flake check`. You cannot build the image there. Use the **Determinate** installer because it
ships a real uninstaller (`/nix/nix-installer uninstall`); Nix cannot come from Homebrew (it needs
a dedicated `/nix` APFS volume + launchd daemon + `nixbld` group).

### 4.1 Pin what you will run (once per release)

[pinned/artifacts.json](pinned/artifacts.json) is already pinned (`nvidia/Kimi-K2.7-Code-NVFP4` at an
immutable commit, 67 shards + configs by sha256, vLLM by OCI digest). Re-run only when you change
the model or the vLLM version — see §5.

```sh
nix run .#pin-artifacts -- <hf-repo> [revision] [vllm-tag]
```

It resolves the revision to an immutable commit, records a sha256 per file, and resolves the vLLM
tag to a digest. **Never hand-write a hash.** Emptied → boot fails closed, by design.

The Orchestrator management pubkey ([pinned/orchestrator_manage_pubkey.sec1](pinned/orchestrator_manage_pubkey.sec1),
65-byte SEC1 point) is measured and published; the private half lives only in Supabase secrets
(`ORCH_MANAGE_PRIVKEY`, PKCS#8 PEM). Rotating it changes the measurement → new image + iOS update.

### 4.2 Gate reproducibility BEFORE you pin a measurement

Two independent builds must be byte-identical. Do not publish a measurement you have not
reproduced.

```sh
nix build .#image --rebuild          # exits 0 only if byte-identical to the first build
sha256sum result/iron-instance.raw   # record this — it is the published image hash
```

If they differ, localize before changing anything: `--rebuild --keep-failed` leaves the second
output at `<store-path>.check`; hash the ESP and root regions separately (offsets are the
`image.repart` partition sizes) and `cmp -l` to count differing bytes per region. repart removes
make-disk-image's leaks at the source (no VM wall-clock, no `bootctl` random-seed), so any residual
is small — hunt it, do not paper over it with normalization hacks.

### 4.3 Boot-test locally (no GPU needed)

The image boots via UEFI (a UKI in the ESP), so QEMU needs OVMF firmware; the raw file in the Nix
store is read-only, so run it under `-snapshot`. TCG (software emulation) is fine — no KVM needed.

```sh
OVMF=$(nix build --no-link --print-out-paths 'nixpkgs#OVMF.fd')/FV/OVMF.fd
nix shell nixpkgs#qemu -c qemu-system-x86_64 \
  -machine q35 -m 4096 -smp 2 -bios "$OVMF" \
  -drive file=result/iron-instance.raw,format=raw,if=virtio \
  -snapshot -nographic
```

Exit QEMU with **`Ctrl-A` then `X`** (`Ctrl-C` goes to the guest). The console stays quiet after
handoff — the image sets `systemd.show_status=false` and has no console login by design — so you
are **not** looking for a prompt. Success is reaching `<<< NixOS Stage 1 >>>` and then mounting the
root partition without a panic. The `iron-*` units will fail (no data disk, no TDX, no GPU, no
manifest) — expected here; this test only proves the kernel, UKI, and root mount work. The failure
that matters is `waiting for device /dev/disk/by-partlabel/root` timing out, which means
`boot.initrd.availableKernelModules` lacks the driver for your disk.

### 4.4 Read the measurement (only real TDX emits it)

`MRTD` is the 48-byte TDX measurement — **not** `sha384sum` of the disk file; it is produced by
hardware and read from the quote. On the first real boot:

```sh
cat /sys/kernel/config/tsm/report/*/outblob   # the quote; MRTD is inside it
```

The same value then goes in **three** places that must agree forever: the hardware report, iOS
`Constants.Attestation.expectedImageMeasurement`, and this repo's GitHub release notes.

---

## 5. Maintain it

Every change under `pinned/`, `src/`, `nix/`, or `flake.lock` changes the image, hence the
measurement. The rule of thumb: **anything that moves the measurement needs a rebuild + a new
`expectedImageMeasurement` in the iOS app.** The table says which changes *also* need more.

| You want to… | Change | Also update |
|---|---|---|
| **Swap the model** | `nix run .#pin-artifacts -- <repo> <rev>`; adjust `vllm.args` (`--served-model-name`, parsers) in `artifacts.json` | iOS chat `model` name if you rename it; check VRAM math (below) |
| **Bump vLLM** | `nix run .#pin-artifacts -- <same repo> <same rev> <new-tag>` (re-resolves the digest) | nothing else, unless new args are needed |
| **Change TP degree** | `--tensor-parallel-size` in `artifacts.json` **and** `EXPECTED_GPU_COUNT` in `src/attestation.rs` | iOS `Constants.Attestation.expectedGPUCount` — they must match |
| **B200 → B300** | `hardware.nvidia.package` in `configuration.nix` may need a newer driver (Blackwell Ultra); VRAM per GPU rises (~180→~288 GB) so you can raise context / batch | GPU count is still 8 per board → `EXPECTED_GPU_COUNT`/iOS stay 8; NVLE/MPT unchanged (still Blackwell); measurement + iOS pin |
| **New GPU count / board** | `EXPECTED_GPU_COUNT` + `--tensor-parallel-size` + iOS `expectedGPUCount` | driver, VRAM math, measurement |
| **Re-pin Apple JWKS** (Apple rotated) | replace `pinned/apple_sign_in_jwks.json` | measurement + iOS pin |
| **Rotate management key** | `openssl ec … -pubout -outform DER | tail -c 65 > pinned/orchestrator_manage_pubkey.sec1`; set new `ORCH_MANAGE_PRIVKEY` in Supabase | measurement + iOS pin |
| **Bump nixpkgs / kernel / driver** | `nix flake update` | reproduce (§4.2) + measurement + iOS pin |

**VRAM math** (why TP=8 for Kimi): ~74 GB of NVFP4 weights per GPU on a 180 GB B200 leaves ~105
GB/GPU for KV cache — enough for the concurrent cohort. A smaller model can drop TP; if it fits one
GPU, TP=1 and `EXPECTED_GPU_COUNT=1`. **What forces an iOS app update:** the measurement (every
release), the GPU count, and the vendor roots (near-immutable). Intermediate certs travel inside
each attestation envelope and never need a pin.

### Configuration surface (the knobs)

| Where | Knob | Meaning |
|---|---|---|
| `artifacts.json` | `model.*`, `vllm.digest`, `vllm.args` | what runs; measured |
| `src/attestation.rs` | `EXPECTED_GPU_COUNT = 8` | GPU reports required; mirror in iOS |
| `configuration.nix` | `image.repart` root `SizeMinBytes = "40G"` | root fs floor (OS + the vLLM OCI pull); weights go on the data disk |
| `configuration.nix` | `hardware.nvidia.package`, `boot.kernelPackages` | driver + kernel; `open = true` is required for CC |
| `configuration.nix` env | `IRON_VLLM_URL`, `IRON_GPU_REPORT_CMD`, `IRON_MANIFEST_PATH` | wiring; do not point off-box |
| runtime env | `IRON_INSTANCE_PORT` | dev-only override of `:443` (unset in the image) |

---

## 6. Known unvalidated surfaces (be honest here)

The Rust service is fully tested (`cargo test` — 22 tests: enroll, manage, mTLS, chat proxy, crypto
golden vectors). **Everything below has never executed on the target hardware** and is the content
of the first paid GPU session. Budget for it to overrun.

| Surface | Why unverified | Lives in |
|---|---|---|
| **configfs-tsm under a locked-down service** | `iron-instance.service` runs `DynamicUser` + only `CAP_NET_BIND_SERVICE`, but creating a `/sys/kernel/config/tsm/report/*` entry needs root/`CAP_DAC_OVERRIDE`. **As wired, every `/attestation` may 503.** Fix + validate first. | `nix/configuration.nix`, `src/attestation.rs` |
| NVIDIA driver in CC mode; NVML attestation over all 8 GPUs | needs a B200 with CC on | `nix/configuration.nix`, `nix/gpu-report.py` |
| NVLE mode + per-GPU `FEATURE_FLAG == MPT` | the one CC value inferred, not confirmed on B200; verifier fails closed if wrong | `nix/gpu-report.py`, `src/attestation.rs`, iOS `AttestationVerifier` |
| Real signed-report layout (request‖response, 8 device certs) | modelled on nvtrust + a Hopper sample; never parsed from a live B200 | `src/attestation.rs`, iOS `AttestationVerifier` |
| TDX quote via configfs-tsm | needs TDX hardware | `src/attestation.rs` |
| Which metadata flavor serves user-data (EC2/GCE/OpenStack probe order) | GCE for this deployment; confirm + prune | `nix/fetch-manifest.sh` |
| Reproducible byte-identical rebuild + the measurement | only a real TDX boot emits `MRTD` | §4.2, §4.4 |

Fix findings **inside `nix/gpu-report.py`** where you can — nothing upstream depends on how the
bytes are obtained.

---

## 7. Layout

```
Cargo.toml  Cargo.lock
flake.nix              image + pin-artifacts app; at the crate root so it can see src/ and pinned/
src/
  attestation.rs       REAL: TDX quote (configfs-tsm) + NVIDIA report over all 8 GPUs
  chat.rs              REAL: vLLM proxy, SSE relayed byte-for-byte
  enroll.rs manage.rs manifest.rs mtls.rs state.rs apple_jwks.rs lib.rs main.rs
pinned/                MEASURED. Changing any of these changes the image hash.
  apple_sign_in_jwks.json          Apple Sign-In JWKS snapshot
  orchestrator_manage_pubkey.sec1  management pubkey (private half: Supabase secret)
  artifacts.json                   Kimi-K2.7-Code-NVFP4 @ immutable commit + vLLM digest, all by sha256
nix/
  configuration.nix    the machine: kernel, NVIDIA CC, podman, the boot chain, firewall, 30-day timer
  package.nix          the Rust service derivation
  fetch-artifacts.sh   THE INTEGRITY BOUNDARY: fetch + sha256-verify, refuse on mismatch
  fetch-manifest.sh    same pattern for the cohort manifest (launch parameter)
  pin-artifacts.sh     build-time: resolve to immutable digests/hashes
  gpu-report.py        the one vendor seam (NVML)
tests/                 22 tests
```

---

## 8. Test node (non-production hardware)

A functional test node — GCP 8×B200 + Intel TDX **with GPU Confidential Computing off** — is a
**separate build**, not this image with a flag flipped, because the production attestation gates
(GPU CC in `gpu-report.py`, `FEATURE_FLAG == MPT` in the verifier) refuse non-CC GPUs by design.
Keep that variant in its own folder so this image stays audit-clean: same `src/` except the
attestation path, which drops the NVIDIA-CC requirement. See that folder's README for exactly what
diverges and how to keep it in sync. **Never** relax an attestation gate in *this* folder.
