# Instance — Working Rules (production build)

Scope: everything under `Instance/`. Project-wide rules: [../CLAUDE.md](../CLAUDE.md).
Design: [../architecture.md](../architecture.md) § vLLM Instance. Build/run: [README.md](./README.md).
A non-CC test node lives in the sibling [../Instance-test/](../Instance-test/) (see below).

---

## What this folder is

The **production** Instance: real Intel TDX + NVIDIA attestation, real vLLM proxy, and the
NixOS image. It is meant to be **published**, so an auditor can rebuild the image, confirm it
hashes to the measurement in the release notes, and read every line that touches plaintext.

Two consequences that override convenience:

1. **No dev flags. No stub code paths. No test hooks.** A door that does not exist cannot be
   opened. If you find yourself adding `if cfg!(debug)` here, you are in the wrong folder —
   put it in `../Instance-test/` (the test build).
2. **No secrets, ever.** The image is public *and measured*. Anything embedded here is
   published. This is precisely why artifacts are fetched from public mirrors with hash pins
   rather than from credentialed buckets.

---

## Standalone, with a test sibling

`Instance/` is the **standalone production build** — real Intel TDX + NVIDIA attestation, real
vLLM, the published/measured image. (An earlier `DevInstance/` twin, a Mac-side synthetic build,
has been removed; nothing here depends on it.)

The sibling `../Instance-test/` is a **non-CC test node** build (GCP 8×B200 + Intel TDX, GPU
Confidential Computing off): identical to this folder except `src/attestation.rs`, which keeps
the real TDX CPU quote but software-signs synthetic GPU reports (a non-CC GPU can't emit a real
one). It is disposable, embeds test keys, and must never be published as production.

When you change shared logic here — anything but the GPU half of `attestation.rs` — mirror it
into the test build **in the same change**, then prove only `attestation.rs` differs:

```sh
for f in lib main enroll manage manifest mtls state apple_jwks chat; do
  diff -q ../Instance-test/src/$f.rs src/$f.rs
done   # silence = correct
```

Both crates share the lib name (`iron_instance`) while the package/binary names differ
(`iron-instance` vs `iron-instance-test`). Do not "fix" that.

---

## Pinned material is measured — never invent a value

Everything in `pinned/` is inside the image, so its bytes are covered by the TDX measurement.
Changing any of them changes the image hash, which changes what the app must trust.

- `apple_sign_in_jwks.json` — real Apple JWKS snapshot. Re-pin when Apple rotates → new image.
- `orchestrator_manage_pubkey.sec1` — the **production** Orchestrator management public key
  (65-byte X9.63 point; public by design — it is measured and published). The test build pins the
  same key deliberately. The private half lives in Supabase secrets (`ORCH_MANAGE_PRIVKEY`) and
  on the operator machine, never in this repo. Rotating it changes the measurement → new image
  + iOS app update.
- `artifacts.json` — **pinned** (`nvidia/Kimi-K2.7-Code-NVFP4` at an immutable commit, 67 shards by
  sha256, vLLM by OCI digest). Re-pin only via `nix/pin-artifacts.sh`, which resolves the commit,
  the per-file sha256s and the OCI digest. **Never hand-write a hash.** Emptied → boot fails
  closed, by design.

---

## The integrity boundary

`nix/fetch-artifacts.sh` is the reason public downloads are safe. It verifies every fetched
byte against a sha256 that lives in the measured image and **refuses to start on mismatch**.
Wrong bytes → no boot. A hostile mirror can deny service; it can never substitute weights or
code. Do not soften that check, do not add a `--force`, do not fall back to "whatever is
latest".

---

## Attestation: the bindings are not symmetric

- **CPU (TDX).** `REPORTDATA` is 64 B and fully caller-supplied →
  `report_data = nonce || SHA-256(SPKI)`. Fetched via `configfs-tsm` (Linux ≥ 6.7): write
  `inblob`, read `outblob`. No vendor SDK. One TEE, N GPUs inside it.
- **GPU (NVIDIA), envelope v2.** The model runs TP=8, so every GPU holds a KV-cache shard (user
  plaintext) and **all 8 are attested**, one report each. The call takes only a 32-byte nonce, so
  the key is folded in per index: `gpu_nonce_i = SHA-256(nonce || SHA-256(SPKI) || u8(i))`. The
  client requires 8 reports, each signed `FEATURE_FLAG == MPT`, from **8 distinct device keys**
  (per-index nonces alone don't stop one CC GPU signing all 8). The NVML blob is request‖response
  and the signature covers both; the challenge is the **request** nonce. Full reasoning:
  architecture.md § Multi-GPU attestation.

`nix/gpu-report.py` is the single vendor-specific seam — it derives nothing; the caller passes it
the 8 per-index nonces and it attests every GPU, refusing unless the system is in CC + NVLE mode.
If hardware disagrees with us, fix it **there** (and the matching `FEATURE_FLAG`/`multiGpuMode`
constant in the verifier) — nothing else upstream depends on how the bytes are obtained.

---

## Verification protocol (your cutoff is wrong here)

NixOS, CUDA, the NVIDIA driver, and TDX toolchains move monthly. Before writing:

- `WebSearch` / `WebFetch` the vendor page. **Do not invent flags, ioctls, or report layouts.**
- Kernel TDX: <https://docs.kernel.org/arch/x86/tdx.html>; configfs-tsm ABI on LWN.
- NVIDIA CC: <https://docs.nvidia.com/nvtrust/>.
- Nix image builders: `make-disk-image.nix` in nixpkgs. Use **raw**, not qcow2 — reproducibility
  is gated by diffing two builds and `diffoscope` cannot diff qcow2.

**The image builds on `x86_64-linux` only.** `make-disk-image.nix` boots a QEMU VM to assemble
the disk, so an ARM Mac would have to emulate an x86 machine inside an emulated x86 process. Do
not send the user down the nix-darwin `linux-builder` path: it is disabled under Determinate Nix
(`nix.enable = false` is required for coexistence, and it takes the `nix.*` options with it).
README § 3 records both dead ends.

## What "tested" means here

`cargo test` (22 tests) covers enroll, manage, mTLS, the chat proxy, and the crypto helpers.
It does **not** cover: the image building, the NVIDIA driver in CC mode, NVML attestation, or
the TDX quote path — none of which can run on a Mac. Those are the content of the first paid
GPU session, and README § 6 lists them explicitly. Do not describe them as done.

Reproducibility is a **gate**, not a hope: build twice, `sha256sum` both, and only then pin a
measurement.
