# TASK: Full security audit of Instance/ — close the open items, prove there are no holes

**For the implementing session.** This is the complete handoff for one job: audit every line of
`Instance/` that touches trust, close the findings below, and leave the folder in a state where
the user can do one final build and publish a measurement against it.

Read the project docs first as usual (root [CLAUDE.md](../CLAUDE.md), [architecture.md](../architecture.md),
[implementation.md](../implementation.md), [Instance/CLAUDE.md](./CLAUDE.md)). This file adds only
what those don't have: what has already been audited and cleared, what has **not**, the open
findings with their evidence, and the rules for this specific change.

**Delete this file when the audit is done. Never commit it.** It is untracked on purpose: the user
builds via `git+file://`, and a git flake copies only tracked files, so leaving it here does not
perturb the image hash — but committing it would (`nix/package.nix`'s source filter excludes
`nix/`, `README.md`, `CLAUDE.md`, `flake.*`, `target`, `result` — **not** arbitrary repo-root files).

---

## 1. Why this exists

`Instance/` is published and measured. Its whole value proposition is that an auditor can read
every line that touches their plaintext and rebuild the image to the hash in the release notes.
That makes "probably fine" worthless here: anything an auditor would flag is a defect, and a stale
or over-claiming comment is a defect too, because the comments are part of what gets read.

The image builder is **settled** — reproducibility is gated and green, the boot path is validated
under QEMU/OVMF. Do not reopen either (see §7). This task is exclusively about the *code*.

**Done means:** every file in §3 has been read by you (not summarised by a sub-agent — root
CLAUDE.md §7 "Never delegate understanding"), every finding in §4/§5 is either fixed or explicitly
recorded as an accepted risk with the reason, `cargo test` is green with zero warnings, and the
Instance-test mirror is proven correct by the diff loop in §6.

## 2. Already audited — do not redo

Read in full on 2026-07-16 and found clean. Re-read only if you touch them.

| File | Verdict |
|---|---|
| `src/attestation.rs` | **Clean.** Per-request configfs entries keyed by pid+atomic seq (no cross-binding race between concurrent quotes); cleanup on every error path; errors never surfaced to the client (fails closed to 503, so host paths can't leak); `spawn_blocking` for the sysfs+subprocess work; per-GPU nonce derivation domain-separated by index with golden vectors cross-asserted against the iOS verifier. |
| `src/mtls.rs` | **Clean.** TLS1.3 only, mandatory client auth, strict 65-byte X9.63 `0x04` check, manifest membership enforced *at the handshake*, key possession delegated to rustls. |
| `src/manage.rs` | **Clean.** Signature verified **before** the nonce is recorded (`manage.rs:56`), so unsigned traffic cannot flood `seen_nonces`. A compromised Orchestrator is DoS-capable by design (architecture.md), so unbounded growth by *validly signed* requests is in-model, not a hole. |

Already fixed on 2026-07-16, no need to revisit: stale `DevInstance`/"stubbed"/`plan.md` comments
purged from `lib.rs`, `enroll.rs`, `chat.rs`, `state.rs`, `main.rs`; `.DS_Store` gitignored;
README §6 corrected (it had claimed `CAP_DAC_OVERRIDE` was unfixed and reproducibility unvalidated —
both were wrong).

## 3. NOT yet audited — this is the real gap

Nobody has read these with a security eye. This is the bulk of the job.

| File | Lines | Why it matters |
|---|---|---|
| `nix/fetch-artifacts.sh` | 98 | **THE INTEGRITY BOUNDARY.** The only reason fetching weights from public mirrors is safe. Verify: every fetched byte is sha256-checked against `pinned/artifacts.json` *before* use; no `--force`/skip path; failure is fatal (no partial/degraded start); no TOCTOU between verify and use; the podman OCI pull is digest-pinned, not tag-pinned. |
| `nix/fetch-manifest.sh` | 69 | Same pattern for the cohort manifest, but the input is **launch-parameter/user-data supplied by an untrusted party (GCP + the Orchestrator)**. Verify the hash gate cannot be bypassed and that a missing/bad manifest fails closed. |
| `nix/gpu-report.py` | 195 | The one vendor seam. It must derive nothing, refuse non-CC/non-NVLE hardware, and refuse a GPU-count mismatch. Its stdout is parsed by `attestation.rs`. |
| `src/apple_jwks.rs` | 109 | Apple identity JWT verification against the pinned JWKS. Check: algorithm confusion (RS256 pinned? `alg:none`? HMAC-with-public-key?), `kid` handling, issuer/audience enforcement, expiry. |
| `src/manifest.rs` | 38 | Manifest parse + `contains_pubkey`. Small; check parsing is total and comparisons are sound. |
| `nix/configuration.nix` | ~370 | Only partly reviewed. Audit the systemd hardening of `iron-instance.service`, the podman/CDI surface, `iron-datadisk`'s device selection (it picks "largest non-root device with no filesystem" and reformats it — reason about what happens if that heuristic picks wrong), and the firewall. |
| `tests/` | 495 | Not a hole surface, but check the 22 tests actually assert the security properties they claim rather than the happy path. |
| `pinned/` | — | Confirm nothing secret is in the tree and `artifacts.json` is fully pinned (immutable commit, per-file sha256, OCI digest). |

## 4. Open findings — decide and act

### 4.1 StoreKit x5c chain: no `basicConstraints` / validity checks — MEDIUM

`src/enroll.rs`, `verify_storekit_jws`, the chain walk:

```rust
for i in 0..parsed.len() - 1 {
    parsed[i].verify_signature(Some(parsed[i + 1].public_key())).map_err(|_| ())?;
}
```

It proves each link is *signed by* the next and pins the root by sha256 — but never checks that
intermediates are actually CAs (`basicConstraints: CA:TRUE`), nor `keyUsage: keyCertSign`, nor
`pathLenConstraint`, nor any certificate's validity window. `validation.validate_exp = false` and
`required_spec_claims.clear()` also disable JWS-level expiry.

This is the textbook X.509 flaw: **any end-entity certificate chaining to Apple Root CA - G3 whose
private key an attacker controls could be presented as an "intermediate" to sign a forged StoreKit
leaf, and this chain walk would accept it.** Pinning the root raises the bar (the attacker needs an
Apple-G3-chained cert *and* its key, and G3 is not the Developer-ID root) — but this is exactly what
an auditor greps for, and "the root is pinned" is a mitigation, not a defence.

Fix: enforce `CA:TRUE` + `keyCertSign` on every non-leaf, honour `pathLenConstraint`, and check
`notBefore`/`notAfter` on each cert against the system clock. Decide separately whether to
re-enable JWS expiry (`validate_exp`) — StoreKit payload semantics may not carry a usable `exp`;
verify before assuming.

**Cross-component:** `Orchestrator/_shared/x509_chain.ts` is the mirror of this logic and almost
certainly has the same gap. Root CLAUDE.md §2 forbids letting the two drift — if you fix it here,
fix it there in the same change, or record explicitly why not.

### 4.2 `rate_limits` documented but not implemented — MEDIUM

`README.md` §2 claims RAM-only state holds `client_pubkey -> {member_hash, session_token,
rate_limits}`. `state.rs` `MemberEntry` has **no such field**, and neither `chat.rs` nor
`attestation.rs` enforces anything. The doc over-claims — that alone must be fixed (either
implement it or stop claiming it; root CLAUDE.md §8).

The concrete risk is `/attestation`, not `/v1/chat/completions`: every call mints a TDX quote **and
shells out to attest 8 GPUs**. It cannot be bearer-gated — it runs *before* `/enroll`, it is how the
client decides whether to trust the box at all. But it is not anonymous either: the mTLS handshake
already proved cohort membership, and `mtls.rs`'s `AddClientPubkey` injects `ClientPubkey` into
**every** request on the connection. So `attestation::handler` can take
`Option<Extension<ClientPubkey>>` and rate-limit per client pubkey today, with no protocol change.

400 paying users share one box; one member spamming `/attestation` degrades inference for everyone.
Decide: implement a per-pubkey limit, or accept and delete the README claim. Do not leave the doc
and the code disagreeing.

## 5. Lower-severity observations — verify each, some may be non-issues

I noted these while reading but did not confirm exploitability. Reason about each; a documented
"not a problem because X" is an acceptable outcome.

1. **`member_hash = sha256(sub || originalTransactionId)` has no domain separator**
   (`enroll.rs:85-88`). Concatenation is ambiguous — `("ab","c")` and `("a","bc")` collide. Not
   exploitable today (both values are Apple-assigned, not attacker-chosen), but it is poor hygiene
   in an audited crypto artifact. **The Orchestrator computes the same hash** — changing it is a
   coordinated, breaking change across components and the manifest format. Probably "document the
   reasoning" rather than "fix", but decide deliberately.
2. **Device-cap wrinkle** (`state.rs`, `MemberStore::insert`). Re-enrolling an existing
   `client_pubkey` under a *different* `original_tx_id` rotates the entry without incrementing the
   new transaction's counter, so `DEVICE_CAP` can undercount. Gated by manifest membership (the
   Orchestrator controls which `(pubkey, member_hash)` pairs exist), so likely unreachable — confirm.
3. **`client_point_from_cert` doesn't check the SPKI algorithm OID** (`mtls.rs:37`), only that the
   key bits are a 65-byte `0x04` point. rustls verifies the handshake signature against the declared
   algorithm, so a mismatched OID should fail there — confirm that reasoning holds.
4. **Non-constant-time comparisons**: session tokens via `HashMap` lookup (`state.rs`), manifest
   hex via `eq_ignore_ascii_case` (`enroll.rs:96`). Almost certainly not remotely exploitable;
   confirm and move on.
5. **Panics = DoS.** Grep the request path for `unwrap()`/`expect()`/indexing that a *client* can
   reach. `RwLock` `.unwrap()` on poisoning is the notable one: one panic while holding the lock
   poisons it and every subsequent request panics — a single-request kill switch for the whole box.
   Worth reasoning about seriously.
6. **`IRON_VLLM_URL` / `IRON_GPU_REPORT_CMD` are env-overridable** (`chat.rs:38`,
   `attestation.rs:179`). Fine only because nothing can set env in an image with no admin plane —
   confirm that argument, and that `IRON_INSTANCE_PORT` (README §5 calls it "dev-only") isn't a
   door in the production build.
7. **Secret hygiene.** Root CLAUDE.md §7: no `print()`/log of JWTs, JWS, bearers, `sub`, or message
   text. Verify `sub` really is discarded after `enroll` and appears in no error path, and that
   `chat.rs` logs nothing (the body is the user's prompt).

## 6. Rules for this change

- **Instance-test is NOT "copy the folder".** The user's instinct here is wrong and it will silently
  break the test build. `Instance-test/src/attestation.rs` is **deliberately different** (real TDX CPU
  quote + software-signed synthetic GPU reports, because a non-CC GPU cannot emit a real one).
  Copying `Instance/` over it would replace the synthetic path with the real NVML one and the test
  node would stop working. `Cargo.toml` (package/binary `iron-instance-test`, extra `p384` dep),
  `pinned/synthetic/`, and the absent `gpu-report.py` also diverge on purpose.
  Mirror the **shared files only**, then prove it:
  ```sh
  for f in lib main enroll manage manifest mtls state apple_jwks chat; do
    cp src/$f.rs ../Instance-test/src/$f.rs
  done
  for f in lib main enroll manage manifest mtls state apple_jwks chat; do
    diff -q ../Instance-test/src/$f.rs src/$f.rs
  done   # silence = correct
  ```
  If you fix a bug in the **CPU half** of `attestation.rs`, port it by hand — that half is shared
  logic; only the GPU half is intentionally synthetic.
- **No new dependencies without explicit user approval** (root CLAUDE.md §7). Especially:
  **`aws-lc-rs` must never enter the tree** — ring is the single crypto backend, and aws-lc-rs drags
  in a C toolchain (cmake/bindgen) that breaks the reproducible Nix build. Check `cargo tree` after
  any dep change. `basicConstraints` parsing needs no new crate: `x509-parser` (already in the tree)
  exposes it — verify the current API rather than assuming.
- **No new abstractions for hypothetical needs.** Three similar lines beat a premature trait.
- **Comments explain non-obvious *why*, never what.** And they are read by auditors — no comment may
  over-claim or describe a build that doesn't exist (that was the worst finding of the last pass).
- **Tests are the floor, not the ceiling.** Any security fix gets a test that fails without it.
  22 tests currently pass with zero warnings in both repos; that must remain true.

## 7. Do NOT scope-creep into

- **The image builder.** `image.repart` is settled: the reproducibility gate is green and the fix
  set (offline repart assembly, pinned `hash_seed`, UKI/ESP, initrd storage modules) is done. Don't
  touch `flake.nix`, the `image.repart` block, or `boot.initrd.availableKernelModules`.
- **nixpkgs / MSRV.** Pinned at `nixos-26.05` (rustc 1.95, `resolver = "3"`, `rust-version = "1.95"`).
  Do not `nix flake update` or bump `rust-version`.
- **Attestation gates.** Never relax `EXPECTED_GPU_COUNT`, the CC/NVLE requirement, or the
  measurement checks to make something pass. No dev flags, no stub paths, no test hooks in this
  folder — that is what `../Instance-test/` is for.
- **Hardware-validation items** (T2, first paid GPU session): configfs-tsm under the `DynamicUser`
  sandbox, NVIDIA CC on B200, `FEATURE_FLAG == MPT`, real report layout, GCP NVMe boot. These are
  listed in README §6 and are *unchanged* by this task. Do not try to "fix" them blind.

## 8. Verify before writing (your cutoff is wrong)

- `x509-parser` — confirm the current API for `BasicConstraints` / `KeyUsage` / validity
  (`WebFetch` docs.rs for the **exact version in `Cargo.lock`**, not latest).
- `jsonwebtoken` v10 — confirm `Validation` semantics before changing `validate_exp`.
- Apple StoreKit / App Store Server JWS — confirm the real chain shape (how many intermediates, are
  they CA:TRUE) against Apple's docs before enforcing a rule that breaks real payloads. Getting this
  wrong fails **every** enrollment closed.
- Anything NixOS/systemd: verify against the **nixos-26.05** branch specifically. Option names and
  defaults move between branches — that has already bitten this project twice
  (`config.nixpkgs.hostPlatform` undefined; `boot.initrd.systemd.enable` flipping to `true`).

## 9. Environment and verification

- **Rust runs on the Mac.** `cargo`/`rustc` are Homebrew, **not** on the default PATH:
  `export PATH="/opt/homebrew/bin:$PATH"`. cargo 1.96.1 locally; the image builds with rustc 1.95
  from nixpkgs 26.05, and `resolver = "3"` + `rust-version = "1.95"` keep the lockfile compatible —
  so a crate that builds locally may still be rejected in the image if it needs a newer MSRV.
- **You cannot build the image.** There is no Nix on the Mac. The user builds on the GCP VM
  (`gcloud compute ssh ironserver-instance --project=ironserver-7355608 --zone=us-central1-a`,
  repo at `~/Instance`) and pastes output back. Note: `sudo sysctl -w
  kernel.apparmor_restrict_unprivileged_userns=0` is required on that box for repart's nested
  userns; it does not survive a VM rebuild.
- Before handing back:
  ```sh
  export PATH="/opt/homebrew/bin:$PATH"
  cd Instance      && cargo test && cargo build 2>&1 | grep -c warning   # 22 passed, 0 warnings
  cd ../Instance-test && cargo test && cargo build 2>&1 | grep -c warning   # 22 passed, 0 warnings
  # plus the diff loop in §6
  ```
- Report to the user, per finding: **fixed** (with the test that proves it) or **accepted** (with
  the reason). Do not report a finding as fixed without a test.

## 10. Then, and only then

The user does the final build + gate + smoke test on the VM, and publishes the sha256 in the
GitHub release notes at that exact commit. Every change you make here moves the image hash — that
is expected. The `MRTD` is still pending the first real TDX boot and is **not** this task.
