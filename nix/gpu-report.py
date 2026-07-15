#!/usr/bin/env python3
"""Fetch signed NVIDIA GPU attestation reports for EVERY GPU on the board.

Prints, on stdout:
    {"gpus": [
       {"report": "<base64 SPDM blob>", "cert_chain": ["<base64 DER>", ...]},   # GPU 0
       {"report": "...",                "cert_chain": [...]},                     # GPU 1
       ...                                                                        # one per GPU
    ]}
in GPU-index order, matching the order of the --nonce-hex arguments (one per GPU).

This is the ONLY vendor-specific surface in the Instance. It exists because NVIDIA does not
expose the raw signed report through a stable C/Rust ABI -- the supported guest path is NVML.
Isolating it here keeps the Rust service free of Python and confines what must be validated on
real hardware to a single file.

## Why ALL GPUs, and one nonce each

The shipping model is served with tensor-parallel-size 8, so every GPU on the board holds a
shard of the KV cache -- the user's conversation in plaintext. Confidentiality therefore
depends on all of them running in Confidential Computing mode, not just GPU 0. Attesting a
subset would leave plaintext on unattested GPUs, so we refuse unless we can attest every GPU.

The caller (src/attestation.rs) derives one nonce per GPU index,

    nonce_i = SHA-256( client_nonce || SHA-256(boot TLS SPKI) || u8(i) )

and passes them in order. Each commits GPU i's signature to the freshness challenge, this
instance's TLS key, and its own slot. The client recomputes each and matches it.

## What this checks, and what the CLIENT re-checks

This helper refuses (nonzero exit) unless the system is in CC mode with multi-GPU NVLink
encryption (NVLE) enabled, and every GPU produces a report. That is **defense in depth**: it
runs inside the measured image, but its *inputs* (GPU count, mode) come through the untrusted
hypervisor, so a measured `count == 8` is not itself a proof. The load-bearing checks are on the
client, over signed bytes it recomputes: N pairwise-distinct device certs (proving N real GPUs,
not one GPU answering N times) and each report's own FEATURE_FLAG == MPT. See
architecture.md multi-GPU attestation.

## Two mode enums, do not conflate them

NVML exposes the *system* multi-GPU mode as `multiGpuMode` in `nvmlSystemGetConfComputeSettings`:
`NVML_CC_SYSTEM_MULTIGPU_{NONE=0, PROTECTED_PCIE=1, NVLE=2}`. The *per-GPU signed report* carries
a different field, `OPAQUE_FIELD_ID_FEATURE_FLAG` = {SPT=0, MPT=1, PPCIE=2}. On B200 the system
mode is NVLE and each GPU's signed flag is MPT; PROTECTED_PCIE / PPCIE is Hopper's mode (NVLink
plaintext, switches inside the TCB) and is rejected. We check the *system* enum here; the client
checks the *per-GPU* enum from the signed report.

## UNVALIDATED ON HARDWARE

The NVML calls below are written against NVIDIA's documented Confidential Computing API but have
never run on a B200. Validate during the first paid GPU session (T2) and fix here only -- nothing
upstream of this file depends on how the bytes are obtained. The single assumption most likely to
need a fix is the exact `multiGpuMode` / FEATURE_FLAG value a B200 emits in NVLink-encrypted mode.
"""

import argparse
import base64
import binascii
import json
import sys

import pynvml


NONCE_LEN = 32

# nvmlSystemGetConfComputeSettings().multiGpuMode (NVML). B200 with encrypted NVLink is NVLE.
NVML_CC_SYSTEM_MULTIGPU_NONE = 0
NVML_CC_SYSTEM_MULTIGPU_PROTECTED_PCIE = 1
NVML_CC_SYSTEM_MULTIGPU_NVLE = 2


def der_certs_from_pem_bundle(blob: bytes) -> list[str]:
    """Split a concatenated PEM bundle into base64-DER certs, order preserved (leaf first)."""
    text = blob.decode("utf-8", errors="ignore")
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    out = []
    idx = 0
    while True:
        start = text.find(begin, idx)
        if start == -1:
            break
        stop = text.find(end, start)
        if stop == -1:
            break
        body = text[start + len(begin):stop]
        der = base64.b64decode("".join(body.split()))
        out.append(base64.b64encode(der).decode("ascii"))
        idx = stop + len(end)
    return out


def parse_nonces(hex_args: list[str]) -> list[bytes] | None:
    """Decode the --nonce-hex arguments to 32-byte nonces, or return None on any bad input."""
    nonces = []
    for h in hex_args:
        try:
            n = binascii.unhexlify(h)
        except binascii.Error:
            print("nonce is not hex", file=sys.stderr)
            return None
        if len(n) != NONCE_LEN:
            print(f"nonce must be {NONCE_LEN} bytes, got {len(n)}", file=sys.stderr)
            return None
        nonces.append(n)
    return nonces


def multi_gpu_mode() -> int:
    """Read the system multi-GPU CC mode (NVML_CC_SYSTEM_MULTIGPU_*)."""
    settings = pynvml.nvmlSystemGetConfComputeSettings()
    # pynvml versions differ on the attribute name; the field is documented as multiGpuMode.
    return int(getattr(settings, "multiGpuMode", getattr(settings, "multi_gpu_mode", -1)))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--nonce-hex",
        action="append",
        dest="nonces",
        required=True,
        metavar="HEX",
        help="32-byte nonce, hex; pass once per GPU, in index order",
    )
    args = ap.parse_args()

    nonces = parse_nonces(args.nonces)
    if nonces is None:
        return 2

    pynvml.nvmlInit()
    try:
        count = pynvml.nvmlDeviceGetCount()
        if count != len(nonces):
            # The caller pins the GPU count (it derives exactly one nonce per expected GPU).
            # A board that presents a different number is either misconfigured or an attempt to
            # attest a subset while other GPUs -- holding KV cache -- run unattested. Refuse.
            print(
                f"REFUSING to attest: board reports {count} GPUs but {len(nonces)} were expected. "
                "Every GPU holds KV cache (user plaintext) under tensor parallelism, so all must "
                "be attested. See architecture.md multi-GPU attestation.",
                file=sys.stderr,
            )
            return 1

        # Refuse a system that is not in Confidential Computing mode at all: a report from a
        # non-CC GPU proves nothing about memory confidentiality.
        state = pynvml.nvmlSystemGetConfComputeState()
        if getattr(state, "ccFeature", 0) == 0:
            print("system is not in Confidential Computing mode", file=sys.stderr)
            return 1

        # Refuse anything but multi-GPU NVLink encryption. In NVLE the NVSwitches are outside the
        # trust boundary (NVLink traffic is encrypted), which is exactly what makes attesting the
        # GPUs alone -- with no switch reports -- sound. PROTECTED_PCIE (Hopper) leaves NVLink in
        # the clear with the switches inside the TCB, so it is rejected here.
        mode = multi_gpu_mode()
        if mode != NVML_CC_SYSTEM_MULTIGPU_NVLE:
            print(
                f"REFUSING to attest: system multiGpuMode is {mode}, expected NVLE "
                f"({NVML_CC_SYSTEM_MULTIGPU_NVLE}). Only encrypted-NVLink multi-GPU mode keeps the "
                "switches outside the trust boundary. See architecture.md multi-GPU attestation.",
                file=sys.stderr,
            )
            return 1

        gpus = []
        for i in range(count):
            dev = pynvml.nvmlDeviceGetHandleByIndex(i)
            report = pynvml.nvmlDeviceGetConfComputeGpuAttestationReport(dev, nonces[i])
            cert = pynvml.nvmlDeviceGetConfComputeGpuCertificate(dev)

            # The SPDM blob exactly as signed. Do not reformat it: the client parses these bytes
            # and verifies the signature over them (request || response-minus-signature).
            raw = bytes(report.attestationReport[: report.attestationReportSize])
            chain_blob = bytes(cert.attestationCertChain[: cert.attestationCertChainSize])
            chain = der_certs_from_pem_bundle(chain_blob)

            if not raw or not chain:
                print(f"empty attestation report or cert chain for GPU {i}", file=sys.stderr)
                return 1

            gpus.append({"report": base64.b64encode(raw).decode("ascii"), "cert_chain": chain})
    finally:
        pynvml.nvmlShutdown()

    json.dump({"gpus": gpus}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
