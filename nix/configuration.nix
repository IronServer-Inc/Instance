{ config, lib, pkgs, modulesPath, ironSrc, ... }:

let
  ironInstance = pkgs.callPackage ./package.nix { inherit ironSrc; };

  # Pinned, MEASURED artifact list. Its bytes are part of the image, so changing what we fetch
  # changes the image hash. Copied to its own store path so systemd units reference a path
  # derived from these bytes alone -- referencing ironSrc directly would tie the image to the
  # whole flake tree's hash, which moves on every doc edit. See pinned/artifacts.json.
  artifacts = pkgs.writeText "artifacts.json" (builtins.readFile (ironSrc + "/pinned/artifacts.json"));

  # Fetch + sha256-verify every artifact. Refuses to continue on any mismatch, which is what
  # makes it safe to pull from public mirrors: wrong bytes -> no boot, never a substitution.
  fetchArtifacts = pkgs.writeShellApplication {
    name = "iron-fetch-artifacts";
    runtimeInputs = with pkgs; [ curl jq coreutils podman ];
    text = builtins.readFile ./fetch-artifacts.sh;
  };

  # Launch parameter -> cohort manifest. Same integrity pattern as fetch-artifacts.sh: user
  # data names {manifest_url, manifest_sha256}; the bytes are fetched from the untrusted
  # network and judged by the hash. Mismatch -> no manifest -> no client can complete the
  # mTLS handshake (fail closed).
  fetchManifest = pkgs.writeShellApplication {
    name = "iron-fetch-manifest";
    runtimeInputs = with pkgs; [ curl jq coreutils ];
    text = builtins.readFile ./fetch-manifest.sh;
  };

  # Vendor-specific seam: asks NVIDIA's tooling for a signed GPU attestation report over our
  # nonce and prints {"report": "<b64>", "cert_chain": ["<b64-DER>", ...]}.
  # MUST be validated on real B200 hardware (T2) -- see README § Known unvalidated surfaces.
  gpuReport = pkgs.writeShellApplication {
    name = "iron-gpu-report";
    runtimeInputs = [ (pkgs.python3.withPackages (ps: [ ps.pynvml ])) ];
    text = ''exec python3 ${./gpu-report.py} "$@"'';
  };

  dataDir = "/var/lib/iron";
in
{
  # image.repart is not in the default module set; it must be imported explicitly.
  imports = [ "${modulesPath}/image/repart.nix" ];

  system.stateVersion = "25.05";
  networking.hostName = "ironserver-instance";

  ############################################################################
  # Boot / kernel
  ############################################################################

  # Nothing installs a bootloader into this image. The ESP contents declared in the
  # image.repart block below ARE the boot path (systemd-boot as the EFI default loader,
  # plus the UKI it loads); grub is NixOS's default installer, so disable it explicitly.
  boot.loader.grub.enable = false;

  # configfs-tsm (CONFIG_TSM_REPORTS) is how the guest gets a TDX quote: write 64 bytes of
  # REPORTDATA to inblob, read the quote from outblob. Mainline since 6.7.
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.kernelModules = [ "tdx_guest" ];
  # systemd mounts configfs at /sys/kernel/config; the TSM directory appears under it.
  boot.kernelParams = [
    "console=ttyS0"
    # The instance has no console user and no admin plane.
    "systemd.show_status=false"
  ];

  ############################################################################
  # Image assembly (systemd-repart)
  #
  # The image is assembled OFFLINE in the Nix build sandbox by systemd-repart --
  # no QEMU VM, no wall-clock filesystem writes. That is what makes it byte-
  # reproducible: the old make-disk-image.nix built the disk inside a booted VM
  # running on real time and could never hash the same twice. GPT and partition
  # UUIDs derive from the module's fixed seed; the ESP is populated from declared
  # files (no bootctl, so no random-seed and no FAT timestamps); the kernel,
  # initrd, and cmdline ship as a single UKI (also the cleaner TDX measurement
  # object). Reference: nixos/tests/appliance-repart-image.nix on nixos-25.05.
  ############################################################################

  image.repart = {
    name = "iron-instance";
    # 512-byte logical sectors: OVMF rejects the repart default of 4096, and GCP
    # persistent disks are 512-logical, so 512 is what both the smoke test and the
    # real target want.
    sectorSize = 512;
    partitions = {
      "esp" = {
        contents =
          let
            # pkgs.stdenv.hostPlatform, NOT config.nixpkgs.hostPlatform: this flake sets the
            # platform through nixosSystem's `system` arg, which populates nixpkgs.system --
            # the nixpkgs.hostPlatform *option* stays undefined, so reading it errors. This is
            # also how uki.nix itself reads efiArch.
            efiArch = pkgs.stdenv.hostPlatform.efiArch;
          in
          {
            # systemd-boot as the fallback EFI loader...
            "/EFI/BOOT/BOOT${lib.toUpper efiArch}.EFI".source =
              "${pkgs.systemd}/lib/systemd/boot/efi/systemd-boot${efiArch}.efi";
            # ...and the UKI it boots (kernel + initrd + cmdline in one PE binary).
            "/EFI/Linux/${config.system.boot.loader.ukiFile}".source =
              "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
          };
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          SizeMinBytes = "256M"; # UKI is ~30 MB with linuxPackages_latest; leave headroom
        };
      };
      "root" = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = {
          Type = "root";
          Format = "ext4";
          Label = "root"; # fileSystems."/" mounts by this GPT partition label
          # A floor, not padding: podman pulls the pinned vLLM OCI image (tens of GB)
          # into /var/lib/containers on THIS fs at boot. (The 595 GB weights go on the
          # separate ephemeral data disk, never here.) make-disk-image gave this via
          # diskSize = 40960.
          SizeMinBytes = "40G";
        };
      };
    };
  };

  ############################################################################
  # Filesystems. systemd-repart labels the GPT partitions it creates; the root
  # fs is mounted by that partition label. Nothing mounts the ESP at runtime:
  # UEFI reads it at boot and the image has no admin plane that would update it.
  ############################################################################

  fileSystems."/" = {
    device = "/dev/disk/by-partlabel/root";
    fsType = "ext4";
  };

  ############################################################################
  # GPU: NVIDIA driver with Confidential Computing
  ############################################################################

  # The NVIDIA driver is the only unfree package allowed in the image; the predicate
  # (rather than a blanket allowUnfree) enforces that. It must live here, not in the
  # flake: nixosSystem instantiates its own nixpkgs, so flake-level pkgs config never
  # reaches module evaluation.
  nixpkgs.config.allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "nvidia-x11" ];

  hardware.graphics.enable = true;
  hardware.nvidia = {
    # CC mode requires the OPEN kernel modules. The proprietary blob does not support it.
    open = true;
    modesetting.enable = false;
    nvidiaSettings = false;
    powerManagement.enable = false;
    package = config.boot.kernelPackages.nvidiaPackages.production;
  };
  services.xserver.videoDrivers = [ "nvidia" ];

  # Lets the vLLM container see the GPU (CDI).
  hardware.nvidia-container-toolkit.enable = true;
  virtualisation.podman = {
    enable = true;
    dockerSocket.enable = false;
  };

  ############################################################################
  # No admin plane. This is the whole point of the trust model.
  ############################################################################

  services.openssh.enable = false;
  users.mutableUsers = false;
  users.users.root.hashedPassword = "!"; # locked; no console login either
  # NixOS refuses to evaluate a config nobody can log in to unless told the
  # lockout is deliberate. Here it is the design: no SSH, no console, no admin plane.
  users.allowNoPasswordLogin = true;
  security.sudo.enable = false;
  services.getty.autologinUser = null;

  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 443 ]; # inbound only, nothing else
    allowedUDPPorts = [ ];
  };

  ############################################################################
  # Weight storage
  #
  # The model is ~595 GB, so it cannot live in RAM. It goes on the instance's ephemeral
  # local disk, freshly formatted at every boot.
  #
  # This is NOT a confidentiality regression: the weights are PUBLIC (we fetch them from
  # HuggingFace), so they need integrity, not secrecy -- and integrity is what the sha256
  # verification gives. User plaintext never touches this disk: prompts and KV cache live
  # only in TDX-encrypted RAM and CC-encrypted GPU memory, and the process holds nothing
  # else. Nothing about a user survives the power going off.
  ############################################################################

  systemd.services.iron-datadisk = {
    description = "Format and mount the ephemeral disk for model weights";
    wantedBy = [ "multi-user.target" ];
    before = [ "iron-artifacts.service" ];
    serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
    path = with pkgs; [ util-linux e2fsprogs coreutils gawk ];
    script = ''
      set -euo pipefail
      # Largest block device that is not the root disk and carries no filesystem.
      root_disk=$(lsblk -no PKNAME "$(findmnt -no SOURCE /)" | head -1)
      dev=$(lsblk -bdno NAME,SIZE,FSTYPE | awk -v r="$root_disk" '$3=="" && $1!=r {print $2, $1}' \
            | sort -rn | head -1 | awk '{print $2}')
      if [ -z "''${dev:-}" ]; then
        echo "iron-datadisk: no ephemeral disk found -- cannot stage 595 GB of weights" >&2
        exit 1
      fi
      echo "iron-datadisk: formatting /dev/$dev"
      mkfs.ext4 -F -L ironmodel "/dev/$dev"
      mkdir -p ${dataDir}
      mount "/dev/$dev" ${dataDir}
      chmod 0700 ${dataDir}
    '';
  };

  ############################################################################
  # Boot pipeline: fetch+verify artifacts -> vLLM -> IronServer
  ############################################################################

  systemd.services.iron-artifacts = {
    description = "Fetch and sha256-verify pinned vLLM image + model weights (~595 GB)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" "podman.service" "iron-datadisk.service" ];
    requires = [ "iron-datadisk.service" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${fetchArtifacts}/bin/iron-fetch-artifacts ${artifacts} ${dataDir}";
      # A hash mismatch must stop the machine, not degrade it.
      SuccessExitStatus = [ 0 ];
      TimeoutStartSec = "3h"; # 595 GB, however fast the provider's link is
    };
    environment.IRON_MODEL_DIR = "${dataDir}/model";
  };

  systemd.services.vllm = {
    description = "vLLM (pinned OCI image, digest-verified)";
    wantedBy = [ "multi-user.target" ];
    after = [ "iron-artifacts.service" ];
    requires = [ "iron-artifacts.service" ]; # no artifacts -> no model server
    serviceConfig = {
      Type = "simple";
      Restart = "on-failure";
      ExecStart = "${fetchArtifacts}/bin/iron-fetch-artifacts --run-vllm ${artifacts} ${dataDir}";
      TimeoutStartSec = "30min"; # weights load slowly
    };
  };

  systemd.services.iron-manifest = {
    description = "Fetch and sha256-verify the cohort manifest (launch parameter)";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${fetchManifest}/bin/iron-fetch-manifest /etc/iron/manifest.json";
      TimeoutStartSec = "10min";
    };
  };

  systemd.services.iron-instance = {
    description = "IronServer Instance (attested mTLS front-end, :443)";
    wantedBy = [ "multi-user.target" ];
    after = [ "vllm.service" "iron-manifest.service" ];
    requires = [ "vllm.service" "iron-manifest.service" ];
    serviceConfig = {
      Type = "simple";
      Restart = "on-failure";
      ExecStart = "${lib.getExe ironInstance}";
      # CAP_NET_BIND_SERVICE: bind 443 without running as root.
      # CAP_DAC_OVERRIDE: minting a TDX quote creates a report entry under
      # /sys/kernel/config/tsm/report/, which is root-owned; configfs-tsm gives no group-writable
      # path, so a DynamicUser (non-root) service needs DAC override to mkdir there. Without it
      # every /attestation fails EACCES -> 503. Scoped to this single-purpose service in a CVM
      # with no admin plane; still least-privilege vs running as root. T2: confirm the quote path
      # works under this exact sandbox on the first real TDX boot.
      AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" "CAP_DAC_OVERRIDE" ];
      CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_DAC_OVERRIDE" ];
      DynamicUser = true;
      NoNewPrivileges = true;
      ProtectHome = true;
      PrivateTmp = true;
      # /sys/kernel/config must stay writable: creating a TSM report entry is a mkdir.
      ProtectKernelTunables = false;
    };
    environment = {
      IRON_VLLM_URL = "http://127.0.0.1:8000/v1/chat/completions";
      IRON_GPU_REPORT_CMD = "${gpuReport}/bin/iron-gpu-report";
      # Materialized by iron-manifest.service from the launch parameter, hash-verified.
      IRON_MANIFEST_PATH = "/etc/iron/manifest.json";
    };
  };

  environment.systemPackages = [ gpuReport ];

  ############################################################################
  # 30-day lifetime. The instance ends itself; it does not wait to be told.
  ############################################################################

  systemd.timers.iron-terminate = {
    description = "Self-terminate 30 days after boot";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "30d";
      AccuracySec = "1m";
    };
  };
  systemd.services.iron-terminate = {
    description = "Wipe RAM-resident state and power off";
    serviceConfig = {
      Type = "oneshot";
      # Ephemeral storage dies with the VM; RAM goes with the power. The Orchestrator notices
      # the instance disappear via the cloud API and notifies users.
      ExecStart = "${pkgs.systemd}/bin/systemctl poweroff";
    };
  };

  # Nothing in this image should ever phone home on its own.
  documentation.enable = false;
  services.timesyncd.enable = true; # certificate/JWT expiry checks need a sane clock
}
