{
  description = "IronServer Instance - reproducible NixOS image (x86_64-linux, Intel TDX + NVIDIA CC)";

  # Pinned by flake.lock. `nix flake update` is a deliberate act: it changes the image, hence
  # the measurement, hence Constants.Attestation.expectedImageMeasurement in the iOS app.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        # The NVIDIA driver is unfree. Nothing else here is.
        config.allowUnfree = true;
      };
      # This flake sits at the crate root so that src/, pinned/ and Cargo.lock are all inside
      # the flake source. A flake only ever copies its own directory into the store, so a
      # flake under nix/ could not reach them.
      ironSrc = ./.;
    in
    {
      nixosConfigurations.instance = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ ./nix/configuration.nix ];
        specialArgs = { inherit ironSrc; };
      };

      packages.${system} = {
        # The service on its own -- useful for `nix build .#iron-instance` sanity checks
        # without paying for a full image build.
        iron-instance = pkgs.callPackage ./nix/package.nix { inherit ironSrc; };

        # RAW, not qcow2: reproducibility is gated by diffing two independent builds, and
        # diffoscope cannot diff qcow2 filesystems.
        image = import "${nixpkgs}/nixos/lib/make-disk-image.nix" {
          inherit pkgs;
          inherit (pkgs) lib;
          config = self.nixosConfigurations.instance.config;
          format = "raw";
          partitionTableType = "efi";
          diskSize = 40960; # MiB. Only the OS + service; weights land on the ephemeral data disk.
          # Reproducibility knobs: without these the image carries a fresh UUID and mtimes on
          # every build and can never hash the same twice.
          deterministic = true;
          touchEFIVars = false;
        };

        default = self.packages.${system}.image;
      };

      # `nix run .#pin-artifacts -- <hf-repo> <revision>`
      apps.${system}.pin-artifacts = {
        type = "app";
        program = "${pkgs.writeShellApplication {
          name = "pin-artifacts";
          runtimeInputs = with pkgs; [ curl jq coreutils skopeo ];
          text = builtins.readFile ./nix/pin-artifacts.sh;
        }}/bin/pin-artifacts";
      };

      formatter.${system} = pkgs.nixpkgs-fmt;
    };
}
