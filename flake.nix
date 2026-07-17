{
  description = "IronServer Instance - reproducible NixOS image (x86_64-linux, Intel TDX + NVIDIA CC)";

  # Pinned by flake.lock. `nix flake update` is a deliberate act: it changes the image, hence
  # the measurement, hence Constants.Attestation.expectedImageMeasurement in the iOS app.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      # This pkgs only drives the crate build and pin-artifacts, all free software (image
      # assembly now happens inside nixosSystem, via systemd-repart in the module set).
      # Unfree handling for the NVIDIA driver lives in nix/configuration.nix
      # (nixpkgs.config.allowUnfreePredicate) because nixosSystem instantiates its own nixpkgs
      # and never sees config set here.
      pkgs = import nixpkgs { inherit system; };
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

        # The appliance image, assembled offline by systemd-repart (definition lives in
        # nix/configuration.nix, image.repart). Raw and uncompressed -- reproducibility is
        # gated by byte-diffing two independent builds, so never qcow2, never compressed.
        image = self.nixosConfigurations.instance.config.system.build.image;

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
