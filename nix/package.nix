{ lib, rustPlatform, ironSrc }:

rustPlatform.buildRustPackage {
  pname = "iron-instance";
  version = "0.1.0";

  # Only the crate itself. nix/, target/, docs and the flake plumbing contribute nothing to
  # the binary and would otherwise churn the derivation hash on every edit to a shell script
  # or a README. tests/ stays: doCheck runs cargo test.
  src = lib.cleanSourceWith {
    src = ironSrc;
    filter = path: type:
      let rel = lib.removePrefix (toString ironSrc + "/") (toString path);
      in !(lib.hasPrefix "target" rel
        || lib.hasPrefix "nix" rel
        || lib.hasPrefix ".git" rel
        || lib.hasPrefix "result" rel
        || rel == "flake.nix"
        || rel == "flake.lock"
        || rel == "README.md"
        || rel == "CLAUDE.md"
        || rel == ".gitignore");
  };

  cargoLock.lockFile = ironSrc + "/Cargo.lock";

  # Tests here bind loopback sockets and generate keys; they run fine in the sandbox and are
  # cheap, so leave them on -- the image should not build if the service is broken.
  doCheck = true;

  meta = {
    description = "IronServer Instance: attested, mutually-authenticated inference front-end";
    mainProgram = "iron-instance";
  };
}
