{ lib
, fetchurl, nix-gitignore
, rustPlatform
, pkg-config, rustfmt
, tpm2-tss, llvm, clang, llvmPackages
, protobuf
, openssl_1_1
}:

let
  openssl3 = (import ./nix/openssl3.nix { inherit openssl_1_1 fetchurl; })
    .openssl_3_0_0_alpha13;
in rustPlatform.buildRustPackage rec {
  pname = "pcr-eventlog-attestation";
  version = "0.0.0";

  src = nix-gitignore.gitignoreSource []
    ./.;

  nativeBuildInputs = [
    pkg-config
    llvmPackages.clang
    rustfmt
  ];

  buildInputs = [
   tpm2-tss llvm llvmPackages.libclang
   openssl3
  ];
  LIBCLANG_PATH = "${llvmPackages.libclang}/lib";
  PROTOBUF_LOCATION = protobuf.out;
  PROTOC = "${protobuf.out}/bin/protoc";
  PROTOC_INCLUDE = "${protobuf.out}/include";

  RUST_BACKTRACE = 1;

  cargoSha256 = "sha256-sRM3++poqAXQO9viOlbEeFK0E7K9hoeX6Vz/BPNiY5w=";

  # TODO: wip, until I fix my tests
  doCheck = false;

  meta = with lib; {
    description = "A remote attestation protocol implementation checking for PCR";
    homepage = "https://github.com/baloo/build-reproducibility";
    license = licenses.unlicense;
    maintainers = [ maintainers.baloo ];
  };
}
