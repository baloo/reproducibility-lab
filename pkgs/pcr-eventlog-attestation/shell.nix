let
  moz_overlay = import (builtins.fetchTarball https://codeload.github.com/mozilla/nixpkgs-mozilla/tar.gz/master);
  nixpkgs = import <nixpkgs> {
    overlays = [ moz_overlay ];
  };
  rustNightly = (nixpkgs.latest.rustChannels.nightly.rust.override {
    extensions = [ "rust-src" "rust-analysis" ];}
  );
  rustStable = (nixpkgs.latest.rustChannels.stable.rust.override {
    extensions = [ "rust-src" "rust-analysis" ];}
  );
in
  with nixpkgs;
  stdenv.mkDerivation {
    name = "rust";
    nativeBuildInputs = [
      pkg-config
      swtpm
    ];
    buildInputs = [
      rustNightly
      tpm2-tss
      llvm
      clang
    ];
    LIBCLANG_PATH = "${llvmPackages.clang-unwrapped.lib}/lib";
  }

