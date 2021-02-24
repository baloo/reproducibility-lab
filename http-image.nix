let
  system = "x86_64-linux";
  overlays = [
    (import ./pkgs/overlay.nix {})
  ];
  #pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/9a9941e02d5d44327229e392231a64cc4dedc1ae.tar.gz") {
  pkgs = import <nixpkgs> {
    inherit  system;

    overlays = overlays;
  };
  lib = pkgs.lib;
  config = (pkgs: lib: import ./config/vm.nix { inherit pkgs lib; });
  configEvaled = pkgs.netboot.evalConfig
    (pkgs.netboot.make-modules 
      (config pkgs lib)
      (import (pkgs.path + "/nixos/modules/installer/netboot/netboot-minimal.nix"))
      {});
  build = configEvaled.config.system.build;
  kernelTarget = configEvaled.pkgs.stdenv.hostPlatform.linux-kernel.target;
in pkgs.netboot.uefiBundle {
  kernel = build.kernel;
  initrd = build.netbootRamdisk;
  toplevel = build.toplevel;
  kernelParams = configEvaled.config.boot.kernelParams;
}
