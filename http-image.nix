let
  system = "x86_64-linux";
  overlays = [
    (import ./pkgs/overlay.nix {})
  ];
  pkgs = import (fetchTarball "https://github.com/NixOS/nixpkgs/archive/3e6571316c65638e7a4c1aa2f2700e405be82487.tar.gz") {
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
  commitid = lib.commitIdFromGitRepo ./.git;
in pkgs.netboot.uefiBundle {
  kernel = build.kernel;
  initrd = build.netbootRamdisk;
  toplevel = build.toplevel;
  kernelParams = configEvaled.config.boot.kernelParams ++ [
    "imageid=${commitid}"
  ];
}
