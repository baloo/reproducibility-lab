{ pkgs, lib, ... }:

{
  imports = [
    (pkgs.path + "/nixos/modules/profiles/minimal.nix")
  ];

  boot.supportedFilesystems = lib.mkForce [];
  boot.kernelParams = [
    "console=tty1" 
    "console=ttyS0" 
    "boot.panic_on_fail"
  ];
  boot.initrd.supportedFilesystems = lib.mkForce [];

  users.users.root.openssh.authorizedKeys.keys = [
     "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDk+TWLUa63TNQwxq1MqbJaIpCm3ahinp9s9c+0rBTpii7BT5wlCC3RVv1sPSeeFxMCcWX9Zkgmm+9PV3BJwes5/pz594dHVamAl2lWprU+n7lSVQwRDYrAu+X3cG8YOmR3tFqePBfdJrqybjyOTnDE+4wAwt77fQ6CIlLTYRXjIK4Xbz0njPUvkHq2owsuOLDu3015uCJ1oi2IUksee2O73mUx+HDr31RaSF9SR7ilrHY11ITrNm0otQoq4Mv11jVE3Kh4XbPSusaHS38GNUa3DGByamGf1WTCq1n+r0AqdrvKMtSd+VBzNOlSjSBwhwAB9XgbD8Ig6Og/E/MNB41p PIV AUTH pubkey"
  ];

  networking.hostName = "demo";

  nixpkgs.config.packageOverrides = pkgs: {
    systemd = pkgs.systemd.override {
      withCryptsetup = false;
      withDocumentation = false;
      withHwdb = false;
    };
  };
  systemd.suppressedSystemUnits = [
    "cryptsetup.target"
  ];

  services.udisks2.enable = false;
  services.openssh.enable = true;
  networking.wireless.enable = false;

  documentation.enable = false;
  documentation.nixos.enable = false;
  
  users.users.nixos = {};
  services.getty.autologinUser = lib.mkForce null;
  services.getty.helpLine = "";

  security.tpm2 = {
    enable = true;
    abrmd.enable = true;
    tctiEnvironment = {
      enable = true;
      interface = "tabrmd";
    };
  };

  environment.systemPackages = with pkgs; [
    tpm2-tools
    netboot.safeboot
    openssl
  ];
}
