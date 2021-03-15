{ ...
}:

self: super:
rec {
  netboot = rec {
    versionSuffix = "";
    versionModule = {
      system.nixos.versionSuffix = versionSuffix;
      system.nixos.revision = "";
    };
    make-modules = configuration: module: rest: [
      configuration versionModule module rest
    ];
    evalConfig = self.callPackage ./make-config {
      system = self.system;
      pkgs = self;
    };
    uefiBundle = self.callPackage ./uefi-bundle {
      inherit pecoff-checksum;
    };

    pecoff-checksum = self.callPackage ./pecoff-checksum { };

    safeboot = self.callPackage ./safeboot { };

    pea = self.callPackage ./pcr-eventlog-attestation { };
  };
}
