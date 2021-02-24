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

    pecoff-checksum = self.callPackage ./pecoff-checksum { inherit signify; };

    safeboot = self.callPackage ./safeboot { };
  };

  # https://github.com/NixOS/nixpkgs/pull/114054
  certvalidator = self.callPackage ./certvalidator {
    asn1crypto = self.python3Packages.asn1crypto;
    oscrypto = self.python3Packages.oscrypto;
    pytestCheckHook = self.python3.pytestCheckHook;
    buildPythonPackage = self.python3Packages.buildPythonPackage;
  };
  signify = self.callPackage ./signify {
    pythonOlder = self.python3.pythonOlder;
    pyasn1 = self.python3Packages.pyasn1;
    pyasn1-modules = self.python3Packages.pyasn1-modules;
    buildPythonPackage = self.python3Packages.buildPythonPackage;
  };
}
