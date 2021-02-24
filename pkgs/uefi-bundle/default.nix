{ stdenvNoCC
, stdenv
, systemd
, binutils-unwrapped 
, pecoff-checksum
}:

{ kernel, initrd, kernelParams, toplevel }:
stdenvNoCC.mkDerivation {
  name = "netboot.efi";

  nativeBuildInputs = [
    binutils-unwrapped
  ];
  buildInputs = [
    pecoff-checksum
  ];

  dontUnpack = true;

  buildPhase = ''
    echo -n "init=${toplevel}/init ${toString kernelParams}" > kernel-command-line.txt
    echo "netboot nixos" > osrel

    # Here we're bundling both kernel, commandline and initrd in a single image
    # We want the whole content to be hashed, not just one part.
    ${binutils-unwrapped}/bin/objcopy \
          --add-section .osrel="osrel" --change-section-vma .osrel=0x20000 \
	  --add-section .cmdline="kernel-command-line.txt" --change-section-vma .cmdline=0x30000 \
	  --add-section .linux="${kernel}/bzImage" --change-section-vma .linux=0x40000 \
	  --add-section .initrd="${initrd}/initrd" --change-section-vma .initrd=0x3000000 \
          ${systemd.out}/lib/systemd/boot/efi/linuxx64.efi.stub \
          linux.efi

    # The checksum of an EFI binary is not just a `sha256sum linux.efi`
    # See:
    #   https://www.trustedcomputinggroup.org/wp-content/uploads/TCG-EFI-Platform-Specification.pdf section 4
    #   https://docs.microsoft.com/en-us/windows-hardware/test/hlk/testref/trusted-execution-environment-efi-protocol#code-try-7
    pecoff-checksum linux.efi checksum.json  
  '';

  installPhase = ''
    mkdir $out/
    install -m 644 linux.efi $out/
    install -m 644 checksum.json $out/
  '';
}
