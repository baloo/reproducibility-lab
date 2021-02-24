{ lib, stdenvNoCC, fetchFromGitHub, makeWrapper
, tpm2-tools, busybox, openssl }:

stdenvNoCC.mkDerivation rec {
  pname = "safeboot";
  version = "0.7-e49799487";

  src = fetchFromGitHub {
    owner = "osresearch";
    repo = pname;
    rev = "e49799487c37b682cb72e52f4feddc64c3069f62";
    sha256 = "sha256-guqS0V6jAHWN0JvNfxOnDxqJu8wACKiIf2pvYiFM5Kw=";
  };

  buildInputs = [ makeWrapper ];

  buildPhase = ''
    install -d $out/bin $out/etc/ $out/etc/safeboot
    install -m 644 functions.sh $out/etc/safeboot/
    install -m 755 sbin/tpm2-attest $out/bin/.tpm2-attest
    echo "PCRS=0,2,4,5,7" > $out/etc/safeboot/safeboot.conf
    makeWrapper $out/bin/.tpm2-attest $out/bin/tpm2-attest \
      --set PREFIX $out \
      --set PATH "${lib.makeBinPath [ busybox tpm2-tools openssl ]}"
  '';

  dontInstall = true;

  meta = with lib; {
    homepage = "https://github.com/wbond/certvalidator";
    description = "Validates X.509 certificates and paths";
    license = licenses.mit;
    maintainers = with maintainers; [ baloo ];
  };
}
