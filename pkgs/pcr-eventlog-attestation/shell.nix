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
  let
    vimConfigured = neovim.override {
      configure = {
        customRC = ''
          set mouse=
          let g:rustfmt_autosave = 1
        '';

        plug.plugins = with vimPlugins; [
          rust-vim 
        ];
      };
    };

    swtpm_datastore = "target/data";

    issuer = writeText "issuer.key" ''
      -----BEGIN PRIVATE KEY-----
      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
      D3LeuuyEcRTzsJQ5EoNR/jQZn6C+AQ==
      -----END PRIVATE KEY-----
    '';

    cert = writeText "issuer.pem" ''
      -----BEGIN CERTIFICATE-----
      MIIFGzCCAwOgAwIBAgIUMYdUtDSM20AcGW+qc0tW1aC+s/QwDQYJKoZIhvcNAQEL
      BQAwHTEbMBkGA1UEAwwSZHVtbXkgbWFudWZhY3R1cmVyMB4XDTIxMDIyMjA0NDMy
      OFoXDTMwMTEyMjA0NDMyOFowHTEbMBkGA1UEAwwSZHVtbXkgbWFudWZhY3R1cmVy
      MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApsq5s6OSRMvixClKxSvj
      Vp9lAuWGwUFtpkv+9S1PKLAINKTt5VL0c1A3CvGqDHrDdC/I4h/xQnlWCq3cCAwu
      VYOnbZYbTppqJxyrwAogSuQxYptuS8wGyN/pRVll5KZ9MWs8I/Iqk6hTPY9hUhMi
      Iqng4ptjI8DPhC8qX9wlhUpPqoRGVN3xPWW4R8eKOJlzcHA7Ag/reUFDXcIa6q5m
      +Ht8UJ9R2b5viBoVwVEm413ByCaYY8F9hN7SHWfGo39ZnjIqtvFxZsbje34L/26A
      HfdP+AvOq8obbnlcinMH2RMw0aQWY0EQQxEseS4lb5y64o32F4B7n7kjE1hOjJnl
      o/MjEYk9idUo7oiqW2qbWuzFXR9JOQhUoG8iDrxkOMMG3sMgHNElSR6rhlwRtRmB
      X2MXiF6mkZq9HkuM1iejBFNhmP2Sd+jyT8HIz5c0qqIpGlc9L1R7yG60AH9q4xZN
      Sm5jAmi2VnGSrcUSYKu8BQ2JUWk+05SSb5aFhV8WNv3Tf+GQ61HVgY/swtDSbxXk
      humbnJxFnC20rM2gXhZNYROAHQZ35ZSnfDi8aBEYPPzRwl5xuBYVzidzcDu4wlNG
      VgfMstG4r4OpOAqFwarkT/eN+pICv/N0w4d4ele+ze2s/bTZmwUXOS3PY/3poOgL
      16q3Uxki6MXZ9QLl/VuK0x8CAwEAAaNTMFEwHQYDVR0OBBYEFHFPzbR9tlBhiAqn
      EhPd6kzDn4JuMB8GA1UdIwQYMBaAFHFPzbR9tlBhiAqnEhPd6kzDn4JuMA8GA1Ud
      EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAB+WLhxO5xCI2mC8iI69k6+d
      H4+kBAVIr1e2vvXCtszVbwd3SaHv4T8kOtgdSr7t/FaplzEIEdyNb36SZ+kCcJ0S
      BZALcXUxWfjmBMnqMVFWrZeC5/LuLcfTkSPeESlG1n6ukrxaeGQVCRWeCiIuiaNj
      FJjiwjoIH60lkVY0Q/zgUjCkVGhf5ODg+O2wRD3TDmeHO5v2SThYlXK/9/RhXIE2
      JECWnYCASirPiLNqMjbRftDWwnzRpTKDEEwzJkURC9AQt+txjtZkTP6rm5aErZqd
      IedygT4gAnjg1x/QxBWEf6Y+h57fKS7nRF+7t3Uwj8EEqWdGVHEoAXASTX8PtCqD
      5bBfjcp5Q/w3rjYpzZPnBWMiqn4jcHwYOCxO28GNV4+oruWh0me3ob6rWiilQerl
      uzUYqW7ncnN3mTva+4rDl1FHealrQUtZGHMoC98s5OBPRLNcl8yg01EY9eTJXSTn
      0tHGCqK/nilgLrli2vVF7ryEGAbRoHAUWKPXvPU67YlfCB1RXlvznWDchVXMXFyn
      0eb+JvsgkgoABls6WWL/hPGp5uLW9WDIQiEqCNOzU4sLCS9p4YJ0k8VIKB2YvITL
      a99yQit1vyEk/bbG2fCL3Dvqt5Yz0tJN043YQXDhHRGuz8YgevwkUt/I+N1MwtfM
      XlBI/PDlx6Vv7i5Gac/M
      -----END CERTIFICATE-----
    '';

    swtpm_localca_config = writeText "swtpm-localca.conf" ''
      certserial=${swtpm_datastore}/serial
      statedir=${swtpm_datastore}/swtpm
      signingkey=${issuer}
      issuercert=${cert}
    '';

    swtpm_config = writeText "swtpm_setup.conf" ''
      create_certs_tool=${swtpm}/share/swtpm/swtpm-localca
      create_certs_tool_config=${swtpm_localca_config}
      create_certs_tool_options=${swtpm}/etc/swtpm-localca.options
    '';

    swtpm' = stdenvNoCC.mkDerivation {
      name = "swtpm-wrappers";
      buildInputs = [ makeWrapper ];
      buildCommand = ''
        mkdir -p $out/bin
        makeWrapper ${swtpm}/bin/swtpm_setup "$out/bin/swtpm_setup" \
           --add-flags "--config=${swtpm_config}"
        for executable in swtpm swtpm_ioctl swtpm_bios swtpm_cert swtpm_cuse
        do
          ln -s "${swtpm}/bin/$executable" "$out/bin/$executable"
        done
        mkdir -p "$out/share"
        ln -s '${swtpm}/share/man' "$out/share/"
      '';
    };

    swtpm_run = writeShellScriptBin "swtpm_run" ''
      set -x
      rm -rf "${swtpm_datastore}"
      mkdir "${swtpm_datastore}"
      echo -n "01" > "${swtpm_datastore}/serial"
      ${swtpm'}/bin/swtpm_setup \
        --tpm2 \
        --tpmstate ${swtpm_datastore} \
        --createek --decryption --create-ek-cert \
        --create-platform-cert \
        --display
      #/home/baloo/dev/swtpm/src/swtpm/.libs/swtpm socket \
      ${swtpm'}/bin/swtpm socket \
        --tpm2 \
        --tpmstate dir=${swtpm_datastore} \
        -p 2321 --ctrl type=tcp,port=2322 \
        --log fd=1,level=5 \
        --flags not-need-init,startup-clear
    '';
    openssl3 = (import ./nix/openssl3.nix { inherit nixpkgs; })
      .openssl_3_0_0_alpha12;
  in stdenv.mkDerivation {
    name = "rust";
    nativeBuildInputs = [
      pkg-config
      swtpm'
      swtpm_run

      cargo-watch

      vimConfigured
    ];
    buildInputs = [
      rustNightly
      tpm2-tss
      llvm
      clang
      openssl3
    ];
    LIBCLANG_PATH = "${llvmPackages.clang-unwrapped.lib}/lib";
    PROTOBUF_LOCATION = protobuf.out;
    PROTOC = "${protobuf.out}/bin/protoc";
    PROTOC_INCLUDE = "${protobuf.out}/include";
    ROOT_CA = cert;
    
    shellHook = ''
      alias vi="${vimConfigured}/bin/nvim";
      alias vim=vi;
    '';
  }

