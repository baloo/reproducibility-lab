{ nixpkgs
}:

with nixpkgs;

{
  openssl_3_0_0_alpha12 = openssl_1_1.overrideAttrs(old: rec {
    version = "3.0.0-alpha12";
    src = fetchurl {
      url = "https://www.openssl.org/source/${old.pname}-${version}.tar.gz";
      sha256 = "sha256-jXgjm+Zq9Xi5aUQSUufBJaoTTvO5usYXnYQnXP4BlQw=";
    };
    withDocs = true;
    #configureFlags = old.configureFlags ++ ["enable-ktls"];
    patches = old.patches ++ [
      #./patches/openssl-disable-kernel-detection.patch
    ];
    # To debug, break the glass
    #postConfigure = "perl configdata.pm --dump ";
  });
}
