{ openssl_1_1 
, fetchurl
}:

{
  openssl_3_0_0_alpha13 = openssl_1_1.overrideAttrs(old: rec {
    version = "3.0.0-alpha13";
    src = fetchurl {
      url = "https://www.openssl.org/source/${old.pname}-${version}.tar.gz";
      sha256 = "sha256-yIy7nTMLTao9u1rx7VEdUGIlMpGlbgn9F+msATog+KM=";
    };
    withDocs = true;
    #configureFlags = old.configureFlags ++ ["enable-ktls"];
    configureFlags = old.configureFlags ++ ["--debug"];
    patches = old.patches ++ [
      #./patches/openssl-disable-kernel-detection.patch
    ];
    # To debug, break the glass
    #postConfigure = "perl configdata.pm --dump ";
  });
}
