{ python3Packages, signify }:

python3Packages.buildPythonPackage {
  pname = "pecoff-checksum";
  version = "0.0.0";

  src = ./.;
  pythonPath = [ signify ];
  doCheck = false;
  meta.description = "A PE image checksum calculation util";
}
