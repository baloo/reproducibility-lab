{ python3Packages}:

python3Packages.buildPythonPackage {
  pname = "pecoff-checksum";
  version = "0.0.0";

  src = ./.;
  pythonPath = with python3Packages; [ signify ];
  doCheck = false;
  meta.description = "A PE image checksum calculation util";
}
