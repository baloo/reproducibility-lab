{ lib, buildPythonPackage, fetchFromGitHub, pythonOlder
, certvalidator, pyasn1, pyasn1-modules
}:

buildPythonPackage rec {
  pname = "signify";
  version = "0.3.0";
  disabled = pythonOlder "3.5";

  src = fetchFromGitHub {
    owner = "ralphje";
    repo = pname;
    rev = "v${version}";
    sha256 = "sha256-JxQECpwHhPm8TCVW/bCnEpu5I/WETyZVBx29SQE4NmE=";
  };

  propagatedBuildInputs = [ certvalidator pyasn1 pyasn1-modules ];

  meta = with lib; {
    homepage = "https://github.com/ralphje/signify";
    description = "library that verifies PE Authenticode-signed binaries";
    license = licenses.mit;
    maintainers = with maintainers; [ baloo ];
  };
}
