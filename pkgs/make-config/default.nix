{ pkgs
, system
}:

modules:
import (pkgs.path + "/nixos/lib/eval-config.nix") {
  inherit system modules pkgs;
}
