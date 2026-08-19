final: prev:
let
  inherit (prev) lib;

  entries = builtins.readDir ./.;

  isDir = _: v: v == "directory";

  # Ignore any directories with a _ prefix; they aren't packages to patch
  isPackage = name: _: !(lib.hasPrefix "_" name);

  names = builtins.attrNames
    (lib.filterAttrs isPackage (lib.filterAttrs isDir entries));
in
builtins.listToAttrs (map
  (name: {
    inherit name;

    # Build in our patches on top of the original patches that already exist in the derivation
    value = import (./. + "/${name}") { inherit (prev) lib; ${name} = prev.${name}; };
  })
  names)
