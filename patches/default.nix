final: prev:
let
  inherit (prev) lib;

  patchDirs = lib.filterAttrs (_: v: v == "directory") (builtins.readDir ./.);

  names = builtins.attrNames patchDirs;
in
builtins.listToAttrs (map
  (name: {
    inherit name;

    # Deliberately `import`, not callPackage, and everything from `prev`.
    # callPackage's autoArgs is `final`, and nixpkgs ships its own libssh2 CVE
    # fixes as fetchpatch derivations -- resolving those through `final` walks
    # fetchpatch -> curl -> libssh2 and recurses forever, because curl links
    # libssh2. Handing the subdirectory just lib and the pre-overlay package
    # keeps `final` out of the patch set entirely.
    value = import (./. + "/${name}") { inherit (prev) lib; ${name} = prev.${name}; };
  })
  names)

