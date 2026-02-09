let
  pkgs = import (import ./nixpkgs.nix) { };
  lib = pkgs.lib;
in
{
  inherit pkgs lib;
  # Add all core software that every machine should have
  # NOTE: the services sub-directory sandboxes services appropriately in SystemD
  imports = [
    ./autoUpgrade.nix
    ./bat.nix
    ./boot.nix
    ./bottom.nix
    ./fd.nix
    ./fish.nix
    ./helix.nix
    ./locale.nix
    ./lsd.nix
    ./nix.nix
    ./nixd.nix
    ./ripgrep.nix

    ./services
  ];
}
