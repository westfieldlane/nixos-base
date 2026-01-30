let
  nixpkgs = import ./nixpkgs.nix;
  lib = nixpkgs.lib;
in
{
  inherit nixpkgs lib;

  # Add all core software that every machine should have
  # NOTE: the services sub-directory sandboxes services appropriately in SystemD
  imports = [
    ./autoUpgrade.nix
    ./bat.nix
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
