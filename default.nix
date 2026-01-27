{
  # Declaratively manage the nixpkgs "channel"
  pkgs = import (import ./nixpkgs.nix) { };

  # Add all core software that every machine should have
  # NOTE: the services sub-directory sandboxes services appropriately in SystemD
  imports = [
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
