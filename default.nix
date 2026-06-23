{
  # Add all core software that every machine should have
  # NOTE: the services sub-directory sandboxes services appropriately in SystemD
  imports = [
    ./autoUpgrade.nix
    ./bat.nix
    ./boot.nix
    ./bottom.nix
    ./fd.nix
    ./firewall.nix
    ./fish.nix
    ./git.nix
    ./helix.nix
    ./ids.nix
    ./locale.nix
    ./lsd.nix
    ./nix.nix
    ./nixd.nix
    ./ripgrep.nix
    ./ssh.nix

    ./services
  ];
}
