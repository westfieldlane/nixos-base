{
  # Add all core software that every machine should have
  # NOTE: the services sub-directory sandboxes services appropriately in SystemD
  imports = [
    ./appArmor.nix
    ./autoUpgrade.nix
    ./bash.nix
    ./bat.nix
    ./boot.nix
    ./bottom.nix
    ./documentation.nix
    ./fd.nix
    ./firewall.nix
    ./git.nix
    ./helix.nix
    ./locale.nix
    ./lsd.nix
    ./nix.nix
    ./nixd.nix
    ./pam.nix
    ./ripgrep.nix
    ./sudo.nix

    ./modules
    ./patches
    ./services
  ];
}
