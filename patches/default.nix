{
  # Add all the overlays
  nixpkgs.overlays = [
    (import ./overlay.nix)
  ];
}
