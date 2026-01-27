let
  rev = "nixos-25.11-small";
in
builtins.fetchTarball {
  url = "https://channels.nixos.org/${rev}/nixexprs.tar.xz?dummy=${toString builtins.currentTime}";
}
