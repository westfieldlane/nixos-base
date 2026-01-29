{
  nix = {
    settings.experimental-features = [ "nix-command" "flakes" ];
    extraOptions = ''
      tarball-ttl = 0
    '';
  };
}
