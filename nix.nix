{
  nix = {
    # Prevent non-root users from using nix-env, nix-build, etc.
    settings = {
      experimental-features = [ "nix-command" "flakes" ];
    };

    gc = {
      automatic = true;
      dates = "daily";
      options = "--delete-older-than 7d";
    };

    optimise = {
      automatic = true;
      dates = "daily";
    };
  };
}
