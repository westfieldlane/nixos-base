{
  nix = {
    gc = {
      automatic = true;
      dates = "05:00";
      options = "--delete-older-than 7d";

      randomizedDelaySec = "30min";
    };

    optimise = {
      automatic = true;
      dates = "05:10";
    };
  };
}
