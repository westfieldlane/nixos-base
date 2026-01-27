{
  system.autoUpgrade = {
    enable = true;
    dates = "04:30";

    allowReboot = true;
    runGarbageCollection = true;
  };

  nix = {
    gc = {
      automatic = true;
      dates = "05:00";
      options = "--delete-older-than 7d";
    };

    optimise = {
      automatic = true;
      dates = "05:10";
    };
  };
}
