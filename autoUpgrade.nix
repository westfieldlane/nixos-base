{
  system.autoUpgrade = {
    enable = true;
    dates = "04:30";
    channel = "https://channels.nixos.org/nixos-26.05";

    allowReboot = true;
    runGarbageCollection = true;

    randomizedDelaySec = "45min";
  };

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
