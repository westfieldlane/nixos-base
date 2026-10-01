{
  system.autoUpgrade = {
    enable = true;
    dates = "04:30";
    channel = "https://channels.nixos.org/nixos-26.05";

    allowReboot = true;
    runGarbageCollection = true;

    randomizedDelaySec = "45min";
  };
}
