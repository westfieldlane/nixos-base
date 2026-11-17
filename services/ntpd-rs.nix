{
  services.ntpd-rs = {
    enable = true;

    # ntpd-rs module string matches on "pool" or sets the mode to "server".
    # Therefore we have to manually define NTS sources in our config
    useNetworkingTimeServers = false;
    settings.source = [
      {
        mode = "nts";
        address = "time.cloudflare.com";
      }
      {
        mode = "nts";
        address = "ntppool1.time.nl";
      }
      {
        mode = "nts";
        address = "nts.netnod.se";
      }
      {
        mode = "nts";
        address = "ptbtime1.ptb.de";
      }
      {
        mode = "nts";
        address = "time.cifelli.xyz";
      }
    ];
  };
}
