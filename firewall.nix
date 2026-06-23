{
  networking.firewall = {
    enable = true;
    logRefusedConnections = true;
    rejectPackets = false;
    allowPing = true;
  };

  services.fail2ban = {
    enable = true;
    maxretry = 5;
    bantime = "1h";
    bantime-increment = {
      enable = true;
      multipliers = "1 2 4 8 16 32 64";
      maxtime = "168h";
    };
  };
}
