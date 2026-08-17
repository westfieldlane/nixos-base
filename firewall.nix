{
  # Set all hosts to use nftables (for consistency)
  networking.nftables.enable = true;

  networking.firewall = {
    enable = true;
    logRefusedConnections = true;
    rejectPackets = false;
    allowPing = true;
  };
}
