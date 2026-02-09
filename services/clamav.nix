{
  services.clamav = {
    daemon.enable = true;
    updater.enable = true;
    updater.frequency = 12;
    scanner = {
      enable = true;
      interval = "*-*-* 05:30:00";
      scanDirectories = [
        "/home"
        "/var/lib"
        "/tmp"
        "/etc"
        "/var/tmp"
      ];
    };
  };
}
