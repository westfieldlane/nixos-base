{
  services.clamav = {
    daemon = {
      enable = true;
      settings.ExcludePath = [
        "^/home/[^/]+/\\.local/share/containers"
        "^/home/[^/]+/\\.local/share/zed"
      ];
    };
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
