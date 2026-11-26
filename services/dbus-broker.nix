{
  services = {
    dbus.implementation = "broker";
    logrotate.enable = true;
    journald = {
      upload.enable = false; # Disable remote log upload (the default)
      settings.Journal = {
        SystemMaxUse = "500M";
        SystemMaxFileSize = "50M";
      };
    };
  };
}
