{
  services = {
    dbus.implementation = "broker";
    logrotate.enable = true;
    journald = {
      upload.enable = false; # Disable remote log upload (the default)
      extraConfig = ''
        SystemMaxUse=500M
        SystemMaxFileSize=50M
      '';
    };
  };
}
