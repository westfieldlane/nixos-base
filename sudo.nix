{
  security.sudo.enable = false;

  security.sudo-rs = {
    enable = true;
    execWheelOnly = true;

    extraConfig = ''
      Defaults timestamp_timeout=5
    '';
  };
}
