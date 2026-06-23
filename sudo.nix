{
  security.sudo = {
    execWheelOnly = true;
    extraConfig = ''
      Defaults use_pty
      Defaults log_input
      Defaults log_output
      Defaults iolog_dir=/var/log/sudo-io
      Defaults timestamp_timeout=5
      Defaults log_host
      Defaults logfile=/var/log/sudo.log
    '';
  };
}
