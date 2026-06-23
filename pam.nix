{
  security.pam.services = {
    login.logFailures = true;
    sshd.logFailures = true;
    sudo.logFailures = true;
    su = {
      logFailures = true;
      requireWheel = true;
    };
  };


  environment.etc."security/faillock.conf".text = ''
    deny = 5
    fail_interval = 900
    unlock_time = 600
  '';
}
