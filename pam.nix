{
  security.pam.services.login.logFailures = true;
  security.pam.services.sshd.logFailures = true;
  security.pam.services.sudo.logFailures = true;
  security.pam.services.su.logFailures = true;

  environment.etc."security/faillock.conf".text = ''
    deny = 5
    fail_interval = 900
    unlock_time = 600
  '';
}
