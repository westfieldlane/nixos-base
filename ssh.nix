{
  services.openssh = {
    enable = true;
    openFirewall = true;

    settings = {
      PermitRootLogin = "no";
      PermitEmptyPasswords = false;
      LoginGraceTime = 30;
      MaxAuthTries = 4;
      MaxStartups = "10:30:60";
      ClientAliveInterval = 300;
      ClientAliveCountMax = 2;
    };
  };
}
