{
  services.tailscale = {
    enable = true;
    openFirewall = true;
  };

  systemd.services.tailscaled.serviceConfig = {
    NoNewPrivileges = true;
    ProtectSystem = "full";
    ProtectHome = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    ProtectProc = "invisible";
    RestrictSUIDSGID = true;
    RestrictRealtime = true;
    LockPersonality = true;
    RestrictNamespaces = true;
    RestrictAddressFamilies = [
      "AF_UNIX"
      "AF_NETLINK"
      "AF_INET"
      "AF_INET6"
      "AF_PACKET"
    ];
    CapabilityBoundingSet = [
      "~CAP_SYS_MODULE"
      "~CAP_SYS_BOOT"
      "~CAP_SYS_PTRACE"
      "~CAP_SYS_RAWIO"
      "~CAP_SYS_TIME"
      "~CAP_SYS_TTY_CONFIG"
      "~CAP_AUDIT_CONTROL"
      "~CAP_AUDIT_WRITE"
      "~CAP_MKNOD"
      "~CAP_SETFCAP"
    ];
    SystemCallFilter = [
      "~@debug"
      "~@raw-io"
      "~@reboot"
      "~@clock"
      "~@module"
      "~@swap"
      "~@obsolete"
      "~@cpu-emulation"
      "~@mount"
    ];
    SystemCallArchitectures = "native";
    SystemCallErrorNumber = "EPERM";
  };
}
