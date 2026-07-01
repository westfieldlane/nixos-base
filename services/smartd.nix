{
  # smartd — SMART attribute monitoring and scheduled self-tests for all
  # local disks. Reports go to journald (see notifications below); no MTA
  # in the baseline, so failures surface via `journalctl -u smartd`.
  services.smartd = {
    enable = true;
    autodetect = true;

    # Notifications: journald only. No wall broadcast (annoying on TTYs),
    # no mail (no MTA in baseline). Per-host modules may add mail/matrix.
    notifications = {
      wall.enable = false;
      mail.enable = false;
    };

    # Lightweight baseline — some drives glitch on active SMART probes,
    # so this deliberately avoids scheduled self-tests, offline data
    # collection, and full-attribute polling. What we *do* check:
    #   -H                       drive's own overall SMART health assessment
    #                            (one ATA command, no seeks)
    #   -W 4,55,60               temperature: +4°C jump / 55°C info / 60°C crit
    #   -l error                 report any growth in the drive's error log
    #
    # Per-host modules can override with heavier options on hosts with
    # robust drives:
    #   -a                       full attribute monitoring
    #   -s (S/.../L/...)         scheduled short/long self-tests
    #   -o on / -S on            offline collection / attribute autosave
    defaults.monitored = "-H -W 4,55,60 -l error";

    # Poll every hour instead of smartd's 30-minute default to further
    # reduce per-drive touches.
    extraOptions = [ "-i 3600" ];
  };

  # Light sandbox. smartd needs raw device access (ioctl to /dev/sd*, /dev/nvme*),
  # so PrivateDevices / DeviceAllow restrictions are deliberately absent.
  systemd.services.smartd.serviceConfig = {
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    ProtectHostname = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    PrivateTmp = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
  };
}
