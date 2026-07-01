{ pkgs, ... }: {
  security.auditd.enable = true;

  # Auditd runtime settings. Without these, audit.log can grow unbounded
  # (observed 22 GB in 6h on a workstation during nixos-rebuild activity).
  #   max_log_file / num_logs        →  100 MB × 5 = 500 MB cap
  #   max_log_file_action = "rotate" →  rotate on full instead of blocking
  #   disp_qos = "lossy"             →  drop events at the dispatcher under
  #                                     pressure rather than block the kernel
  #                                     (better than the kernel dropping via
  #                                     netlink, which shows up as `lost N`
  #                                     in `auditctl -s`)
  security.auditd.settings = {
    max_log_file = 100;
    num_logs = 5;
    max_log_file_action = "rotate";
    disp_qos = "lossy";
  };

  # Stage 1 of the log pipeline (see services/vector.nix): bridge auditd
  # events into journald via the audispd syslog plugin. /var/log/audit/audit.log
  # remains the durable primary; journald gets a duplicate for Vector to ingest.
  security.auditd.plugins.syslog = {
    active = true;
    direction = "out";
    path = "${pkgs.audit}/bin/audisp-syslog";
    # NB: don't set `args` — the NixOS module already defaults to
    # [ "LOG_INFO" ], and list options merge rather than override, so
    # setting it here produces `args = LOG_INFO LOG_INFO` in the plugin
    # config file. audisp-syslog reads that as priority + facility, and
    # since "LOG_INFO" isn't a valid facility name, silently refuses to
    # forward — auditd events never reach journald.
    format = "string";
  };

  security.audit.rules = [
    "-D"

    # Identity files
    "-w /etc/passwd -p wa -k identity"
    "-w /etc/shadow -p wa -k identity"
    "-w /etc/group -p wa -k identity"
    "-w /etc/gshadow -p wa -k identity"

    # Privilege configuration
    "-w /etc/sudoers -p wa -k sudoers"
    "-w /etc/sudoers.d -p wa -k sudoers"
    "-w /etc/ssh/sshd_config -p wa -k sshd"

    # Faillock state — tracks lockout events
    "-w /var/run/faillock -p wa -k auth"

    # Time change (affects certificate and NTS validity)
    "-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change"
    "-w /etc/localtime -p wa -k time_change"

    # Kernel module load/unload
    "-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules"

    # UID/GID-changing syscalls from interactive user sessions
    "-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -F auid>=1000 -F auid!=-1 -k privilege_escalation"
    "-a always,exit -F arch=b32 -S setuid,setgid,setreuid,setregid,setresuid,setresgid -F auid>=1000 -F auid!=-1 -k privilege_escalation"

    # Execution of setuid/setgid binaries
    "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid_exec"
    "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid_exec"

    # Permission and ownership changes from user sessions
    "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -k perm_change"

    # NB: previously we watched -EACCES/-EPERM open(),creat(),truncate() for
    # "denied access." Removed because on desktop hosts every process monitor
    # (bottom, ps, top…) probes /proc/PID/io on non-owned PIDs constantly,
    # generating a firehose (22 GB/6h observed). Failed file access is also
    # a weak security signal on its own. Add back per-host with tighter
    # filters if a specific detection use case emerges.
  ];

  systemd.services.auditd.serviceConfig = {
    NoNewPrivileges = true;
    ProtectSystem = "full";
    ProtectHome = true;
    ProtectHostname = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectControlGroups = true;
    ProtectProc = "invisible";
    ProtectClock = true;
    PrivateTmp = true;
    PrivateNetwork = true;
    PrivateMounts = true;
    PrivateDevices = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    RestrictAddressFamilies = [
      "~AF_INET6"
      "~AF_INET"
      "~AF_PACKET"
    ];
    MemoryDenyWriteExecute = true;
    LockPersonality = true;
    SystemCallFilter = [
      "~@clock"
      "~@module"
      "~@mount"
      "~@swap"
      "~@obsolete"
      "~@cpu-emulation"
    ];
    SystemCallArchitectures = "native";
    CapabilityBoundingSet = [
      "~CAP_CHOWN"
      "~CAP_FSETID"
      "~CAP_SETFCAP"
    ];
  };
}
