{ lib, pkgs, ... }:
let
  # Directories the scheduled scan walks (passed to the forced ExecStart below).
  scanDirs = [
    "/home"
    "/var/lib"
    "/tmp"
    "/etc"
    "/var/tmp"
  ];

  # NOTE: with `clamdscan --fdpass`, clamd.conf's ExcludePath is bypassed (the
  # client walks the tree and passes fds). So the authoritative excludes for the
  # scheduled scan are the client-side `--exclude-dir` flags in ExecStart below;
  # the daemon ExcludePath list only applies to manual, non-`--fdpass` scans.
  excludeDirs = [
    "^/home/[^/]+/\\.local/share/containers"
    "^/home/[^/]+/\\.config/containers"
    "^/home/[^/]+/\\.local/share/zed"
    "^/var/lib/containers"
    "^/var/lib/docker"
    "^/var/lib/libvirt"
    "^/var/lib/machines"
    "^/var/lib/clamav" # its own signature DB
  ];

  excludeFlags = lib.concatMapStringsSep " " (re: "--exclude-dir=${re}") excludeDirs;
in
{
  services.clamav = {
    daemon = {
      enable = true;
      settings = {
        ExcludePath = excludeDirs;
        MaxThreads = 4;
        MaxScanTime = 120000;
      };
    };
    updater.enable = true;
    updater.frequency = 12;
    scanner = {
      enable = true;
      interval = "*-*-* 05:30:00";
    };
  };

  # The module's clamdscan exposes no --exclude-dir knob; force the command to add
  # client-side excludes (+ --allmatch).
  systemd.services.clamdscan.serviceConfig.ExecStart = lib.mkForce (
    "${pkgs.clamav}/bin/clamdscan --multiscan --fdpass --infected --allmatch "
    + "${excludeFlags} ${lib.concatStringsSep " " scanDirs}"
  );

  systemd.services.clamav-daemon.serviceConfig = {
    Nice = 15;
    CPUWeight = 30;
    IOSchedulingClass = "idle";
    IOWeight = 30;

    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = "read-only";
    ProtectProc = "invisible";
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    PrivateTmp = "yes";
    PrivateDevices = "yes";
    PrivateNetwork = "yes";
    RestrictAddressFamilies = [ "AF_UNIX" ]; # LocalSocket=/run/clamav/clamd.ctl
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    CapabilityBoundingSet = [ "" ];
  };
}
