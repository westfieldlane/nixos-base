{
  config,
  lib,
  pkgs,
  ...
}:
let
  # Directories the scheduled scan walks (passed to the forced ExecStart below).
  scanDirs = [
    "/home"
    "/var/lib"
    "/tmp"
    "/etc"
    "/var/tmp"
  ];

  # NOTE: neither list below actually takes effect on the scheduled scan.
  # clamdscan has no --exclude-dir option (it logs "Ignoring unsupported
  # option" and scans anyway), and --fdpass bypasses clamd.conf ExcludePath
  # because the client walks the tree itself. --fdpass cannot simply be
  # dropped either: the daemon runs with PrivateTmp and would scan its own
  # /tmp. Filter with `find -prune` into --file-list if this is re-enabled.
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
      enable = lib.mkDefault false;
      settings = {
        ExcludePath = excludeDirs;
        MaxThreads = 4;
        MaxScanTime = 120000;
      };
    };
    updater.enable = lib.mkDefault false;
    updater.frequency = 12;
    scanner = {
      enable = lib.mkDefault false;
      interval = "*-*-* 05:30:00";
    };
  };

  systemd.services = lib.mkMerge [
    # The module's clamdscan exposes no --exclude-dir knob; force the command to
    # add client-side excludes (+ --allmatch).
    (lib.mkIf config.services.clamav.scanner.enable {
      clamdscan.serviceConfig.ExecStart = lib.mkForce (
        "${pkgs.clamav}/bin/clamdscan --multiscan --fdpass --infected --allmatch "
        + "${excludeFlags} ${lib.concatStringsSep " " scanDirs}"
      );
    })

    # Hardening only; guarded so a host that forces the daemon off does not get
    # a phantom clamav-daemon.service with no ExecStart. See ./docker.nix.
    (lib.mkIf config.services.clamav.daemon.enable {
      clamav-daemon.serviceConfig = {
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
    })
  ];
}
