{ lib, pkgs, ... }:
let
  # Directories to scan (referenced by both the module and the forced ExecStart below).
  scanDirs = [
    "/home"
    "/var/lib"
    "/tmp"
    "/etc"
    "/var/tmp"
  ];

  # Paths to skip: container/VM image stores and database data dirs. These hold
  # large, frequently-changing, non-executable blobs that are pointless to scan
  # and are what pins the CPU. Regexes are matched against the full path.
  #
  # NOTE: with `clamdscan --fdpass`, clamd.conf's ExcludePath is bypassed (the
  # client walks the tree and passes fds). So the authoritative excludes for the
  # scheduled scan are the client-side `--exclude-dir` flags in ExecStart below;
  # the daemon ExcludePath list is kept only for on-access scanning.
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
        # Cap scan parallelism: 4 of 8 cores instead of the default 10 threads.
        MaxThreads = 4;
        # Don't let a single pathological archive peg a worker forever (ms).
        MaxScanTime = 120000;
      };
    };
    updater.enable = true;
    updater.frequency = 12;
    scanner = {
      enable = true;
      interval = "*-*-* 05:30:00";
      scanDirectories = scanDirs;
    };
  };

  # The NixOS module hardcodes the clamdscan command with no way to pass
  # --exclude-dir, and ExcludePath doesn't apply under --fdpass. Force the
  # command to add client-side excludes.
  systemd.services.clamdscan.serviceConfig.ExecStart = lib.mkForce (
    "${pkgs.clamav}/bin/clamdscan --multiscan --fdpass --infected --allmatch "
    + "${excludeFlags} ${lib.concatStringsSep " " scanDirs}"
  );

  # The scan's CPU is spent in the long-running clamd daemon, so throttle there.
  # Soft controls (weight/nice) let the 05:30 scan run full-speed when the box
  # is idle but yield immediately to interactive work if it overlaps.
  systemd.services.clamav-daemon.serviceConfig = {
    Nice = 15;
    CPUWeight = 30;
    IOSchedulingClass = "idle";
    IOWeight = 30;
  };
}
