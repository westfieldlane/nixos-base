# Hardening only; guarded so hosts without accountsservice do not get a phantom
# accounts-daemon.service with no ExecStart. See ./docker.nix.
{ config, lib, ... }:
{
  systemd.services = lib.mkIf config.services.accounts-daemon.enable {
    accounts-daemon.serviceConfig = {
      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ProtectProc = "invisible";
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectClock = true;
      PrivateTmp = true;
      RestrictSUIDSGID = true;
      SystemCallFilter = [
        "~@swap"
        "~@resources"
        "~@raw-io"
        "~@mount"
        "~@module"
        "~@reboot"
        "~@debug"
        "~@cpu-emulation"
        "~@clock"
      ];
    };
  };
}
