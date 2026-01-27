{ lib, ... }:
{
  systemd.services.bluetooth.serviceConfig = lib.mkForce {
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectHostname = true;
    ProtectControlGroups = true;
    ProtectProc = "invisible";
    SystemCallFilter = [
      "~@obsolete"
      "~@cpu-emulation"
      "~@swap"
      "~@reboot"
      "~@mount"
    ];
    SystemCallArchitectures = "native";
  };
}
