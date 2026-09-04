{ config, lib, ... }:
{
  systemd.services = lib.mkIf config.hardware.bluetooth.enable {
    bluetooth.serviceConfig = lib.mkForce {
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
  };
}
