{ pkgs, config, lib, ... }:
let
  cfg = config.services.vulnix;
in
{
  options = {
    services.vulnix = {
      enable = lib.mkEnableOption "Periodic CVE scanning with the vulnix utility";

      dates = lib.mkOption {
        type = lib.types.str;
        default = "06:30";
        example = "daily";
        description = ''
          How often or when to run the vulnerability scan. For most desktop and server systems
          a sufficient scan frequency is once a day.

          The format is described in {manpage}`systemd.time(7)`.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    systemd = {
      # Define the service which will execute the CVE scan
      services."vulnix" = {
        description = "Vulnix vulnerability scan";

        serviceConfig = {
          Type = "oneshot";

          DynamicUser = true;

          LogsDirectory = "vulnix";
          StateDirectory = "vulnix";
          UMask = "0077";

          # Least privilege: scanning the store and fetching NVD needs no caps.
          NoNewPrivileges = true;
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";

          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";

          # Kernel / host isolation.
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;

          # Execution restrictions.
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
          # AF_UNIX: nix-daemon socket. AF_INET/6: fetching the NVD feeds.
          RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        };

        environment = config.nix.envVars
          // {
          inherit (config.environment.sessionVariables) NIX_PATH;
          # Writable HOME under StateDirectory (owned by the dynamic user) so
          # vulnix/nix caches don't try to touch the real /root, which is now
          # both hidden (ProtectHome) and read-only (ProtectSystem=strict).
          HOME = "/var/lib/vulnix";
        }
          // config.networking.proxy.envVars;

        script =
          let
            vulnix = "${pkgs.vulnix}/bin/vulnix";
            date = "${pkgs.coreutils}/bin/date";
          in
          ''
            set -e

            stamp="$(${date} +%Y-%m-%d)"

            rc=0
            ${vulnix} -Svv \
              1>"$LOGS_DIRECTORY/$stamp.results.log" \
              2>"$LOGS_DIRECTORY/$stamp.debug.log" || rc=$?

            if [ "$rc" -gt 2 ]; then
              exit "$rc"
            fi
          '';

        startAt = cfg.dates;

        # vulnix pulls from the NIST database, and therefore needs network access
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
      };

      # Define the timer which will trigger the scan
      timers."vulnix" = {
        timerConfig = {
          Persistent = true;
        };
      };
    };
  };
}
