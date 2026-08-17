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

      user = lib.mkOption {
        type = lib.types.str;
        default = "vulnix";
        description = ''
          User account under which the scan runs. It owns the NVD cache in
          {file}`/var/lib/vulnix` and the retained report in
          {file}`/var/log/vulnix`.

          The account is declared by this module.
        '';
      };

      group = lib.mkOption {
        type = lib.types.str;
        default = "vulnix";
        description = ''
          Primary group of {option}`services.vulnix.user`. Members can read the
          most recent report at {file}`/var/log/vulnix/latest.json` without
          root, so point this at an existing administrative group, or add
          administrators to it, to grant access.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      inherit (cfg) group;
    };
    users.groups.${cfg.group} = { };

    systemd = {
      # Define the service which will execute the CVE scan
      services."vulnix" = {
        description = "Vulnix vulnerability scan";

        serviceConfig = {
          Type = "oneshot";

          User = cfg.user;
          Group = cfg.group;
          RemoveIPC = true;

          LogsDirectory = "vulnix";
          LogsDirectoryMode = "0750";
          StateDirectory = "vulnix";
          # 0027 so members of cfg.group can read the retained report.
          UMask = "0027";

          NoNewPrivileges = true;
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";

          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";

          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;

          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
          RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        };

        environment = config.nix.envVars
          // {
          inherit (config.environment.sessionVariables) NIX_PATH;
          HOME = "/var/lib/vulnix";
        }
          // config.networking.proxy.envVars;

        script =
          let
            vulnix = "${pkgs.vulnix}/bin/vulnix";
            jq = "${pkgs.jq}/bin/jq";
            cat = "${pkgs.coreutils}/bin/cat";
            mv = "${pkgs.coreutils}/bin/mv";
            rm = "${pkgs.coreutils}/bin/rm";
            wc = "${pkgs.coreutils}/bin/wc";
          in
          ''
            set -e

            latest="$LOGS_DIRECTORY/latest.json"
            staging="$latest.new"
            compact="$latest.compact"

            rc=0
            ${vulnix} -S --json >"$staging" || rc=$?

            if ! ${jq} -e . "$staging" >/dev/null 2>&1; then
              ${rm} -f "$staging"
              echo "vulnix produced no parseable JSON report (vulnix exit $rc)" >&2
              [ "$rc" -gt 2 ] || rc=1
              exit "$rc"
            fi

            ${mv} -f "$staging" "$latest"

            ${jq} -c . "$latest" >"$compact"
            ${cat} "$compact"

            if [ $(${wc} -c <"$compact") -gt 48000 ]; then
              echo "report is $size bytes and may exceed one journal record; full report retained at $latest" >&2
            fi
            ${rm} -f "$compact"

            # vulnix exits 1/2 to report findings; only higher codes are errors.
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
