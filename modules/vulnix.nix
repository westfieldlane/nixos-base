{ pkgs, config, lib, ... }:
let
  cfg = config.services.vulnix;

  # A malformed whitelist is not a warning. vulnix aborts while loading it, so
  # ONE bad character stops every suppression in the file from applying at
  # once -- and the way you find out is a scan that suddenly reports dozens of
  # findings you triaged months ago. Validating here turns that into a build
  # failure at the point the typo was introduced.
  #
  # The two regexes mirror vulnix/whitelist.py:check_section_header, which
  # rejects unquoted section headers before TOML parsing ever runs.
  whitelistChecker = pkgs.writeText "check-vulnix-whitelist.py" ''
    import re
    import sys

    import toml

    path = sys.argv[1]
    with open(path) as fobj:
        content = fobj.read()

    if re.search(r'^\s*\[[^"a-zA-Z]', content, re.M) or \
       re.search(r'^\s*\[[^\]]*[^"a-zA-Z0-9]\]$', content, re.M):
        sys.exit("vulnix requires quoted section headers, e.g. [\"pname\"]")

    toml.load(path)
  '';

  # Paths are checked and passed through; strings are URLs fetched at scan time
  # and cannot be inspected at build time.
  checkWhitelist = w:
    if builtins.isPath w then
      pkgs.runCommand "checked-${baseNameOf (toString w)}" { src = w; } ''
        ${pkgs.python3.withPackages (ps: [ ps.toml ])}/bin/python3 \
          ${whitelistChecker} "$src"
        cp "$src" "$out"
      ''
    else w;

  # WARNING: resolveTargets specifically runs as root so the scanner
  # utility can run with minimal permissions. This will resolve all targets
  # in the cfg.closures option to their nix store paths.
  resolveTargets = pkgs.writeShellScript "vulnix-resolve-targets" ''
    set -eu
    export LC_ALL=C

    out="$STATE_DIRECTORY/targets"
    tmp="$out.new"

    : >"$tmp"
    for target in ${lib.concatStringsSep " " cfg.closures}; do
      if [ -e "$target" ]; then
        ${pkgs.coreutils}/bin/readlink -f "$target" >>"$tmp"
      fi
    done
    ${pkgs.coreutils}/bin/sort -u -o "$tmp" "$tmp"

    # 0644 explicitly: root writes it, the scan user reads it, UMask=0027.
    ${pkgs.coreutils}/bin/install -m 0644 "$tmp" "$out"
    ${pkgs.coreutils}/bin/rm -f "$tmp"
  '';
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
        '';
      };

      group = lib.mkOption {
        type = lib.types.str;
        default = "vulnix";
        description = ''
          Primary group of {option}`services.vulnix.user`. 
        '';
      };

      mirror = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "http://mirror.soe.example.org/nvd/";
        description = ''
          Base URL the NVD JSON feeds are fetched from, passed to vulnix as
          `-m`. Null omits the flag entirely, leaving vulnix on its own default.
        '';
      };

      closures = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "/nix/var/nix/profiles/default"
          "/nix/var/nix/profiles/per-user/*/profile"
          "/home/*/.nix-profile"
          "/home/*/.local/state/nix/profiles/profile"
          # The generation closure, a superset of the user profile above.
          "/home/*/.local/state/nix/profiles/home-manager"
        ];
        example = lib.literalExpression ''
          [ "/nix/var/nix/profiles/per-user/buildbot/profile" ]
        '';
        description = ''
          What to scan on top of the running system. Entries are shell glob
          patterns; each match is resolved to its store path, and patterns
          matching nothing are skipped. Set to `[ ]` to scan only the system.
        '';
      };

      whitelists = lib.mkOption {
        type = lib.types.listOf (lib.types.either lib.types.path lib.types.str);
        default = [ ];
        example = lib.literalExpression ''
          [
            ./vulnix-whitelist.toml
            "https://soe.example.org/vulnix-whitelist.toml"
          ]
        '';
        description = ''
          Whitelists passed to vulnix as `-w`. Each entry is either a path,
          which is copied into the Nix store so the sandboxed scan can read it,
          or a URL fetched at scan time.
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

          # This triggers the script which runs as root (note the "+"). Everything else
          # runs as ${cfg.user}:${cfg.group}
          ExecStartPre = lib.mkIf (cfg.closures != [ ]) "+${resolveTargets}";

          User = cfg.user;
          Group = cfg.group;
          RemoveIPC = true;

          LogsDirectory = "vulnix";
          LogsDirectoryMode = "0750";
          StateDirectory = "vulnix";
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
            comm = "${pkgs.coreutils}/bin/comm";
            cp = "${pkgs.coreutils}/bin/cp";
            mv = "${pkgs.coreutils}/bin/mv";
            rm = "${pkgs.coreutils}/bin/rm";
            wc = "${pkgs.coreutils}/bin/wc";

            # Omitted entirely when null so vulnix keeps its own default.
            mirrorArg = lib.optionalString (cfg.mirror != null)
              "-m ${lib.escapeShellArg cfg.mirror}";

            # checkWhitelist turns each path into a build-time-validated copy;
            # URLs pass through untouched. See the top of this file.
            whitelistArgs = lib.concatMapStringsSep " "
              (w: "-w ${lib.escapeShellArg "${checkWhitelist w}"}")
              cfg.whitelists;
          in
          ''
            set -e

            export LC_ALL=C

            latest="$LOGS_DIRECTORY/latest.json"
            staging="$latest.new"
            compact="$latest.compact"

            # Resolved by the privileged ExecStartPre; see resolveTargets.
            extraTargets=()
            ${lib.optionalString (cfg.closures != [ ]) ''
              resolved="$STATE_DIRECTORY/targets"
              if [ -s "$resolved" ]; then
                while IFS= read -r target; do
                  [ -n "$target" ] && extraTargets+=("$target")
                done <"$resolved"
              fi
              echo "scanning ''${#extraTargets[@]} extra closure(s) alongside the system" >&2
            ''}

            # Execute the actual scan, and save to staging file
            # -S adds the running system; -C applies the traversal to every target.
            rc=0
            ${vulnix} -S -C "''${extraTargets[@]}" ${mirrorArg} ${whitelistArgs} \
              --json >"$staging" || rc=$?

            # If the staging file is empty, then something went wrong
            if ! ${jq} -e . "$staging" >/dev/null 2>&1; then
              ${rm} -f "$staging"
              echo "vulnix produced no parseable JSON report (vulnix exit $rc)" >&2
              [ "$rc" -gt 2 ] || rc=1
              exit "$rc"
            fi

            # Triage happens on what changed. The standing list is re-read only
            # when somebody goes looking; the delta is what needs a decision
            # today, so it is reported separately and kept small.
            previous="$LOGS_DIRECTORY/previous.json"
            pairs() {
              ${jq} -r '[.[] | . as $pkg | .affected_by[] | "\($pkg.name)\t\(.)"] | sort | .[]' "$1"
            }

            # Determine what are new CVEs and what are "fixed" CVEs
            if [ -f "$previous" ]; then
              pairs "$previous" >"$latest.pairs.old"
              pairs "$staging" >"$latest.pairs.new"

              ${comm} -13 "$latest.pairs.old" "$latest.pairs.new" >"$latest.pairs.added"
              ${comm} -23 "$latest.pairs.old" "$latest.pairs.new" >"$latest.pairs.gone"

              if [ -s "$latest.pairs.added" ]; then
                echo "new since previous scan:" >&2
                ${cat} "$latest.pairs.added" >&2
              else
                echo "no new findings since previous scan" >&2
              fi

              # The other half of the cycle: confirming a remediation landed.
              if [ -s "$latest.pairs.gone" ]; then
                echo "resolved since previous scan:" >&2
                ${cat} "$latest.pairs.gone" >&2
              fi

              ${rm} -f "$latest.pairs.old" "$latest.pairs.new" \
                       "$latest.pairs.added" "$latest.pairs.gone"
            else
              echo "no previous report to compare against; this run establishes the baseline" >&2
            fi

            ${cp} -f "$staging" "$previous"
            ${mv} -f "$staging" "$latest"

            ${jq} -c . "$latest" >"$compact"
            ${cat} "$compact"

            size=$(${wc} -c <"$compact")
            if [ "$size" -gt 48000 ]; then
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
