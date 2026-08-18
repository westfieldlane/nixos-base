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

          Leaving this at the default creates a group nobody belongs to, which
          makes the retained report root-only in practice.
        '';
      };

      mirror = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = "http://mirror.soe.example.org/nvd/";
        description = ''
          Base URL the NVD JSON feeds are fetched from, passed to vulnix as
          `-m`. Null omits the flag entirely, leaving vulnix on its own default
          of <https://nvd.nist.gov/feeds/json/cve/2.0/>.

          A mirror must serve the upstream file names, {file}`nvdcve-2.0-`
          followed by the year and {file}`.json.gz`, and should pass through
          `ETag`, because vulnix revalidates with `If-None-Match` and skips any
          archive that answers 304. Without that the scan re-downloads
          everything on every run.

          NIST shapes these feeds to roughly 90 KB/s per connection against a
          20 MB-plus archive per year, so a fleet pointed straight at
          {file}`nvd.nist.gov` spends minutes per host per cold start and draws
          further throttling from a shared egress address. An internal mirror
          seeded once and served over the LAN avoids both.

          This must be a feed URL. The NVD REST API is a different interface
          and vulnix cannot read it.
        '';
      };

      scanProfiles = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Also scan the Nix profiles found on the machine, so packages a user
          installed outside the system closure are covered.

          `-S` reaches the activated system and nothing else. Anything from
          {command}`nix profile`, {command}`nix-env`, or home-manager lives in a
          separate profile whose closure the system never references, and on a
          typical workstation that is a few hundred store paths of genuinely
          executable software. Leaving them out understates what the machine
          runs, which is the one error worth avoiding here.

          The standard profile locations are globbed at scan time and the ones
          that exist are added as targets. Discovery is deliberately runtime
          rather than evaluation time, because which users exist and what they
          have installed is not knowable when the system is built.

          Per-user profile symlinks live under {file}`/home`, so enabling this
          relaxes the unit's `ProtectHome` from `true` to `"read-only"`. The
          module does that on its own, and reverts it when this is disabled.
        '';
      };

      closures = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        example = lib.literalExpression ''
          [ "/nix/var/nix/profiles/per-user/buildbot/profile" ]
        '';
        description = ''
          Additional store paths to scan, on top of the running system.

          The scan always passes `-S -C`. `-S` supplies the current system as a
          target and `-C` selects the traversal: every target is examined with
          {command}`nix path-info -r`, so a package is reported only if the
          running system can actually reach it. An empty list therefore scans
          the activated system plus whatever
          {option}`services.vulnix.scanProfiles` discovers, and entries here are
          added to those rather than replacing them.

          Use this for anything those two miss, such as a service-owned profile
          outside the standard locations.

          Without `-C`, vulnix resolves each target to its {file}`.drv` and
          walks {command}`nix-store -qR` over that instead. The requisites of a
          derivation are its *build* inputs, so that pulls in bootstrap
          compilers, source archives, and language build tooling that sits in
          the store but never executes -- on a typical machine the difference
          between roughly 12000 and 1700 paths, with the extra 10000 producing
          high-scoring findings that nothing can reach.

          Entries must be strings. A Nix path literal would be copied into the
          store during evaluation, and the scan would then examine that frozen
          copy under a new name instead of the live system.
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

          Whitelists suppress findings that have been triaged, which keeps the
          report small enough that a new finding is noticeable. Entries are
          TOML, keyed by a quoted package name with an optional version:

          ```toml
          ["libfoo"]
          cve = [ "CVE-2026-0001" ]
          comment = "CPE collision: the CVE is against an unrelated project."

          ["libbar-1.2.3"]
          cve = [ "CVE-2026-0002" ]
          until = "2026-12-01"
          comment = "Accepted until the next release bumps this."
          ```

          The section header must be quoted; vulnix rejects a bare `[libfoo]`.
          Use `until` for accepted risk so the entry expires and the finding
          comes back, and reserve undated entries for findings that are wrong
          rather than merely tolerated.

          Note that {option}`services.vulnix.closures` filters build-only
          inputs more cheaply than whitelisting them one by one.

          Keep whitelists in the store or under {file}`/etc`. A path under
          {file}`/home` only resolves while {option}`services.vulnix.scanProfiles`
          is holding `ProtectHome` at `"read-only"`, and stops resolving the
          moment profile scanning is turned off.
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
          UMask = "0027";

          NoNewPrivileges = true;
          CapabilityBoundingSet = "";
          AmbientCapabilities = "";

          ProtectSystem = "strict";
          ProtectHome = if cfg.scanProfiles then "read-only" else true;
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

            # -S supplies the current system as a target; -C is the traversal
            # mode and applies to every target, so extra closures need no flag
            # of their own.
            scanTargets = "-S -C " + lib.concatMapStringsSep " " lib.escapeShellArg cfg.closures;

            # Omitted entirely when null so vulnix keeps its own default.
            mirrorArg = lib.optionalString (cfg.mirror != null)
              "-m ${lib.escapeShellArg cfg.mirror}";

            # Left unquoted on purpose so the shell expands them.
            profileGlobs = lib.concatStringsSep " " [
              "/nix/var/nix/profiles/default"
              "/nix/var/nix/profiles/per-user/*/profile"
              "/home/*/.nix-profile"
              "/home/*/.local/state/nix/profiles/profile"
            ];

            whitelistArgs = lib.concatMapStringsSep " "
              (w: "-w ${lib.escapeShellArg "${w}"}")
              cfg.whitelists;
          in
          ''
            set -e

            export LC_ALL=C

            latest="$LOGS_DIRECTORY/latest.json"
            staging="$latest.new"
            compact="$latest.compact"

            # Determine which extra profiles need to be scanned
            # NOTE: this has to be done at script runtime, not at build-time, hence why it's here
            profileTargets=()
            ${lib.optionalString cfg.scanProfiles ''
              for profile in ${profileGlobs}; do
                if [ -e "$profile" ]; then
                  profileTargets+=("$profile")
                fi
              done
              echo "scanning ''${#profileTargets[@]} profile(s) alongside the system" >&2
            ''}

            # Execute the actual scan, and save to staging file
            rc=0
            ${vulnix} ${scanTargets} "''${profileTargets[@]}" ${mirrorArg} ${whitelistArgs} \
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
