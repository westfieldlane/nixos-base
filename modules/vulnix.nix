{ pkgs, config, lib, ... }:
let
  cfg = config.services.vulnix;

  # Runs as root (see the "+" on ExecStartPre) so the globs can resolve into
  # other users' profiles, which the scan user cannot read.
  resolveTargets =
    let
      chmod = "${pkgs.coreutils}/bin/chmod";
      mv = "${pkgs.coreutils}/bin/mv";
      readlink = "${pkgs.coreutils}/bin/readlink";
      sort = "${pkgs.coreutils}/bin/sort";
    in
    pkgs.writeShellScript "vulnix-resolve-targets" ''
      set -eu
      export LC_ALL=C

      # Unquoted so the shell expands the globs. A pattern matching nothing is
      # left as a literal, fails the -e test, and is skipped.
      for target in ${lib.concatStringsSep " " cfg.closures}; do
        if [ -e "$target" ]; then
          ${readlink} -f "$target"
        else
          echo "closure target not found, skipping: $target" >&2
        fi
      done | ${sort} -u >"$STATE_DIRECTORY/targets.new"

      # 0644 explicitly: root writes this and the scan user reads it, so the
      # unit's UMask=0027 would otherwise leave it unreadable.
      ${chmod} 0644 "$STATE_DIRECTORY/targets.new"
      ${mv} "$STATE_DIRECTORY/targets.new" "$STATE_DIRECTORY/targets"
    '';

  # -S adds the running system; -C applies closure traversal to every target.
  # Mirror is omitted when null so vulnix keeps its own default. Whitelist
  # paths interpolate to store paths the sandboxed unit can read; strings are
  # URLs vulnix fetches at scan time.
  scanCommand = [ "${pkgs.vulnix}/bin/vulnix" "-S" "-C" "--json" ]
    ++ lib.optionals (cfg.mirror != null) [ "-m" cfg.mirror ]
    ++ lib.concatMap (w: [ "-w" "${w}" ]) cfg.whitelists;
in
{
  options.services.vulnix = {
    enable = lib.mkEnableOption "Periodic CVE scanning with the vulnix utility";

    dates = lib.mkOption {
      type = lib.types.str;
      default = "06:30";
      example = "daily";
      description = ''
        How often or when to run the scan, in the format described in
        {manpage}`systemd.time(7)`. Once a day is sufficient for most systems.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "vulnix";
      description = ''
        User the scan runs as. It owns the NVD cache in {file}`/var/lib/${cfg.user}`
        and the report in {file}`/var/log/${cfg.user}`.
      '';
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "vulnix";
      description = "Primary group of {option}`services.vulnix.user`.";
    };

    mirror = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "http://mirror.soe.example.org/nvd/";
      description = ''
        Base URL the NVD feeds are fetched from, passed as `-m`. Null omits
        the flag, leaving vulnix on its own default.
      '';
    };

    closures = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "/nix/var/nix/profiles/default"
        "/nix/var/nix/profiles/per-user/*/profile"
        "/home/*/.nix-profile"
        "/home/*/.local/state/nix/profiles/profile"
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
        Whitelists passed to vulnix as `-w`. Paths are copied into the Nix
        store so the sandboxed scan can read them; strings are URLs fetched at
        scan time. vulnix aborts on a malformed whitelist, which fails the
        scan rather than silently dropping the suppressions.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # vulnix queries the store with `nix path-info -r --json` — the new CLI,
    # which is refused outright unless nix-command is enabled. Without it every
    # scan dies on its first store query, so catch that at build time rather
    # than at 06:30. extraOptions is checked too: setting the feature there is
    # equally valid, and failing that config would be wrong.
    assertions = [
      {
        assertion = builtins.elem "nix-command" config.nix.settings.experimental-features
          || lib.hasInfix "nix-command" config.nix.extraOptions;
        message = ''
          services.vulnix requires the "nix-command" experimental feature:
          vulnix shells out to `nix path-info` and cannot scan the store
          without it. Add it to nix.settings.experimental-features.
        '';
      }
    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      inherit (cfg) group;
    };
    users.groups.${cfg.group} = { };

    systemd = {
      services."vulnix" = {
        description = "Vulnix vulnerability scan";
        startAt = cfg.dates;

        # vulnix downloads the NVD feeds, so it needs the network up.
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];

        environment = config.nix.envVars
          // { inherit (config.environment.sessionVariables) NIX_PATH; }
          // config.networking.proxy.envVars
          # The NVD cache, which is why the scan needs a writable state dir.
          // { HOME = "%S/${cfg.user}"; };

        script =
          let
            mv = "${pkgs.coreutils}/bin/mv";
          in
          ''
            set -u

            targets=()
            if [ -e "$STATE_DIRECTORY/targets" ]; then
              mapfile -t targets <"$STATE_DIRECTORY/targets"
            fi

            rc=0
            ${lib.escapeShellArgs scanCommand} "''${targets[@]}" \
              >"$LOGS_DIRECTORY/latest.json.new" || rc=$?

            # vulnix exits 1 (whitelisted only) and 2 (active advisories) to report
            # findings, not failure. Anything higher is a real error, and leaves the
            # previous report untouched.
            [ "$rc" -le 2 ] || exit "$rc"

            # check the report has contents before promoting
            if [ ! -s "$LOGS_DIRECTORY/latest.json.new" ]; then
              echo "vulnix produced no report (exit $rc); keeping the previous one" >&2
              exit 1
            fi

            # promote the new json to latest and the old one to previous
            if [ -e "$LOGS_DIRECTORY/latest.json" ]; then
              ${mv} -f "$LOGS_DIRECTORY/latest.json" "$LOGS_DIRECTORY/previous.json"
            fi
            ${mv} -f "$LOGS_DIRECTORY/latest.json.new" "$LOGS_DIRECTORY/latest.json"
          '';

        serviceConfig = {
          Type = "oneshot";

          # The "+" runs this one step as root; see resolveTargets.
          ExecStartPre = lib.mkIf (cfg.closures != [ ]) "+${resolveTargets}";

          User = cfg.user;
          Group = cfg.group;
          RemoveIPC = true;

          LogsDirectory = "${cfg.user}";
          LogsDirectoryMode = "0750";
          StateDirectory = "${cfg.user}";
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
      };

      timers."vulnix".timerConfig.Persistent = true;
    };
  };
}
