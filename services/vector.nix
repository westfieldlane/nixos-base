{ config, lib, ... }:
let
  vulnix = config.services.vulnix;

  # The vulnix source only makes sense on a host that runs the scanner;
  # guarding it keeps the base usable everywhere else.
  vulnixEnabled = vulnix.enable;

  # Everything that has been through a normalize pass. Sinks take this
  # rather than spelling the list out, so adding a source cannot silently
  # miss one.
  normalized = [ "normalize" ] ++ lib.optional vulnixEnabled "vulnix_normalize";
in
{
  # vector.service — log collection + normalization shipper.
  #
  # Two-stage log pipeline (see audit.nix for stage 1's auditd bridge):
  #   Stage 1: every source funnels into journald
  #            (auditd → audispd syslog plugin → journald; everything
  #             else logs to journald natively)
  #   Stage 2: Vector reads journald, normalizes to an ECS-lite schema,
  #            and writes daily per-dataset JSONL to /var/log/vector.
  #
  # One exception to stage 1: the vulnix report is structured JSON read
  # straight off disk, never through journald — reports run well past
  # journald's 48K LineMax and would arrive truncated.
  #
  # No downstream sink yet. When one is available, add sinks.<name>
  # alongside local_archive — Vector fans out, and the archive keeps
  # working as a durable local buffer.
  services.vector = {
    enable = true;
    journaldAccess = true;

    settings = lib.recursiveUpdate {
      data_dir = "/var/lib/vector";

      sources.journald = {
        type = "journald";
        current_boot_only = false;
        # Prevent feedback loop: Vector's own logs go to journald, so
        # without this we'd re-process every log line we emit, which
        # amplifies volume dramatically.
        exclude_units = [ "vector.service" ];
      };

      # Single VRL pass: envelope → classifier → per-dataset enrichment.
      transforms.normalize = {
        type = "remap";
        inputs = [ "journald" ];
        source = ''
          # --- Envelope -----------------------------------------------
          # Note: VRL doesn't narrow types via `if x == null` checks —
          # we have to explicitly coerce with `to_string(...) ?? default`
          # so downstream operations know the value is a string.
          .ecs.version = "8.11"

          hostname = to_string(del(.host)) ?? "unknown"
          .host = { "hostname": hostname, "name": hostname }

          ts = del(.timestamp)
          if ts == null { ts = now() }
          .@timestamp = ts

          unit = to_string(del(._SYSTEMD_UNIT)) ?? ""
          comm = to_string(del(._COMM)) ?? ""
          if unit != "" { .process.name = unit } else { .process.name = comm }
          .process.pid = to_int(del(._PID)) ?? 0

          # Drop the noisiest journald internals we won't query on
          del(._MACHINE_ID); del(._BOOT_ID); del(._TRANSPORT)
          del(._SOURCE_REALTIME_TIMESTAMP); del(._SYSTEMD_CGROUP)
          del(._CAP_EFFECTIVE); del(._SELINUX_CONTEXT)
          del(._SYSTEMD_INVOCATION_ID); del(._SYSTEMD_SLICE)

          # --- Classifier ---------------------------------------------
          # Sequential-override pattern: default first, then any match
          # wins. We check both the systemd unit AND _COMM because
          # user-invoked programs (sudo especially) don't have their own
          # systemd unit — they inherit user@N.service.
          .data_stream.type = "logs"
          .data_stream.namespace = "default"
          .data_stream.dataset = "system"

          # Unit-based (services running as systemd units)
          if starts_with(unit, "audit")    { .data_stream.dataset = "auditd"   }
          if starts_with(unit, "sshd")     { .data_stream.dataset = "ssh"      }
          if starts_with(unit, "fail2ban") { .data_stream.dataset = "fail2ban" }
          if starts_with(unit, "clamav")   { .data_stream.dataset = "clamav"   }

          # Comm-based (invoked from user sessions, not systemd services)
          if comm == "sudo"           { .data_stream.dataset = "sudo"   }
          if comm == "audisp-syslog"  { .data_stream.dataset = "auditd" }

          # --- Per-dataset enrichment ---------------------------------
          dataset = .data_stream.dataset
          msg = to_string(.message) ?? ""

          if dataset == "auditd" {
            m, err = parse_regex(msg, r'^type=(?P<t>\S+) msg=audit\((?P<ep>[\d.]+):(?P<seq>\d+)\):\s*(?P<rest>.*)$')
            if err == null {
              .event = { "kind": "event", "category": ["iam", "process"], "action": m.t }
              .audit.sequence = to_int(m.seq) ?? null
              fields, ferr = parse_key_value(m.rest, key_value_delimiter: "=", field_delimiter: " ")
              if ferr == null {
                .audit.fields = fields
                if fields.res != null {
                  if fields.res == "success" { .event.outcome = "success" } else { .event.outcome = "failure" }
                }
              }
            }
          } else if dataset == "ssh" {
            .event = { "kind": "event", "category": ["authentication"] }
            if contains(msg, "Accepted") {
              .event.outcome = "success"; .event.action = "logged-in"
            } else if contains(msg, "Failed password") {
              .event.outcome = "failure"; .event.action = "password-failed"
            } else if contains(msg, "Invalid user") {
              .event.outcome = "failure"; .event.action = "user-not-found"
            }
            m, err = parse_regex(msg, r'from (?P<ip>\S+) port (?P<port>\d+)')
            if err == null { .source.ip = m.ip; .source.port = to_int(m.port) ?? null }
          } else if dataset == "fail2ban" {
            .event = { "kind": "alert", "category": ["intrusion_detection"] }
            m, err = parse_regex(msg, r'\]\s+(?P<action>Ban|Unban|Found)\s+(?P<ip>\S+)')
            if err == null {
              .source.ip = m.ip
              if m.action == "Ban"   { .event.action = "ban"    }
              if m.action == "Unban" { .event.action = "unban"  }
              if m.action == "Found" { .event.action = "detect" }
            }
          } else if dataset == "sudo" {
            .event = { "kind": "event", "category": ["iam"], "type": ["change"] }
            m, err = parse_regex(msg, r'(?P<u>\S+)\s*:\s*TTY=(?P<tty>\S+).*USER=(?P<t>\S+)\s*;\s*COMMAND=(?P<c>.*)$')
            if err == null {
              .user.name = m.u
              .sudo = { "tty": m.tty, "target_user": m.t }
              .process.command_line = m.c
              .event.action = "sudo-run"
            }
          } else if dataset == "clamav" {
            if contains(msg, "FOUND") {
              .event = { "kind": "event", "category": ["malware"], "action": "malware-detected", "outcome": "failure" }
              m, err = parse_regex(msg, r'(?P<p>\S+):\s+(?P<s>\S+)\s+FOUND')
              if err == null { .file.path = m.p; .threat.name = m.s }
            }
          }
        '';
      };

      # Local archive: daily per-dataset JSONL. Add a network sink here
      # later; Vector will fan out and this stays as a durability floor.
      sinks.local_archive = {
        type = "file";
        inputs = normalized;
        path = "/var/log/vector/{{ data_stream.dataset }}-%Y-%m-%d.jsonl";
        encoding.codec = "json";
      };
    } (lib.optionalAttrs vulnixEnabled {
      sources.vulnix_report = {
        type = "file";

        # The exact path, not a glob: previous.json sits beside it and holds
        # a report that has already been shipped.
        include = [ "/var/log/${vulnix.user}/latest.json" ];
        read_from = "beginning";

        # device_and_inode, NOT the default checksum. The scan replaces
        # latest.json by rename, so every report arrives as a new inode. A
        # checksum over the opening bytes is unchanged between scans —
        # vulnix sorts by derivation, so the first entry rarely moves —
        # which Vector reads as "already ingested" and then ships nothing,
        # with no error and no log line.
        fingerprint.strategy = "device_and_inode";

        # vulnix pretty-prints, so one report is many short lines. This
        # reassembles the array into a single event, which the transform
        # below fans back out. halt_with on the closing bracket is exact;
        # the timeout is only the fallback if vulnix ever emitted the array
        # on one line.
        multiline = {
          start_pattern = "^\\[";
          mode = "halt_with";
          condition_pattern = "^\\]";
          timeout_ms = 5000;
        };

        # Not needed at any report size today: max_line_bytes applies per
        # line read from disk, before multiline reassembly, and the longest
        # line vulnix emits is a few hundred bytes. Raised purely so that a
        # switch to compact JSON output would not silently drop every
        # report — the default 100K would, without logging anything.
        max_line_bytes = 16777216;
      };

      transforms.vulnix_normalize = {
        type = "remap";
        inputs = [ "vulnix_report" ];
        source = ''
          parsed, err = parse_json(.message)
          if err != null {
            log("vulnix: unparseable report, dropping", level: "error")
            abort
          }

          # One event in, one per (package, CVE) out: a remap returning an
          # array has each element emitted as its own event. A clean host
          # reports an empty array, which emits nothing.
          #
          # The file source carries no host field, unlike journald, and the
          # report carries no scan time — ingest time is within seconds of
          # the scan, since the source is watching for the rename.
          ts = now()
          hostname = get_hostname!()

          out = []
          for_each(array!(parsed)) -> |_i, entry| {
            pkg = object!(entry)
            scores = object(pkg.cvssv3_basescore) ?? {}

            for_each(array(pkg.affected_by) ?? []) -> |_j, id| {
              cve = string!(id)
              out = push(out, {
                "@timestamp": ts,
                "ecs": { "version": "8.11" },
                "host": { "hostname": hostname, "name": hostname },
                "data_stream": {
                  "type": "logs",
                  "namespace": "default",
                  "dataset": "vulnix"
                },
                # A census, not a transition: every event says this CVE was
                # outstanding as of this scan, so there is no outcome to
                # report. "what changed" is a query across scans.
                "event": {
                  "kind": "state",
                  "category": ["vulnerability"]
                },
                "vulnerability": {
                  "id": cve,
                  "score": get(scores, [cve]) ?? null
                },
                "package": {
                  "name": pkg.pname,
                  "version": pkg.version,
                  "derivation": pkg.derivation
                }
              })
            }
          }

          # vulnix also carries a per-CVE description. It is deliberately
          # dropped: in a census it would be repeated on every event, every
          # scan, every host, and it is retrievable from NVD by id.
          . = out
        '';
      };
    });
  };

  # Age off archive after 30d. Tune down once a durable downstream exists.
  systemd.tmpfiles.rules = [
    "e /var/log/vector - - - 30d"
  ];

  # Conservative sandbox. No SystemCallFilter yet — tune tighter after
  # observing production behaviour with `systemd-analyze security vector`.
  # Guarded so a host that forces Vector off does not get a phantom
  # vector.service with no ExecStart. See ./docker.nix.
  systemd.services = lib.mkIf config.services.vector.enable {
    vector.serviceConfig = {
      StateDirectory = "vector";
      LogsDirectory = "vector";

      # /var/log/vulnix is 0750 vulnix:vulnix and Vector runs as a DynamicUser,
      # so it cannot be added via users.users — the account does not exist
      # statically. A supplementary group is what works, and it is load-bearing:
      # without it the file source silently reads nothing.
      SupplementaryGroups = lib.optionals vulnixEnabled [ vulnix.group ];

      NoNewPrivileges = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ProtectHostname = true;
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectControlGroups = true;
      ProtectProc = "invisible";
      ProtectClock = true;
      PrivateTmp = true;
      PrivateDevices = true;
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      CapabilityBoundingSet = [ "" ];
      AmbientCapabilities = [ "" ];
    };
  };
}
