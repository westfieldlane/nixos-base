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
  # No downstream sink yet. When one is available, add sinks.<name>
  # alongside local_archive — Vector fans out, and the archive keeps
  # working as a durable local buffer.
  services.vector = {
    enable = true;
    journaldAccess = true;

    settings = {
      data_dir = "/var/lib/vector";

      sources.journald = {
        type = "journald";
        current_boot_only = false;
      };

      # Single VRL pass: envelope → classifier → per-dataset enrichment.
      transforms.normalize = {
        type = "remap";
        inputs = [ "journald" ];
        source = ''
          # --- Envelope -----------------------------------------------
          .ecs.version = "8.11"
          hostname = get_hostname!() ?? "unknown"
          .host = { "hostname": hostname, "name": hostname }
          .@timestamp = del(.timestamp) ?? now()

          unit = del(._SYSTEMD_UNIT) ?? ""
          .process.name = if unit != "" { unit } else { del(._COMM) ?? "" }
          .process.pid = to_int(del(._PID) ?? 0) ?? 0

          # Drop the noisiest journald internals we won't query on
          del(._MACHINE_ID); del(._BOOT_ID); del(._TRANSPORT)
          del(._SOURCE_REALTIME_TIMESTAMP); del(._SYSTEMD_CGROUP)
          del(._CAP_EFFECTIVE); del(._SELINUX_CONTEXT)
          del(._SYSTEMD_INVOCATION_ID); del(._SYSTEMD_SLICE)

          # --- Classifier ---------------------------------------------
          .data_stream.type = "logs"
          .data_stream.namespace = "default"
          .data_stream.dataset =
            if starts_with(unit, "audit") ?? false          { "auditd"    }
            else if starts_with(unit, "sshd") ?? false      { "ssh"       }
            else if starts_with(unit, "fail2ban") ?? false  { "fail2ban"  }
            else if starts_with(unit, "sudo") ?? false      { "sudo"      }
            else if starts_with(unit, "clamav") ?? false    { "clamav"    }
            else                                            { "system"    }

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
                if exists(fields.res) {
                  .event.outcome = if fields.res == "success" { "success" } else { "failure" }
                }
              }
            }
          } else if dataset == "ssh" {
            .event = { "kind": "event", "category": ["authentication"] }
            if contains(msg, "Accepted") ?? false {
              .event.outcome = "success"; .event.action = "logged-in"
            } else if contains(msg, "Failed password") ?? false {
              .event.outcome = "failure"; .event.action = "password-failed"
            } else if contains(msg, "Invalid user") ?? false {
              .event.outcome = "failure"; .event.action = "user-not-found"
            }
            m, err = parse_regex(msg, r'from (?P<ip>\S+) port (?P<port>\d+)')
            if err == null { .source.ip = m.ip; .source.port = to_int(m.port) ?? null }
          } else if dataset == "fail2ban" {
            .event = { "kind": "alert", "category": ["intrusion_detection"] }
            m, err = parse_regex(msg, r'\]\s+(?P<action>Ban|Unban|Found)\s+(?P<ip>\S+)')
            if err == null {
              .event.action = downcase(m.action) ?? m.action
              .source.ip = m.ip
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
            if contains(msg, "FOUND") ?? false {
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
        inputs = [ "normalize" ];
        path = "/var/log/vector/{{ data_stream.dataset }}-%Y-%m-%d.jsonl";
        encoding.codec = "json";
      };
    };
  };

  # Age off archive after 30d. Tune down once a durable downstream exists.
  systemd.tmpfiles.rules = [
    "e /var/log/vector - - - 30d"
  ];

  # Conservative sandbox. No SystemCallFilter yet — tune tighter after
  # observing production behaviour with `systemd-analyze security vector`.
  systemd.services.vector.serviceConfig = {
    StateDirectory = "vector";
    LogsDirectory = "vector";

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
}
