# Security backports for libusb 1.0.29.
#
# Both are memory-safety bugs in descriptor parsing, reachable from public API
# with the malformed input supplied by an attached USB device -- so the threat
# model is a hostile or malfunctioning device plugged into a fleet machine, not
# the network. Upstream fixed both in a single commit
# (bc0886173ea15b8cc9bba2918f58a97a7f185231) released in 1.0.30; nixpkgs 26.05
# still ships 1.0.29 with an empty `patches` list.
#
# Split one-CVE-per-file rather than vendoring the upstream commit whole. vulnix
# matches CVE ids in patch *filenames*, so a combined file would have to be
# named for both ids, and the two fixes would then have to be dropped together
# once nixpkgs catches up. Separate files let each retire on its own.
#
# The redundancy filter below exists because nixpkgs backports without bumping
# versions, so the version number cannot tell you whether a fix has landed.
# Re-applying a patch nixpkgs already carries fails the patch phase outright
# ("Reversed (or previously applied) patch detected") rather than warning.

{ lib, libusb1 }:

assert lib.assertMsg (libusb1.version == "1.0.29") ''
  patches/libusb1 carries CVE-2026-23679 and CVE-2026-47104 backports rebased
  onto libusb 1.0.29, but nixpkgs now ships ${libusb1.version}. Both fixes are
  in upstream 1.0.30, so if this is 1.0.30 or newer just delete this directory.
'';

libusb1.overrideAttrs (old:
let
  existing = map (p: baseNameOf (toString p)) (old.patches or [ ]);

  covered = patch: lib.any (name: lib.hasInfix (lib.removeSuffix ".patch" (baseNameOf patch)) name) existing;
in
{
  patches = (old.patches or [ ]) ++ lib.filter (p: !covered p) [
    ./CVE-2026-23679.patch # NULL deref, parse_interface()   6.2
    ./CVE-2026-47104.patch # 1-byte OOB read, parse_iad_array()  4.0
  ];
})
