# Security backports for dhcpcd 10.3.1.
#
# Four bugs found in one coordinated batch (all reported by CuB3y0nd, all fixed
# by Roy Marples on 2026-06-22/23) and released in dhcpcd 10.3.2. nixpkgs 26.05
# still ships 10.3.1 with an empty `patches` list.
#
# Three are unauthenticated same-link attacks -- the threat model is anyone on
# the same LAN segment as a fleet machine, reached through ordinary DHCPv6 and
# Router Advertisement traffic that dhcpcd processes by default. The fourth
# (CVE-2026-56117) needs local access but is live here specifically because
# nixpkgs configures dhcpcd with --disable-privsep; see that patch's header.
#
# Each CVE maps 1:1 onto an upstream commit, so these are the upstream diffs
# vendored whole rather than split by hand (contrast ../libusb1, where one
# commit covered two CVEs). All four apply to 10.3.1 with hunk offsets only.

{ lib, dhcpcd }:

assert lib.assertMsg (dhcpcd.version == "10.3.1") ''
  patches/dhcpcd carries CVE-2026-5611{3,4,6,7} backports verified against
  dhcpcd 10.3.1, but nixpkgs now ships ${dhcpcd.version}. All four are fixed in
  upstream 10.3.2, so if this is 10.3.2 or newer just delete this directory.
'';

dhcpcd.overrideAttrs (old:
  let
    existing = map (p: baseNameOf (toString p)) (old.patches or [ ]);

    covered = patch: lib.any (name: lib.hasInfix (lib.removeSuffix ".patch" (baseNameOf patch)) name) existing;
  in
  {
    patches = (old.patches or [ ]) ++ lib.filter (p: !covered p) [
      ./CVE-2026-56113.patch # UAF, dhcp6_deprecateaddrs()   same-link  5.3
      ./CVE-2026-56114.patch # 1-byte OOB write, dhcp6_makemessage()    5.3
      ./CVE-2026-56116.patch # memory leak, routeinfo_findalloc()       4.7
      ./CVE-2026-56117.patch # UAF, control_recvdata()       local      6.5
    ];
  })
