# Security backports for libssh2 1.11.1.
#
# nixpkgs 26.05 ships libssh2 1.11.1 carrying backports for six CVEs, but not
# for these four. All are client-side -- a malicious *server* attacks the
# connecting client -- and three of the four land pre-authentication, so
# connecting at all is enough. Every machine that makes an SSH or SFTP client
# connection is exposed, which is every machine in the fleet.
#
# Patch filenames are the bare CVE ids on purpose. vulnix reads the
# derivation's `patches` attribute and suppresses any CVE whose id appears in a
# patch *filename*; it never reads patch contents. Naming them this way closes
# the findings in the next scan without a whitelist entry, and the suppression
# disappears on its own when a file does. A whitelist entry would outlive the
# patch and quietly hide a regression.
#
# The patches are vendored rather than fetched. `curl` links `libssh2`, so a
# fetchpatch/fetchurl here would give libssh2 -> patches -> fetch -> curl ->
# libssh2, an infinite recursion at eval time; nixpkgs ships its own libssh2
# CVE patches as in-tree files for the same reason. Two of the four also had to
# be rebased onto 1.11.1 and no longer match upstream byte-for-byte -- each
# patch header records its upstream commit and what changed.

{ lib, libssh2 }:

assert lib.assertMsg (libssh2.version == "1.11.1") ''
  patches/libssh2 carries CVE-2026-6603{2,3,4,5} backports written against
  libssh2 1.11.1, but nixpkgs now ships ${libssh2.version}. Check whether those
  four are fixed upstream; if so, delete this directory. If not, re-verify each
  patch still applies -- two are rebases against 1.11.1 source, and the macro
  renames they work around may have landed by now.
'';

libssh2.overrideAttrs (old: {
  patches = (old.patches or [ ]) ++ [
    ./CVE-2026-66032.patch # double free in sftp_open()             5e47761
    ./CVE-2026-66033.patch # OOB read/write, AES-GCM      pre-auth  a2ed82d
    ./CVE-2026-66034.patch # OOB read, publickey list     pre-auth  a13bb6c
    ./CVE-2026-66035.patch # heap overflow, ETM decrypt   pre-auth  42e33d8
  ];
})
