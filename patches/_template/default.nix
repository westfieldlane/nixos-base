# TEMPLATE -- copy this directory to patches/<nixpkgs-attribute>/ and edit.
#
# The leading underscore keeps ../overlay.nix from evaluating this as a package;
# see the isPackage filter there. Nothing in here is built.
#
# ---------------------------------------------------------------------------
# Checklist for a new patch directory
# ---------------------------------------------------------------------------
#
# 1. Name the directory after the NIXPKGS ATTRIBUTE, not the pname vulnix
#    prints. vulnix says "libusb", the attribute is `libusb1`, and the overlay
#    resolves `prev.<dirname>` -- a mismatch fails with a confusing
#    "attribute missing" rather than anything about patches.
#    Check with: nix-instantiate --eval -E '(import <nixpkgs> {}).<attr>.version'
#
# 2. Confirm nixpkgs has not already fixed it. It backports WITHOUT bumping
#    versions, so the version number tells you nothing:
#      nix-instantiate --eval --strict -E \
#        'map (p: baseNameOf (toString p)) (import <nixpkgs> {}).<attr>.patches'
#    If a CVE id already appears there, you have nothing to do.
#
# 3. Find the real upstream fix and confirm the CVE -> commit mapping against a
#    second source (Debian's security tracker is good:
#    https://security-tracker.debian.org/tracker/CVE-YYYY-NNNNN). Never write
#    the patch yourself off a CVE description alone.
#
# 4. One CVE per file, named exactly CVE-YYYY-NNNNN.patch. vulnix suppresses a
#    finding when its id appears in a patch FILENAME -- it never reads contents.
#    That is what closes the finding without a whitelist entry, and it unwinds
#    on its own when the file goes away. If one upstream commit fixes several
#    CVEs, split it (see ../libusb1); if the mapping is 1:1, vendor the commit
#    diff whole (see ../dhcpcd).
#
# 5. Vendor the .patch file. Do not use fetchpatch/fetchurl: anything in the
#    fetch path pulls in curl, and if the package you are patching is in curl's
#    own dependency closure you get infinite recursion at eval time. Vendoring
#    also means the patch is reviewable in the diff.
#
# 6. Head each .patch with provenance: upstream commit, released-in version,
#    where you confirmed the mapping, what the attacker needs, and -- if you
#    rebased -- exactly what you changed and why.
#
# 7. Verify it applies before trusting it:
#      SRC=$(nix-build '<nixpkgs>' -A <attr>.src --no-out-link)
#      cp -r "$SRC" /tmp/src && chmod -R u+w /tmp/src
#      cd /tmp/src && patch -p1 --dry-run < .../CVE-YYYY-NNNNN.patch
#    Then build it for real: ../../check.sh <attr>
#
# 8. Delete the directory once nixpkgs catches up. The assert below tells you
#    when, and the covered filter keeps the build green in the meantime.

{ lib, PACKAGE }:

# Guards a version bump: patches verified against one source tree are not
# automatically valid against the next. The filter below handles the other
# case -- nixpkgs backporting the fix without changing the version.
assert lib.assertMsg (PACKAGE.version == "VERSION") ''
  patches/PACKAGE carries CVE-YYYY-NNNNN backports verified against
  PACKAGE VERSION, but nixpkgs now ships ''${PACKAGE.version}. Check whether
  these are fixed upstream; if so, delete this directory. If not, re-verify
  each patch still applies against the new source.
'';

PACKAGE.overrideAttrs (old:
  let
    existing = map (p: baseNameOf (toString p)) (old.patches or [ ]);

    # nixpkgs names its backports <hash>-CVE-YYYY-NNNNN.patch, so an infix
    # match on the bare id catches them. Applying a patch nixpkgs already
    # carries is not a warning -- "Reversed (or previously applied) patch
    # detected" fails the build outright.
    covered = patch: lib.any (name: lib.hasInfix (lib.removeSuffix ".patch" (baseNameOf patch)) name) existing;
  in
  {
    patches = (old.patches or [ ]) ++ lib.filter (p: !covered p) [
      ./CVE-YYYY-NNNNN.patch # one-line: bug class, function, vector, score
    ];
  })
