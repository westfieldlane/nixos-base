{ lib, ... }:
let
  inherit (lib) types;
in
{
  options = {
    # This is adapted from:
    # https://github.com/nixos/nixpkgs/blob/master/nixos/modules/misc/ids.nix
    custom.ids.uids = lib.mkOption {
      internal = true;
      description = ''
        The user IDs used in Westfieldlane
      '';
      type = types.attrsOf types.ints.u32;
    };

    custom.ids.gids = lib.mkOption {
      internal = true;
      description = ''
        The group IDs used in Westfieldlane
      '';
      type = types.attrsOf types.ints.u32;
    };
  };
  config = {
    custom.ids = {
      uids = {
        jellyfin = 994;
        imhotep = 1000;
        cwa = 35000;
        immich = 35001;
        nextcloud = 35002;
      };

      gids = {
        jellyfin = 992;
        cwa = 35000;
        immich = 35001;
        nextcloud = 35002;
      };
    };
  };
}
