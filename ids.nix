{ lib, config, ... }:
let
  inherit (lib) types;

  uids = config.custom.ids.uids;
  gids = config.custom.ids.gids;


  # If a uid/gid is defined in this module, then enforce its use
  # Else, just use the configuration as defined
  assignUid = users: lib.mapAttrs
    (name: userCfg:
      if uids ? ${name} then
        userCfg // { uid = uids.${name}; }
      else
        userCfg
    )
    users;

  assignGid = users: lib.mapAttrs
    (name: userCfg:
      if gids ? ${name} then
        userCfg // { gid = gids.${name}; }
      else
        userCfg
    )
    users;
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
      };

      gids = {
        jellyfin = 992;
        cwa = 35000;
      };
    };

    # Make it so users don't have to manually assign their ids from this
    # module. It's done for them.
    # 
    # NOTE: Since all user ids should be managed here, any user that isn't will
    # throw an error.
    users.users = lib.mkIf (config.users.users != { }) (
      assignUid config.users.users
    );

    users.groups = lib.mkIf (config.users.users != { }) (
      assignGid config.users.groups
    );
  };
}
