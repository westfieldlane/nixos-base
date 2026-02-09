{ lib, ... }: {
  services.geoclue2.enable = lib.mkForce false;
}
