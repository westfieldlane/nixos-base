{ lib, ... }: {
  services.avahi.enable = lib.mkForce false;
}
