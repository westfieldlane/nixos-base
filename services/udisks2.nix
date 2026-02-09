{ lib, ... }: {
  services.udisks2.enable = lib.mkForce false;
}
