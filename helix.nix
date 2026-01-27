{ pkgs, ... }:
{
  environment.systemPackages = [ pkgs.evil-helix ];
  environment.variables.EDITOR = "hx";
}
