# This will create enough of a bare-bones scaffolding to be able to do some local testing before pushing configs
# Example: `nixos-rebuild repl -I nixos-config=./host.nix`
{
  imports = [ ../default.nix ];

  fileSystems."/" = {
    device = "/dev/null";
    fsType = "ext4";
  };

  boot.loader.grub = {
    enable = true;
    device = "nodev";
  };

  # Pins the stateVersion so the build does not emit the "defaulting to" warning
  # on every run and drown real output.
  system.stateVersion = "26.05";
}
