{
  # Capability modules: each declares an option interface and stays inert until
  # enabled. Importing this only *declares* the options; the SOE decides which
  # to turn on (see ../default.nix).
  imports = [
    ./vulnix.nix
  ];
}
