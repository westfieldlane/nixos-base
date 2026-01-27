{ lib, ... }:

{
  time.timeZone = lib.mkDefault "Australia/Perth";
  i18n.defaultLocale = lib.mkDefault "en_US.UTF-8";
}
