{ lib, ... }:

{
  time.timeZone = lib.mkDefault "UTC";
  i18n.defaultLocale = lib.mkDefault "en_AU.UTF-8";
}
