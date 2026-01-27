{
  boot.tmp.useZram = true;
  boot.tmp.zramSettings = {
    fs-type = "ext4";
    options = "X-mount.mode=1777,rw,noatime,nosuid,nodev,noexec,discard";
    zram-size = "ram * 0.3";
    compression-algorithm = "zstd";
  };
}
