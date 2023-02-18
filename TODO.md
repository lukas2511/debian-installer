# Important

## check identity files

Make sure that no identifying files get left after installation.
E.g. machine-id, dhcpv6 duid, zfs identity?, hostname in weird places, etc.

## check network configuration

Something weird is still going on with DHCP for IPv4.. might be my test setup,
will need to check this in more depth.

# Nice-to-have

## dhcp in initramfs

Network configuration in initramfs currently doesn't support DHCP.

## more management tools

The ISO already contains some very useful tools, e.g. `ipmitool` which
allows to reconfigure e.g. networking for the IPMI from a running system.

Tools like `fwupd` or some common RAID/HBA controller tools would probably
be quite useful.

I'd like to keep the ISO lightweight, so it's hard to decide which tools to
include.
