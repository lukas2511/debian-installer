# Important

## check identity files

Make sure that no identifying files get left after installation.
E.g. machine-id, dhcpv6 duid, zfs identity?, hostname in weird places, etc.

## check network configuration

Something weird is still going on with DHCP for IPv4.. might be my test setup,
will need to check this in more depth.

## synchronize biosboot- and efi-partitions

During grub updates the biosboot- and efi-partitions need to be updated.

Since they are not synchronized in form of some raid they have to be
provisioned individually.

Proxmox has a script for this. If the license allows it maybe it could simply
be integrated.

# Nice-to-have

## more management tools

The ISO already contains some very useful tools, e.g. `ipmitool` which
allows to reconfigure e.g. networking for the IPMI from a running system.

Tools like `fwupd` or some common RAID/HBA controller tools would probably
be quite useful.

I'd like to keep the ISO lightweight, so it's hard to decide which tools to
include.

## dropbear + network config in initramfs

Using dropbear in initramfs it's possible to unlock encrypted partitions
over SSH.

Unfortunately the default scripts only allow very simplistic configurations.
No network bonds, no VLAN IDs, no IPv6, etc.

Ideally it would be possible to integrate ifupdown2 or something similar into
initramfs.
