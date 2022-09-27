# Custom Debian Installer

Custom debian installer with ZFS support and some advanced network
configuration capabilities.

Mainly written for my personal use, but I don't see any reason not to
make it public.

**Warning**: There is basically no input validation.  
Your entries might get written to config files or used in shell commands without any sanity check.

[Download ISO](https://git.fslab.de/lschau2s/debian-zfs-installer/-/jobs/artifacts/potato/raw/debian-custom.iso?job=build) (Built directly from potato branch)

# Supported Filesystems

- ZFS
- XFS (Standalone or on LVM)
- EXT4 (Standalone or on LVM)

The installer allows selecting multiple disks to set up a RAID (mdraid for lvm/ext4/xfs, native raid for ZFS)

All filesystems can also be encrypted using LUKS disk encryption.  
For ZFS it's also possible to select native encryption instead.

# Networking features

- bond: Multiple interfaces can be configured as bond
- bridge: Interface or bond can be attached to a bridge (avoids manual re-configuration after install)
- vlan: A VLAN ID can be selected to allow for tagged management networks
- dual stack: Both IPv6 and legacy IPv4 addreses can be separately configured
- manual dns servers: DNS configuration will always be configured manually since I simply dislike automatic DNS server detection

During gateway configuration the gateway does not have to be in the same subnet as the configured IP.  
ifupdown2 handles this perfectly well, allowing for e.g. routes through link-local addresses.
