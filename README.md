# Custom Debian Installer

Custom debian installer with ZFS support and some advanced network
configuration capabilities.

Mainly written for my personal use, but I don't see any reason not to
make it public.

The installer shows a wizard on tty1 on start but also allows for automatic
installations (see infos below).

[Download ISO](https://git.fslab.de/lschau2s/debian-zfs-installer/-/jobs/artifacts/potato/raw/debian-custom.iso?job=build) (Built directly from potato branch)

# Warning

**There is basically no input validation.**

Your entries might get written to config files or used in shell commands without any sanity check.

# Boot environment

The ISO boots on both BIOS and UEFI systems and the installed system will behave the same.

In raid configurations the boot partition will be mirrored accross all disks while the
bios- and efi-boot partitions are kept separately for each disk.  

Keeping those partitions separately allows for clean compatibility with weird UEFI implementations
that write to the efi disk on boot (I think Dell does this? probably others as well).

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

# Automatic installation

The installer checks for a partition labeled `INSTALL_CFG`, looking for three
specific files (all of them optional):

- `prepare.sh`: Runs first. Allows to e.g. acquire and configure a list of disks to install to
- `config.json`: Will be simply copied to `/tmp/config.json` (which the installer reads from)
- `install.py`: Updated version of the install script. Replaces the original installer completely, allowing to repurpose the live system for other use cases.

The partition gets mounted and unmounted before running the installer script,  
that should allow the dual-use of the new system disk as temporary config device.

For installations of servers etc you could use a second USB stick with the configuration on it.

# config.json

## Installer settings

```
{
    # remove unnecessary packages after installation (e.g. cryptsetup packages on an unencrypted setup)
    "purge_unnecessary": true,
    # do not ask questions for already configured settings (usefull for automatic installation)
    "skip_configured": true,
    # don't ask for confirmation, automatically starts installation of all settings have been configured
    "automatic_install": true,
    # shutdown after installation
    "shutdown": false,
}
```

## Basic information

```
{
    # fully qualified domain name (combined host + domain) of system
    "fqdn": "debian.lan",
    # timezone
    "timezone": "Europe/Berlin",
}
```

# Filesystem configuration

```
{
    # filesystem type (zfs/ext4/ext4lvm/xfs/xfslvm)
    "filesystem_type": "zfs",
    # list of devices as seen in /dev/disk/by-id
    "filesystem_devices": [
        "ata-QEMU_HARDDISK_QM00001",
        "ata-QEMU_HARDDISK_QM00002"
    ],
    # encryption passphrase (leave empty to disable encryption)
    "filesystem_encpasswd": "test1234",
    # raid level (number as string again.. i know.. it's weird..)
    # zfs: 0: striped, 1: mirror, 5: raidz, 6: raidz2, 7: raidz3
    # other: 0: striped, 1: mirror, 5: raid5, 6: raid6, 7: not defined
    "filesystem_raidlevel": "1",
    # zfs-only: use zfs native encryption instead of luks
    "filesystem_enczfsnative": true
}
```

## Network configuration
```
{
    # list of network interfaces (selecting multiple requires the definition of a bond type)
    "network_interfaces": ["ens3"],
    # bond type/mode (number, but as string.. because of reasons.)
    # {"0": "balance-rr", "1": "active-backup", "2": "balance-xor", "3": "broadcast", "4": "802.3ad", "5": "balance-tlb", "6": "balance-alb"}
    "network_bond_type": null,
    # define name of network bridge (or leave empty if you don't want to create one)
    "network_bridge": "",
    # tagged vlan id (leave empty for untagged operation)
    "network_vlan": "",
    # IPv6 address including Subnet in slash notation (leave empty for automatic slaac configuration, disabling IPv6 is not an option)
    "network_ip6": "",
    # IPv6 gateway (leave empty for automatic configuration)
    "network_gw6": "",
    # IPv4 address (leave empty for dhcp, or set to "disable" to not configure IPv4)
    "network_ip4": "10.0.2.15/24",
    # IPv4 gateway (required if static ipv4 address is set, otherwise will use DHCP as well)
    "network_gw4": "10.0.2.2",
    # list of dns servers (default set: cloudflare)
    "network_dns": [
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "1.1.1.1",
        "1.0.0.1"
    ],
}
```

## User configuration

```
{
    # root info
    "root_password": "test1234",
    "root_pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7W3NIGeEGRHu63+dP7s6M5/s0uHODI4QV2Y1yOzDEq lukas2511",
    # user info (leave name empty to disable creation of an unprivileged user)
    "user_name": "",
    "user_password": "test1234",
    "user_pubkey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7W3NIGeEGRHu63+dP7s6M5/s0uHODI4QV2Y1yOzDEq lukas2511",
}
```
