#!/usr/bin/env python3

import os
import json
import dialog
import glob
import re
import sys
import time
import subprocess
import shutil
import urllib.request

diag = dialog.Dialog(dialog="dialog")

CONFIG_FILE = "/tmp/config.json"
CONFIG = {}

BOND_MODES = {"0": "balance-rr", "1": "active-backup", "2": "balance-xor", "3": "broadcast", "4": "802.3ad", "5": "balance-tlb", "6": "balance-alb"}

def load_config():
    CONFIG.update(json.load(open(CONFIG_FILE)))

def save_config():
    open(CONFIG_FILE, "w").write(json.dumps(CONFIG, indent=4))

def get_textvalue(option, title, question="", default="", allow_empty=True, store_func=None, load_func=None):
    if option in CONFIG and "skip_configured" in CONFIG and CONFIG["skip_configured"]: return
    repeatreason = ""
    if option in CONFIG:
        if load_func:
            initval = load_func(CONFIG[option])
        else:
            initval = CONFIG[option]
    else:
        initval = default
    while True:
        try:
            retstate, retval = diag.inputbox(question + repeatreason, init=initval, width=54, title=title)
            if retstate != "ok":
                exit(0)
            if not allow_empty and not retval:
                repeatreason = "\n\nPlease try again, this value is not optional."
            else:
                break
        except:
            exit(0)

    if store_func:
        CONFIG[option] = store_func(retval)
    else:
        CONFIG[option] = retval
    save_config()

def get_yesno(option, title, question, default):
    if option in CONFIG and "skip_configured" in CONFIG and CONFIG["skip_configured"]: return
    try:
        retval = True if diag.yesno(question, title=title, defaultno=(not CONFIG[option]) if option in CONFIG else (not default)) == "ok" else False
    except:
        exit(0)
    CONFIG[option] = retval
    save_config()

def get_choice(option, title, question, choices, default=None):
    if option in CONFIG and "skip_configured" in CONFIG and CONFIG["skip_configured"]: return
    selected = CONFIG[option] if option in CONFIG else default

    menu_choices = []
    if isinstance(choices, list):
        for choice in choices:
            menu_choices.append((choice, choice))
    else:
        for choice_key, choice_value in choices.items():
            menu_choices.append((choice_key, choice_value))
    try:
        retstate, selected = diag.menu(question, choices=menu_choices, default_item=selected if selected is not None else menu_choices[0][0], title=title)
    except:
        exit(0)
    if retstate == "cancel":
        exit(0)

    CONFIG[option] = selected
    save_config()

def get_multichoice(option, title, question, choices, default=[], min_choices=1):
    if option in CONFIG and "skip_configured" in CONFIG and CONFIG["skip_configured"]: return
    selected = CONFIG[option] if option in CONFIG else default

    while True:
        check_choices = []
        if isinstance(choices, list):
            for choice in choices:
                check_choices.append((choice, choice, choice in selected))
        else:
            for choice_key, choice_value in choices.items():
                check_choices.append((choice_key, choice_value, choice_key in selected))
        try:
            retstate, selected = diag.checklist(question, choices=check_choices, width=0, height=0, title=title)
            if len(selected) >= min_choices: break
        except:
            exit(0)
        if retstate == "cancel":
            exit(0)
    CONFIG[option] = selected
    save_config()

def get_password(option, title, subject, default="", allow_empty=False, minlength=8):
    if option in CONFIG and "skip_configured" in CONFIG and CONFIG["skip_configured"]: return
    password = CONFIG[option] if option in CONFIG else default

    repeatreason = ""
    while True:
        try:
            retstate, retval1 = diag.passwordbox(f"Enter password for {subject} (min. %d characters){repeatreason}" % minlength, title=title, insecure=True, init=password)
            if retstate == "cancel":
                exit(0)
            if retval1 and len(retval1) >= minlength:
                if retval1 == password:
                    retval2 = retval1
                else:
                    retstate, retval2 = diag.passwordbox(f"Repeat password entry for {subject}", title=title, insecure=True)
                    if retstate == "cancel":
                        exit(0)
            elif allow_empty:
                retval2 = retval1
        except:
            exit(0)

        if retval1 and len(retval1) < minlength:
            repeatreason = "\n\nPlease try again, password needs to be at least %d characters long." % minlength
        elif not retval1 and not allow_empty:
            repeatreason = "\n\nPlease try again, password was empty."
        elif retval1 != retval2:
            repeatreason = "\n\nPlease try again, passwords didn't match."
        else:
            break

    CONFIG[option] = retval1
    save_config()

def list_netifaces():
    ifaces = {}
    tmp_ifaces = []
    for path in sorted(glob.glob("/sys/class/net/*")):
        iface = os.path.basename(path)
        if iface == "bonding_masters": continue

        realpath = os.readlink(path)
        if '/virtual/' in realpath: continue

        if iface == "lo":
            continue

        subprocess.call(["ip", "link", "set", "up", "dev", iface])
        tmp_ifaces.append((iface, path))

    time.sleep(5)

    for (iface, path) in tmp_ifaces:
        hwaddr = open(path + "/address").read().strip()
        state = open(path + "/operstate").read().strip()
        if state == "up":
            speed = int(open(path + "/speed").read().strip())
            if speed < 1000:
                state = "up: %dM" % speed
            else:
                state = "up: %dG" % (speed/1000)

        ifaces[iface] = "%s (%s)" % (hwaddr, state)
    return ifaces

def list_blockdevices():
    devices = {}
    for path in sorted(glob.glob("/dev/disk/by-id/*")):
        device = os.path.basename(path)
        blockdev = os.path.basename(os.readlink(path))

        if re.search("(^(nvme-eui|wwn))|(-part[0-9]$)", device): continue
        if blockdev.startswith("dm"): continue

        size = int(open("/sys/block/" + blockdev + "/size", "r").read()) / 1024 / 1024 / 1024 * 512
        if size < 5:
            continue

        devices[device] = "%.2f GB" % size
    return devices

def get_config():
    diag.set_background_title("Custom Debian Installer")

    if os.path.exists(CONFIG_FILE):
        load_config()

    overview = ""

    # Basic info
    overview += "# Basic information\n"
    get_textvalue("fqdn", "Hostname + Domain", "Enter fqdn for new system", "debian.lan")
    overview += "FQDN: %s\n" % CONFIG["fqdn"]
    get_textvalue("timezone", "Timezone", "Select timezone", "Europe/Berlin")
    overview += "Timezone: %s\n" % CONFIG["timezone"]

    # Filesystem info
    overview += "\n# Filesystem information\n"
    filesystem_types = {"zfs": "ZFS", "ext4": "ext4", "ext4lvm": "ext4 on LVM", "xfs": "XFS", "xfslvm": "XFS on LVM"}
    get_choice("filesystem_type", "Filesystem", "Select filesystem type", filesystem_types, "zfs")
    overview += "Type: %s\n" % filesystem_types[CONFIG["filesystem_type"]]
    get_multichoice("filesystem_devices", "Select devices", "Select devices to install to.\nSelecting multiple devices allows for various raid configurations.", list_blockdevices())
    overview += "Device(s):\n"
    for device in CONFIG["filesystem_devices"]:
        overview += " - %s\n" % device
    if len(CONFIG["filesystem_devices"]) > 1:
        fs = CONFIG["filesystem_type"]
        raid_levels = {"0": "Striped", "1": "Mirrored"}
        raid_default = "1"
        if len(CONFIG["filesystem_devices"]) > 2:
            raid_levels["5"] = "RAID-Z" if fs == "zfs" else "RAID 5"
            raid_default = "5"
        if len(CONFIG["filesystem_devices"]) > 3:
            raid_levels["6"] = "RAID-Z" if fs == "zfs" else "RAID 6"
        if len(CONFIG["filesystem_devices"]) > 4 and fs == "zfs":
            raid_levels["7"] = "RAID-Z3"
        get_choice("filesystem_raidlevel", "RAID level", "You selected multiple devices.\nPlease select RAID level.\n", raid_levels, raid_default)
        overview += "RAID-Level: %s\n" % raid_levels[CONFIG["filesystem_raidlevel"]]
    else:
        CONFIG["filesystem_raidtype"] = None

    get_password("filesystem_encpasswd", "Encryption passphrase", "disk encryption\n\nLeave empty to disable.", allow_empty=True)
    overview += "Encryption: %s\n" % ("Enabled" if CONFIG["filesystem_encpasswd"] else "Disabled")
    if CONFIG["filesystem_encpasswd"]:
        get_yesno("dropbear", "Dropbear", "Enable dropbear SSH server in initramfs?", True)
    else:
        CONFIG["dropbear"] = False
    if CONFIG["filesystem_encpasswd"] and CONFIG["filesystem_type"] == "zfs":
        get_yesno("filesystem_enczfsnative", "ZFS native encryption", "Use ZFS native encryption instead of LUKS?", False)
        overview += "Encryption type: %s\n" % ("ZFS-native" if CONFIG["filesystem_enczfsnative"] else "LUKS")
    else:
        CONFIG["filesystem_enczfsnative"] = None

    # Network info
    overview += "\n# Network information\n"
    get_multichoice("network_interfaces", "Network interfaces", "Select network interface(s)\n\nMultiple selected interfaces will be configured as bond.", list_netifaces())
    overview += "Device(s): %s\n" % (", ".join(CONFIG["network_interfaces"]))
    if len(CONFIG["network_interfaces"]) > 1:
        get_choice("network_bond_type", "Network bonding", "Select type of network bond", BOND_MODES)
        overview += "Bond-Type: %s\n" % BOND_MODES[CONFIG["network_bond_type"]]
    else:
        CONFIG["network_bond_type"] = None
    get_textvalue("network_bridge", "Bridge name", "Create network bridge?\nEnter name for bridge device or leave empty to disable bridging.")
    if CONFIG["network_bridge"]:
        overview += "Bridge: %s\n" % CONFIG["network_bridge"]
    else:
        overview += "No Bridge configured\n"
    get_textvalue("network_vlan", "Tagged VLAN", "Use tagged VLAN?\nEnter VLAN id or leave empty for normal untagged operation.")
    if CONFIG["network_vlan"]:
        overview += "VLAN: %s\n" % CONFIG["network_vlan"]
    else:
        overview += "No VLAN configured\n"
    get_textvalue("network_ip6", "IPv6 address", "Enter IPv6 address (including subnet with slash-notation)\n\nLeave empty for automatic configuration.\nDisabling IPv6 is not an option.\n")
    if CONFIG["network_ip6"]:
        get_textvalue("network_gw6", "IPv6 gateway", "Enter IPv6 gateway\n\nLeave empty for automatic configuration.")
    else:
        CONFIG["network_gw6"] = ""
    overview += "IPv6 address: %s\n" % (CONFIG["network_ip6"] if CONFIG["network_ip6"] else "SLAAC")
    overview += "IPv6 gateway: %s\n" % (CONFIG["network_gw6"] if CONFIG["network_gw6"] else "SLAAC")

    get_textvalue("network_ip4", "IPv4 address", "Enter IPv4 address (including subnet with slash-notation)\n\nLeave empty for DHCP.\nEnter 'disable' to disable IPv4.")
    if CONFIG["network_ip4"] != "disable":
        if CONFIG["network_ip4"]:
            get_textvalue("network_gw4", "IPv4 gateway", "Enter IPv4 gateway", allow_empty=False)
            overview += "IPv4 gateway: %s\n" % (CONFIG["network_gw4"] if CONFIG["network_gw4"] else "DHCP")
        else:
            CONFIG["network_gw4"] = ""
            overview += "IPv4 gateway: DHCP\n"
    else:
        CONFIG["network_gw4"] = ""
    overview += "IPv4 address: %s\n" % (CONFIG["network_ip4"] if CONFIG["network_ip4"] else "DHCP")

    get_textvalue("network_dns", "DNS server(s)", "Enter DNS servers (separated by single spaces)\n\nDefaults to CloudFlare-DNS.", "2606:4700:4700::1111 2606:4700:4700::1001 1.1.1.1 1.0.0.1", store_func=lambda x: x.split(), load_func=lambda x: " ".join(x))
    overview += "DNS servers:\n"
    for dns in CONFIG["network_dns"]:
        overview += " - %s\n" % dns

    # User info
    overview += "\n# User information\n"
    get_password("root_password", "Root password", "user root")
    get_textvalue("root_pubkey", "SSH keys", "Enter SSH authorized key for user root (optional)\n\nYou can also enter a GitHub username using github:username (only works after manually configuring network, previous settings don't apply here).")
    if CONFIG["root_pubkey"]:
        if CONFIG["root_pubkey"].startswith("github:"):
            CONFIG["root_pubkey"] = urllib.request.urlopen("https://github.com/%s.keys" % (CONFIG["root_pubkey"][7:])).read().decode()
            save_config()
        overview += "SSH authorized key for root was configured\n"
    else:
        overview += "SSH authorized key for root was NOT configured\n"

    get_textvalue("user_name", "Unprivileged user", "Enter username for unprivileged user.\n\nLeave empty to disable.")
    if CONFIG["user_name"]:
        overview += "Unprivileged user %s will be created\n" % CONFIG["user_name"]
        get_password("user_password", "User password", "user %s" % CONFIG["user_name"])
        get_textvalue("user_pubkey", "SSH keys", "Enter SSH authorized key for user %s (optional)\n\nYou can also enter a GitHub username using github:username (only works after manually configuring network, previous settings don't apply here)." % CONFIG["user_name"])

        if CONFIG["user_pubkey"]:
            if CONFIG["user_pubkey"].startswith("github:"):
                CONFIG["user_pubkey"] = urllib.request.urlopen("https://github.com/%s.keys" % (CONFIG["user_pubkey"][7:])).read().decode()
                save_config()
            overview += "SSH authorized key for %s was configured\n" % CONFIG["user_name"]
        else:
            overview += "SSH authorized key for %s was NOT configured\n" % CONFIG["user_name"]
    else:
        overview += "No unprivileged user will be created\n"

    get_yesno("purge_unnecessary", "Cleanup", "Purge unnecessary packages from installation?", False)

    return overview

def luks_encrypt(partition, passphrase, name):
    proc = subprocess.Popen(["cryptsetup", "-q", "luksFormat", partition], stdin=subprocess.PIPE)
    proc.communicate(input=(passphrase+"\n").encode())
    proc = subprocess.Popen(["cryptsetup", "luksOpen", partition, name], stdin=subprocess.PIPE)
    proc.communicate(input=(passphrase+"\n").encode())


def main():
    if not os.path.exists("/mnt/etc/os-release"):
        cleanup_devices()

    # stuff
    CONFIG["skip_configured"] = True
    CONFIG["automatic_install"] = False

    # user input
    overview = get_config()

    if "automatic_install" not in CONFIG or not CONFIG["automatic_install"]:
        diag.msgbox(overview, title="Overview", ok_label="Install", width=0, height=0)
    else:
        print(overview)
        sys.stdout.write("Installation starting in 10 seconds")
        sys.stdout.flush()
        for i in range(10):
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(1)
        print("")

    if not os.path.exists("/mnt/etc/os-release"):
        prepare_disks()
    install_debian()

    readme = "# General\n"
    readme += "This OS has been installed from lukas2511 custom debian installer\n"
    readme += "\n"
    readme += "# Boot partitions\n"
    readme += "On systems with multiple disks the EFI and BIOS-Boot partitions are not automatically synced.\n"
    readme += "An automated script re-installs grub on all those partitions after a kernel or grub update.\n"
    readme += "In case of disks replacements the partition UUIDs in `/etc/kernel/efi-boot-uuids` might need\n"
    readme += "to be updated and `/etc/kernel/postinst.d/zz-update-grub-raid` has to be run manually.\n"
    readme += "\n"
    readme += "# Dropbear in initramfs\n"
    readme += "For encrypted systems with enabled dropbear support the installer creates initramfs scripts\n"
    readme += "for network configuration.\n"
    readme += "These scripts are located in `/etc/initramfs-tools/scripts/local-{top,bottom}/network` and\n"
    readme += "will need to be updated if your network configuration changes.\n"
    readme += "\n"
    readme += "# Configuration overview\n"
    readme += "In the following sections you'll find an overview of options given during installation.\n"
    readme += "\n"
    readme += overview
    open("/mnt/root/README.txt", "w").write(overview)

def cleanup_devices():
    # unmount filesystems
    unmount = []
    for line in open("/proc/mounts").read().splitlines():
        dev, path, fstype, options, _, _ = line.split()
        if path == "/": continue
        if path.split("/")[1] in ["sys", "proc", "dev", "usr", "run", "tmp"]: continue
        if fstype != "zfs":
            unmount.append(path)
    for path in sorted(unmount, reverse=True):
        subprocess.call(["umount", path])
        time.sleep(1)

    # export zfs pools
    for pool in subprocess.check_output(["zpool", "list", "-H", "-o", "name"]).decode().splitlines():
        subprocess.call(["zpool", "export", pool])
        time.sleep(1)

    # stop LVMs
    subprocess.call(["vgchange", "-an"])
    if glob.glob("/sys/class/block/dm-*"):
        time.sleep(1)
        for dm in glob.glob("/sys/class/block/dm-*"):
            subprocess.call(["cryptsetup", "luksClose", "/dev/" + os.path.basename(dm)])
            time.sleep(2)

    if glob.glob("/sys/class/block/dm-*"):
        raise Exception("Some devicemapper virtual devices are still active. Please clean up before running installer.")

    # stop RAIDs
    for path in glob.glob("/sys/class/block/md*"):
        subprocess.call(["mdadm", "--stop", os.path.basename(path)])
        time.sleep(2)
    if glob.glob("/sys/class/block/md*"):
        raise Exception("Some mdraid devices are still active. Please clean up before running installer.")

def prepare_disks():
    # wipe and partition disks
    for disk in CONFIG["filesystem_devices"]:
        for part in glob.glob("/dev/disk/by-id/" + disk + "-part*"):
            subprocess.call(["wipefs", "--quiet", "--all", part])
        subprocess.call(["wipefs", "--quiet", "--all", "/dev/disk/by-id/" + disk])
    subprocess.call(["partprobe", "/dev/disk/by-id/" + disk])

    gdisk_cmds = "o\nY\n" # create new gpt layout
    gdisk_cmds += "n\n1\n\n+64M\nef02\n" # bios boot partition
    gdisk_cmds += "n\n2\n\n+128M\nef00\n" # efi partition
    gdisk_cmds += "n\n3\n\n+512M\n8300\n" # boot partition
    gdisk_cmds += "n\n4\n\n\n8300\nw\nY\n" # main partition

    for disk in CONFIG["filesystem_devices"]:
        path = "/dev/disk/by-id/" + disk
        proc = subprocess.Popen(["gdisk", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        proc.communicate(input=gdisk_cmds.encode())

        subprocess.call(["partprobe", path])
        time.sleep(2)
        if not os.path.exists(path + "-part4"):
            raise Exception("Partitioning went wrong.. this should not happen :(")

        for part in ["1", "2", "3", "4"]:
            subprocess.call(["wipefs", "--quiet", "--all", "/dev/disk/by-id/" + disk + "-part" + part])

        subprocess.call(["mkfs.vfat", path + "-part2"])

    if len(CONFIG["filesystem_devices"]) == 1:
        disk_path = "/dev/disk/by-id/" + CONFIG["filesystem_devices"][0]

        boot_part = disk_path + "-part3"
        subprocess.call(["mkfs.ext4", boot_part])

        real_root_part = disk_path + "-part4"
        root_part = real_root_part
    else:
        partitions = [("/dev/disk/by-id/" + disk + "-part3") for disk in CONFIG["filesystem_devices"]]
        subprocess.call(["mdadm", "--create", "/dev/md0", "--metadata=0.90", "--level=1", "--raid-devices=%d" % len(partitions)] + partitions)
        subprocess.call(["mkfs.ext4", "/dev/md0"])
        boot_part = "/dev/md0"

        if CONFIG["filesystem_type"] != "zfs":
            partitions = [("/dev/disk/by-id/" + disk + "-part4") for disk in CONFIG["filesystem_devices"]]
            subprocess.call(["mdadm", "--create", "/dev/md1", "--metadata=1.2", "--level=%s" % CONFIG["filesystem_raidlevel"], "--raid-devices=%d" % len(partitions)] + partitions)
            real_root_part = "/dev/md1"
            root_part = real_root_part

    if CONFIG["filesystem_type"] == "zfs":
        root_disks = [("/dev/disk/by-id/" + disk + "-part4") for disk in CONFIG["filesystem_devices"]]
        ashift = ["-o", "ashift=12"]
        if "/nvme-" in ("".join(root_disks)):
            ashift = ["-o", "ashift=13"]
        if CONFIG["filesystem_encpasswd"] and not CONFIG["filesystem_enczfsnative"]:
            encrypted_disks = []
            for disk in root_disks:
                luks_encrypt(disk, CONFIG["filesystem_encpasswd"], os.path.basename(disk))
                encrypted_disks.append("/dev/mapper/" + os.path.basename(disk))
            root_disks = encrypted_disks
        zpool_command = ["zpool", "create", "-R", "/mnt", "-O", "mountpoint=none"] + ashift
        if CONFIG["filesystem_encpasswd"] and CONFIG["filesystem_enczfsnative"]:
            zpool_command += ["-O", "encryption=on", "-O", "keylocation=prompt", "-O", "keyformat=passphrase"]
        zpool_command += ["zroot"]
        if len(root_disks) > 1 and CONFIG["filesystem_raidlevel"] != "0":
            raid_levels = {"1": "mirror", "5": "raidz", "6": "raidz2", "7": "raidz3"}
            zpool_command += [raid_levels[CONFIG["filesystem_raidlevel"]]]
        zpool_command += root_disks

        proc = subprocess.Popen(zpool_command, stdin=subprocess.PIPE)
        if CONFIG["filesystem_encpasswd"] and CONFIG["filesystem_enczfsnative"]:
            proc.communicate(input=(CONFIG["filesystem_encpasswd"] + "\n" + CONFIG["filesystem_encpasswd"] + "\n").encode())
        else:
            proc.communicate()

        subprocess.call(["zfs", "create", "zroot/ROOT"])
        subprocess.call(["zfs", "create", "-o", "mountpoint=/", "zroot/ROOT/debian"])
        subprocess.call(["zfs", "create", "-o", "mountpoint=/home", "zroot/home"])
        subprocess.call(["zfs", "create", "-o", "mountpoint=/root", "zroot/home/root"])
        subprocess.call(["zfs", "create", "zroot/var"])
        subprocess.call(["zfs", "create", "-o", "mountpoint=/var/lib", "zroot/var/lib"])
        subprocess.call(["zfs", "create", "-o", "mountpoint=/var/log", "zroot/var/log"])
        subprocess.call(["zfs", "create", "-o", "mountpoint=/var/cache", "zroot/var/cache"])
        subprocess.call(["zpool", "set", "bootfs=zroot/ROOT/debian", "zroot"])
    else:
        if CONFIG["filesystem_encpasswd"]:
            luks_encrypt(real_root_part, CONFIG["filesystem_encpasswd"], "root-crypt")
            root_part = "/dev/mapper/root-crypt"

        if CONFIG["filesystem_type"] in ["xfslvm", "ext4lvm"]:
            subprocess.call(["pvcreate", root_part])
            subprocess.call(["vgcreate", "vg0", root_part])
            subprocess.call(["lvcreate", "-L", "20G", "-n", "root", "vg0"])
            root_part = "/dev/vg0/root"
            subprocess.call(["mkfs.%s" % (CONFIG["filesystem_type"][:-3]), root_part])
        else:
            subprocess.call(["mkfs.%s" % CONFIG["filesystem_type"], root_part])

        subprocess.call(["mount", root_part, "/mnt"])

    os.mkdir("/mnt/boot")
    subprocess.call(["mount", boot_part, "/mnt/boot"])
    os.mkdir("/mnt/boot/efi")

def install_debian():
    # rsync live os to disk
    print("# Installing OS")
    exclude_dirs = ["/dev", "/proc", "/run", "/sys", "/tmp", "/mnt", "/root", "/home"]
    exclude_files = ["/etc/machine-id", "/etc/systemd/system/getty@tty1.service.d", "/lib/live"]
    for alg in ["ecdsa", "ed25519", "rsa", "dsa"]:
        exclude_files += [f"/etc/ssh/ssh_host_{alg}_key"]
        exclude_files += [f"/etc/ssh/ssh_host_{alg}_key.pub"]
    exclude_files += glob.glob("/boot/initrd*")
    rsync = ["rsync", "--archive", "--numeric-ids", "--links", "--delete", "--one-file-system"]
    for path in exclude_dirs + exclude_files:
        rsync += ["--exclude", path]
    rsync += ["/", "/mnt/"]
    subprocess.call(rsync)
    for path in exclude_dirs:
        if not os.path.exists("/mnt" + path):
            os.mkdir("/mnt" + path)

    # mount system directories to chroot
    print("# Mounting system directories")
    if not os.path.exists("/mnt/dev/disk"):
        for path in ["/dev", "/dev/pts", "/proc", "/sys"]:
            subprocess.call(["mount", "--bind", path, "/mnt" + path])

    # /etc/machine-id
    print("# Generating machine-id")
    if not os.path.exists("/mnt/etc/machine-id"):
        machine_id = subprocess.check_output(["dbus-uuidgen"]).decode()
        open("/mnt/etc/machine-id", "w").write(machine_id)

    # purge unnecessary packages
    print("# Removing unnecessary packages")
    unneeded_packages = ["live-boot"]
    if not CONFIG["dropbear"]:
        unneeded_packages += ["dropbear-initramfs", "dropbear-bin"]
    if CONFIG["purge_unnecessary"]:
        unneeded_packages += ["debootstrap", "python3-netifaces", "python3-dialog"]
        if CONFIG["filesystem_type"] != "zfs":
            unneeded_packages += ["zfs-dkms", "zfs-initramfs", "zfsutils-linux"]
        if not CONFIG["filesystem_encpasswd"]:
            unneeded_packages += ["dropbear-initramfs"]
        if not CONFIG["filesystem_encpasswd"] or CONFIG["filesystem_enczfsnative"]:
            unneeded_packages += ["cryptsetup", "cryptsetup-initramfs"]
        if 'lvm' not in CONFIG["filesystem_type"]:
            unneeded_packages += ["lvm2"]
    subprocess.call(["chroot", "/mnt", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-qqy", "purge"] + unneeded_packages)
    subprocess.call(["chroot", "/mnt", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-qqy", "autoremove", "--purge"])

    # /etc/ssh/ssh_host_*_key{,.pub}
    print("# Generating ssh host keys")
    subprocess.call(["chroot", "/mnt", "ssh-keygen", "-A"])

    # set root password
    print("# Setting root password")
    proc = subprocess.Popen(["chroot", "/mnt", "chpasswd"], stdin=subprocess.PIPE)
    proc.communicate(input=("root:%s\n" % CONFIG["root_password"]).encode())

    # set root shell
    print("# Setting root shell")
    subprocess.call(["chroot", "/mnt", "chsh", "-s", "/usr/bin/zsh", "root"])

    # /root/.dotfiles
    print("# Adding dotfiles")
    subprocess.call(["cp", "-Ra", "/root/.dotfiles", "/mnt/root"])
    # /root/.zshrc
    print("# Setting zshrc symlink")
    subprocess.call(["ln", "-sf", ".dotfiles/zshrc", "/mnt/root/.zshrc"])
    # /root/.ssh/authorized
    if CONFIG["root_pubkey"]:
        print("# Adding authorized keys for root")
        if not os.path.exists("/mnt/root/.ssh"):
            os.mkdir("/mnt/root/.ssh")
        open("/mnt/root/.ssh/authorized_keys", "w").write(CONFIG["root_pubkey"])

    # unprivileged user
    if CONFIG["user_name"]:
        print("# Setting up unprivileged user")
        # create user and home
        if not os.path.exists("/mnt/home/%s" % CONFIG["user_name"]):
            subprocess.call(["chroot", "/mnt", "useradd", "-m", CONFIG["user_name"]])
        home = "/mnt/home/" + CONFIG["user_name"]
        # set shell for user
        subprocess.call(["chroot", "/mnt", "chsh", "-s", "/usr/bin/zsh", CONFIG["user_name"]])
        # set password for user
        proc = subprocess.Popen(["chroot", "/mnt", "chpasswd"], stdin=subprocess.PIPE)
        proc.communicate(input=("%s:%s\n" % (CONFIG["user_name"], CONFIG["user_password"])).encode())
        # /home/$user/.dotfiles
        subprocess.call(["cp", "-Ra", "/root/.dotfiles", home + "/"])
        # /home/$user/.zshrc
        subprocess.call(["ln", "-sf", ".dotfiles/zshrc", home + "/.zshrc"])
        # /home/$user/.ssh/authorized_keys
        if CONFIG["user_pubkey"]:
            if not os.path.exists(home + "/.ssh"):
                os.mkdir(home + "/.ssh")
            open(home + "/.ssh/authorized_keys", "w").write(CONFIG["user_pubkey"])
        # /home/$user permissions
        subprocess.call(["chown", "-R", "1000:1000", home])

    # /etc/locale.gen
    print("# Generating locale")
    locales = "en_US.UTF-8 UTF-8\n"
    if open("/mnt/etc/locale.gen").read() != locales:
        open("/mnt/etc/locale.gen", "w").write(locales)
        subprocess.call(["chroot", "/mnt", "locale-gen"])

    # /etc/locale.conf
    print("# Configuring locale")
    open("/mnt/etc/locale.conf", "w").write("LANG=en_US.UTF-8\n")

    # /etc/vconsole.conf
    print("# Configuring keymap")
    open("/mnt/etc/vconsole.conf", "w").write("KEYMAP=us\n")

    # /etc/localtime
    print("# Configuring timezone")
    subprocess.call(["ln", "-sf", "/usr/share/zoneinfo/Europe/Berlin", "/mnt/etc/localtime"])

    # /etc/resolv.conf
    print("# Generating resolv.conf")
    if os.path.exists("/mnt/etc/resolv.conf"):
        os.unlink("/mnt/etc/resolv.conf")
    open("/mnt/etc/resolv.conf", "w").write("\n".join(["nameserver %s" % x for x in CONFIG["network_dns"]]) + "\n")

    # /etc/hostname
    print("# Setting hostname")
    open("/mnt/etc/hostname", "w").write(CONFIG["fqdn"].split(".")[0])

    # /etc/hosts
    print("# Generating hosts file")
    hosts = "127.0.1.1 %s %s\n" % (CONFIG["fqdn"], CONFIG["fqdn"].split(".")[0])
    hosts += "127.0.0.1 localhost\n"
    hosts += "::1 localhost ip6-localhost ip6-loopback\n"
    hosts += "ff02::1 ip6-allnodes\n"
    hosts += "ff02::2 ip6-allrouters\n"
    open("/mnt/etc/hosts", "w").write(hosts)

    # /etc/network/interfaces
    print("# Generating network configuration")
    interfaces = ""
    bridge_port = None

    initram_up = []
    initram_down = []

    for iface in CONFIG["network_interfaces"]:
        interfaces += f"auto {iface}\n"
    interfaces += "\n"

    bond_options = []
    if len(CONFIG["network_interfaces"]) == 1:
        mgmt_if = CONFIG["network_interfaces"][0]
        initram_mgmt_if = mgmt_if
    else:
        mgmt_if = "bond0"
        initram_mgmt_if = mgmt_if
        bond_options.append("bond-slaves " + (" ".join(CONFIG["network_interfaces"])))
        bond_options.append("bond-mode " + BOND_MODES[CONFIG["network_bond_type"]])
        bond_options.append("bond-miimon 100")
        interfaces += f"auto {mgmt_if}\n"
        initram_up.append(f"ip link add {initram_mgmt_if} type bond")
        initram_up.append(f"ip link set {initram_mgmt_if} type bond miimon 100 mode {BOND_MODES[CONFIG['network_bond_type']]}")
        initram_down.append(f"ip link del dev {initram_mgmt_if}")
        for iface in CONFIG["network_interfaces"]:
            initram_up.append(f"ip link set {iface} down")
            initram_up.append(f"ip link set {iface} master {initram_mgmt_if}")
            initram_up.append(f"ip link set {iface} up")
    initram_up.append(f"sysctl -w net.ipv6.conf.{initram_mgmt_if}.accept_ra=0 > /dev/null")
    initram_up.append(f"ip link set {initram_mgmt_if} up")
    initram_down.append(f"ip link set {initram_mgmt_if} down")

    if CONFIG["network_bridge"]:
        interfaces += f"iface {mgmt_if} inet manual\n"
        interfaces += f"    up sysctl -w net.ipv6.conf.{mgmt_if}.accept_ra=0\n"
        for option in bond_options:
            interfaces += f"    {option}\n"
        interfaces += "\n"
        interfaces += f"auto {CONFIG['network_bridge']}\n"
        bridge_port = mgmt_if
        mgmt_if = CONFIG["network_bridge"]

    vlan_id = CONFIG["network_vlan"]
    vlan_raw_device = None
    if CONFIG["network_vlan"]:
        initram_up.append(f"ip link add link {initram_mgmt_if} name {initram_mgmt_if}.{vlan_id} type vlan id {vlan_id}")
        initram_down.append(f"ip link del dev {initram_mgmt_if}.{vlan_id}")
        initram_up.append(f"sysctl -w net.ipv6.conf.{initram_mgmt_if}/{vlan_id}.accept_ra=0 > /dev/null")
        initram_up.append(f"ip link set {initram_mgmt_if}.{vlan_id} up")
        initram_down.append(f"ip link set {initram_mgmt_if}.{vlan_id} down")

        vlan_raw_device = mgmt_if
        interfaces += f"iface {mgmt_if} inet manual\n"
        interfaces += f"    up sysctl -w net.ipv6.conf.{mgmt_if}.accept_ra=0\n"
        if bridge_port:
            interfaces += f"    bridge_ports {bridge_port}\n"
            interfaces += f"    bridge_stp off\n"
            interfaces += f"    bridge_fd 0\n"
        else:
            for option in bond_options:
                interfaces += f"    {option}\n"
        mgmt_if = f"{mgmt_if}.{vlan_id}"
        initram_mgmt_if = f"{initram_mgmt_if}.{vlan_id}"
        interfaces += "\n"
        interfaces += f"auto {mgmt_if}\n"

    if CONFIG["network_ip6"]:
        interfaces += f"iface {mgmt_if} inet6 static\n"
        interfaces += f"    address {CONFIG['network_ip6']}\n"
        initram_up.append(f"ip -6 addr add {CONFIG['network_ip6']} dev {initram_mgmt_if}")
        initram_down.append(f"ip -6 addr flush dev {initram_mgmt_if}")
        initram_up.append(f"ip -6 route add default via {CONFIG['network_gw6']} dev {initram_mgmt_if}")
        initram_down.append(f"ip -6 route flush dev {initram_mgmt_if}")
        if CONFIG["network_gw6"]:
            interfaces += f"    gateway {CONFIG['network_gw6']}\n"
            interfaces += f"    up sysctl -w net.ipv6.conf.{mgmt_if.replace('.','/')}.accept_ra=0\n"
    else:
        interfaces += f"iface {mgmt_if} inet6\n"
    if vlan_raw_device:
        interfaces += f"    vlan-raw-device {vlan_raw_device}\n"
    elif bridge_port:
        interfaces += f"    bridge_ports {bridge_port}\n"
        interfaces += f"    bridge_stp off\n"
        interfaces += f"    bridge_fd 0\n"
    else:
        for option in bond_options:
            interfaces += f"    {option}\n"
    interfaces += "\n"

    if CONFIG["network_ip4"] != "disable":
        if CONFIG["network_ip4"]:
            initram_up.append(f"ip addr add {CONFIG['network_ip4']} dev {initram_mgmt_if}")
            initram_down.append(f"ip addr flush dev {initram_mgmt_if}")
            initram_up.append(f"ip route add default via {CONFIG['network_gw4']} dev {initram_mgmt_if}")
            initram_down.append(f"ip route flush dev {initram_mgmt_if}")
            interfaces += f"iface {mgmt_if} inet static\n"
            interfaces += f"    address {CONFIG['network_ip4']}\n"
            interfaces += f"    gateway {CONFIG['network_gw4']}\n"
        else:
            interfaces += f"iface {mgmt_if} inet dhcp\n"

    open("/mnt/etc/network/interfaces", "w").write(interfaces)

    if CONFIG["dropbear"]:
        initramscript = '#!/bin/sh\nif [ "${1}" = "prereqs" ]; then exit 0; fi\nexport PATH=/bin:/sbin:/usr/bin:/usr/sbin\necho Waiting 5 seconds before network configuration\nsleep 5\n'
        for cmd in initram_up:
            initramscript += cmd + "\n"
        initramscript += "sleep 2\nip a\n"
        print(initramscript)
        open("/mnt/etc/initramfs-tools/scripts/local-top/network", "w").write(initramscript)
        os.chmod("/mnt/etc/initramfs-tools/scripts/local-top/network", 0o755)

        open("/mnt/etc/initramfs-tools/conf.d/network.conf", "w").write("IP=off\n")
        open("/mnt/etc/initramfs-tools/modules", "a").write("8021q\nbonding\n")

        initramscript_down = '#!/bin/sh\nif [ "${1}" = "prereqs" ]; then exit 0; fi\nexport PATH=/bin:/sbin:/usr/bin:/usr/sbin\necho Clearing network configuration\n'
        for cmd in initram_down[::-1]:
            initramscript_down += cmd + "\n"
        open("/mnt/etc/initramfs-tools/scripts/local-bottom/network", "w").write(initramscript_down)
        os.chmod("/mnt/etc/initramfs-tools/scripts/local-bottom/network", 0o755)

        open("/mnt/etc/dropbear-initramfs/config", "w").write('DROPBEAR_OPTIONS="-p 222"\n')
        open("/mnt/etc/dropbear-initramfs/authorized_keys", "w").write(CONFIG["root_pubkey"])

    # /etc/crypttab
    print("# Generating crypttab")
    crypttab = "# <name> <device> <password> <options>\n"
    if CONFIG["filesystem_encpasswd"]:
        if CONFIG["filesystem_type"] == "zfs":
            if not CONFIG["filesystem_enczfsnative"]:
                for disk in CONFIG["filesystem_devices"]:
                    path = "/dev/disk/by-id/" + disk + "-part4"
                    uuid = subprocess.check_output(["blkid", path, "-o", "value", "-s", "UUID"]).decode().strip()
                    crypttab += f"{disk} UUID={uuid} none luks,initramfs,discard\n"
        else:
            if len(CONFIG["filesystem_devices"]) > 1:
                path = "/dev/md1"
            else:
                path = "/dev/disk/by-id/" + CONFIG["filesystem_devices"][0] + "-part4"
            uuid = subprocess.check_output(["blkid", path, "-o", "value", "-s", "UUID"]).decode().strip()
            crypttab += f"root-crypt UUID={uuid} none luks,initramfs,discard\n"

    open("/mnt/etc/crypttab", "w").write(crypttab)

    # /etc/fstab
    print("# Generating fstab")
    fstab = "tmpfs /tmp tmpfs nosuid,nodev 0 0\n"
    if len(CONFIG["filesystem_devices"]) > 1:
        boot_uuid = subprocess.check_output(["blkid", "/dev/md0", "-o", "value", "-s", "UUID"]).decode().strip()
        fstab += f"UUID={boot_uuid} /boot ext4 defaults,errors=remount-ro 0 0\n"
    else:
        boot_uuid = subprocess.check_output(["blkid", "/dev/disk/by-id/" + CONFIG["filesystem_devices"][0] + "-part3", "-o", "value", "-s", "UUID"]).decode().strip()
        fstab += f"UUID={boot_uuid} /boot ext4 defaults,errors=remount-ro 0 0\n"

        efi_uuid = subprocess.check_output(["blkid", "/dev/disk/by-id/" + CONFIG["filesystem_devices"][0] + "-part2", "-o", "value", "-s", "UUID"]).decode().strip()
        fstab += f"UUID={efi_uuid} /boot/efi vfat defaults,errors=remount-ro 0 0\n"

    fs = CONFIG["filesystem_type"]
    fsoptions = "defaults"
    if "ext4" in fs:
        fsoptions += ",errors=remount-ro"

    if "lvm" in CONFIG["filesystem_type"]:
        fstab += f"/dev/vg0/root / {fs[:-3]} {fsoptions} 0 0\n"
    elif CONFIG["filesystem_type"] in ["ext4", "xfs"]:
        if CONFIG["filesystem_encpasswd"]:
            root_part = "/dev/mapper/root-crypt"
        elif len(CONFIG["filesystem_devices"]) > 1:
            root_part = "UUID=" + subprocess.check_output(["blkid", "/dev/md1", "-o", "value", "-s", "UUID"]).decode().strip()
        else:
            root_part = "UUID=" + subprocess.check_output(["blkid", "/dev/disk/by-id/" + CONFIG["filesystem_devices"][0] + "-part4", "-o", "value", "-s", "UUID"]).decode().strip()
        fstab += f"{root_part} / {fs} {fsoptions} 0 0\n"
    open("/mnt/etc/fstab", "w").write(fstab)

    # /etc/mdadm/mdadm.conf
    print("# Generating mdadm config")
    mdadm = "HOMEHOST <system>\nMAILADDR root\n"
    if len(CONFIG["filesystem_devices"]) > 1:
        boot_raid_uuid = subprocess.check_output(["blkid", "/dev/disk/by-id/" + CONFIG["filesystem_devices"][0] + "-part3", "-o", "value", "-s", "UUID"]).decode().strip()
        mdadm += f"ARRAY /dev/md0 UUID={boot_raid_uuid.replace('-',':')}\n"
        if CONFIG["filesystem_type"] != "zfs":
            root_raid_uuid = subprocess.check_output(["blkid", "/dev/disk/by-id/" + CONFIG["filesystem_devices"][0] + "-part4", "-o", "value", "-s", "UUID"]).decode().strip()
            mdadm += f"ARRAY /dev/md1 UUID={root_raid_uuid.replace('-',':')}\n"
    open("/mnt/etc/mdadm/mdadm.conf", "w").write(mdadm)

    # update initramfs
    print("# Updating initramfs")
    kernel_version = os.path.basename(glob.glob("/mnt/lib/modules/*")[0])
    subprocess.call(["chroot", "/mnt", "update-initramfs", "-u", "-k", kernel_version])

    # /etc/default/grub
    grubdefault = "GRUB_DEFAULT=0\n"
    grubdefault += "GRUB_TIMEOUT=5\n"
    grubdefault += "GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`\n"
    grubdefault += "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n"
    if CONFIG["filesystem_type"] == "zfs":
        grubdefault += "GRUB_CMDLINE_LINUX=\"root=ZFS=zroot/ROOT/debian boot=zfs audit=0\"\n"
        open("/mnt/etc/kernel/cmdline", "w").write("root=ZFS=zroot/ROOT/debian boot=zfs audit=0")
    else:
        grubdefault += "GRUB_CMDLINE_LINUX=\"audit=0\"\n"
        open("/mnt/etc/kernel/cmdline", "w").write("audit=0")
    open("/mnt/etc/default/grub", "w").write(grubdefault)

    # configure and install grub
    print("# Configuring and installing grub")
    if not os.path.exists("/mnt/boot/efi"):
        os.mkdir("/mnt/boot/efi")
    subprocess.call(["chroot", "/mnt", "update-grub"])

    esp_list = []
    for disk in CONFIG["filesystem_devices"]:
        path = "/dev/disk/by-id/" + disk + "-part2"
        esp_list.append(subprocess.check_output(["blkid", path, "-o", "value", "-s", "UUID"]).decode())
        subprocess.call(["mount", path, "/mnt/boot/efi"])
        subprocess.call(["chroot", "/mnt", "grub-install", "--target=i386-pc", "/dev/disk/by-id/" + disk])
        subprocess.call(["chroot", "/mnt", "grub-install", "--target=x86_64-efi", "--removable"])
        subprocess.call(["umount", "/mnt/boot/efi"])

    if len(esp_list) > 1:
        open("/mnt/etc/kernel/efi-boot-uuids", "w").write("\n".join(esp_list))

    # update motd and issue
    print("# Updating motd + issue")
    open("/mnt/etc/motd", "w").write("")
    open("/mnt/etc/issue", "w").write(open("/etc/issue").read().splitlines()[0] + "\n\n")

    print("# Done!")

    if "shutdown" in CONFIG and CONFIG["shutdown"]:
        subprocess.call(["shutdown", "-h", "now"])

if __name__ == '__main__':
    main()
