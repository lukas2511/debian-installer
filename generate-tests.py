#!/usr/bin/env python3

import json
import subprocess
import tempfile
import os
import shutil

BASE_CONFIG = {
    'fqdn': 'debian.lan',
    'timezone': 'Europe/Berlin',
    'network_interfaces': ['ens3'],
    'network_bond_type': None,
    'network_bridge': 'br0',
    'network_vlan': '',
    'network_ip6': '',
    'network_gw6': '',
    'network_ip4': '10.0.2.15/24',
    'network_gw4': '10.0.2.2',
    'network_dns': ['2606:4700:4700::1111', '2606:4700:4700::1001', '1.1.1.1', '1.0.0.1'],
    'root_password': 'test1234',
    'root_pubkey': 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH7W3NIGeEGRHu63+dP7s6M5/s0uHODI4QV2Y1yOzDEq lukas2511',
    'user_name': '',
    'purge_unnecessary': True,
    'skip_configured': True,
    'automatic_install': True,
    'shutdown': True,
}

DISKS = ["ata-QEMU_HARDDISK_QM00001", "ata-QEMU_HARDDISK_QM00002", "ata-QEMU_HARDDISK_QM00003"]

CONFIGS = []

def add_config(config):
    CONFIGS.append(config.copy())

for filesystem_type in ["zfs", "ext4", "ext4lvm"]:
    for encpasswd in ["", "test1234"]:
        for num_disks in [1, 2]:
            CONFIG = BASE_CONFIG.copy()
            CONFIG["filesystem_type"] = filesystem_type
            CONFIG["filesystem_devices"] = DISKS[:num_disks]
            CONFIG["filesystem_encpasswd"] = encpasswd
            CONFIG["filesystem_raidlevel"] = '1' if (num_disks > 1) else ''
            CONFIG['filesystem_enczfsnative'] = False
            if filesystem_type == "zfs":
                add_config(CONFIG)
                CONFIG['filesystem_enczfsnative'] = True
            add_config(CONFIG)

template_script = "#!/bin/bash\n\n"
template_script += 'SOURCE="${0}"\n'
template_script += 'while [ -h "$SOURCE" ]; do DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"; SOURCE="$(readlink "$SOURCE")"; [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"; done\n'
template_script += 'SCRIPTDIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"\n'
template_script += 'cd "${SCRIPTDIR}"\n\n'

install_all = template_script
install_all += 'N=4\n'
install_all += 'for script in'

for i, config in enumerate(CONFIGS):
    name = config["filesystem_type"] + ("-raid%s" % config["filesystem_raidlevel"] if len(config['filesystem_devices']) > 1 else "") + ("-encrypted" if config["filesystem_encpasswd"] else "") + ("-native" if config["filesystem_enczfsnative"] else "")

    if not os.path.exists("tests"):
        os.mkdir("tests")
    if not os.path.exists("tests/%s" % name):
        os.mkdir("tests/%s" % name)

    configfile = "tests/%s/config.json" % name
    open(configfile, "w").write(json.dumps(config, indent=4))

    configimage = "tests/%s/config.img" % name
    subprocess.call(["dd", "status=none", "if=/dev/zero", "of=" + configimage, "bs=1M", "count=20"])
    subprocess.call(["mkfs.vfat", "-n", "INSTALL_CFG", configimage], stdout=subprocess.PIPE)
    subprocess.call(["mcopy", "-i", configimage, configfile, "::/config.json"])
    subprocess.call(["mcopy", "-i", configimage, "install.py", "::/install.py"])

    script = template_script
    script += "qemu-system-x86_64 -enable-kvm \\\n"
    script += "  -m 4096M -smp 8 \\\n"

    letters = "abde"
    for i in range(len(config["filesystem_devices"])):
        if os.path.exists("tests/%s/disk%d.img" % (name, i)):
            os.unlink("tests/%s/disk%d.img" % (name, i))
        subprocess.call(["qemu-img", "create", "-q", "-f", "raw", "tests/%s/disk%d.img" % (name, i), "30G"])
        #script += "  -hd%s disk%d.img \\\n" % (letters[i], i)
        script += "  -drive file=disk%d.img,index=%d,media=disk,format=raw \\\n" % (i, i)

    open("tests/%s/boot.sh" % name, "w").write(script[:-3] + "\n")
    os.chmod("tests/%s/boot.sh" % name, 0o0755)

    script += "  -drive file=config.img,index=%d,media=disk,format=raw \\\n" % (i+1)
    script += "  -drive file=../../debian-custom.iso,index=%d,media=cdrom,format=raw" % (i+2)

    open("tests/%s/install.sh" % name, "w").write(script)
    os.chmod("tests/%s/install.sh" % name, 0o0755)

    install_all += " %s/install.sh" % name
install_all += '; do\n'
install_all += '    ((i=i%N)); ((i++==0)) && wait\n'
install_all += '    $script &\n'
install_all += 'done\n'

open("tests/install-all.sh", "w").write(install_all)
os.chmod("tests/install-all.sh", 0o0755)
