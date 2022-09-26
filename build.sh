#!/bin/bash

BUILD_DIR="/tmp/build"
CHROOT_DIR="${BUILD_DIR}/chroot"
STAGING_DIR="${BUILD_DIR}/staging"

PACKAGES="linux-image-amd64 linux-headers-amd64"
PACKAGES="${PACKAGES} dbus systemd-sysv live-boot xz-utils"
PACKAGES="${PACKAGES} locales console-setup"
PACKAGES="${PACKAGES} vim git htop tmux zsh curl wget"
PACKAGES="${PACKAGES} ifupdown2 bridge-utils ifenslave isc-dhcp-client"
PACKAGES="${PACKAGES} iproute2 net-tools ethtool tcpdump iputils-ping"
PACKAGES="${PACKAGES} cryptsetup cryptsetup-initramfs dropbear-initramfs"
PACKAGES="${PACKAGES} mdadm lvm2"
PACKAGES="${PACKAGES} gdisk parted debootstrap"
PACKAGES="${PACKAGES} dosfstools e2fsprogs xfsprogs"
PACKAGES="${PACKAGES} openssh-server"
PACKAGES="${PACKAGES} ipmitool"
PACKAGES="${PACKAGES} python3-netifaces python3-dialog"
PACKAGES="${PACKAGES} grub-efi grub-pc-bin rsync"
PACKAGES="${PACKAGES} ca-certificates"

BACKPORTS="zfs-dkms zfs-initramfs zfsutils-linux"

debootstrap --arch=amd64 --variant=minbase bullseye "${CHROOT_DIR}" http://deb.debian.org/debian/
cp -R files/rootfs/* "${CHROOT_DIR}/"

chroot "${CHROOT_DIR}" apt-get -qq update
chroot "${CHROOT_DIR}" env DEBIAN_FRONTEND=noninteractive apt-get -qqy dist-upgrade
chroot "${CHROOT_DIR}" env DEBIAN_FRONTEND=noninteractive apt-get -qqy install --no-install-recommends ${PACKAGES}
chroot "${CHROOT_DIR}" env DEBIAN_FRONTEND=noninteractive apt-get -qqy install -t bullseye-backports --no-install-recommends ${BACKPORTS}
chroot "${CHROOT_DIR}" dkms install "$(basename ${CHROOT_DIR}/usr/src/zfs-* | tr '-' '/')" -k "$(basename ${CHROOT_DIR}/lib/modules/*)"

mkdir "${CHROOT_DIR}/etc/systemd/system/getty@tty1.service.d"
printf "[Service]\nExecStart=\nExecStart=-/sbin/agetty --autologin root --noclear %%I \$TERM\n" > "${CHROOT_DIR}/etc/systemd/system/getty@tty1.service.d/override.conf"

echo en_US.UTF-8 UTF-8 > "${CHROOT_DIR}/etc/locale.gen"
chroot "${CHROOT_DIR}" locale-gen
echo root:root | chroot "${CHROOT_DIR}" chpasswd

git clone https://github.com/lukas2511/dotfiles.git "${CHROOT_DIR}/root/.dotfiles"
ln -s .dotfiles/zshrc "${CHROOT_DIR}/root/.zshrc"
chroot "${CHROOT_DIR}" chsh -s /usr/bin/zsh root

echo "AUTO -all" >> "${CHROOT_DIR}/etc/mdadm/mdadm.conf"

rm -rf "${CHROOT_DIR}/var/lib/apt/lists" "${CHROOT_DIR}/var/cache/apt/"*
rm -rf "${CHROOT_DIR}/dev"/*
rm -rf "${CHROOT_DIR}/proc"/*
rm -rf "${CHROOT_DIR}/sys"/*

mkdir -p "${STAGING_DIR}"
cp -R files/staging/* "${STAGING_DIR}/"
cp install.py "${CHROOT_DIR}/root/install.py"
chmod a+x "${CHROOT_DIR}/root/install.py"
mksquashfs "${CHROOT_DIR}" "${STAGING_DIR}/live/filesystem.squashfs" -comp xz
cp ${CHROOT_DIR}/boot/vmlinuz-* "${STAGING_DIR}/live/vmlinuz"
cp ${CHROOT_DIR}/boot/initrd.img-* "${STAGING_DIR}/live/initrd"

mkdir -p "${BUILD_DIR}/tmp"
cat > "${BUILD_DIR}/tmp/grub-embed.cfg" << 'EOF'
if ! [ -d "$cmdpath" ]; then
    # On some firmware, GRUB has a wrong cmdpath when booted from an optical disc.
    # https://gitlab.archlinux.org/archlinux/archiso/-/issues/183
    if regexp --set=1:isodevice '^(\([^)]+\))\/?[Ee][Ff][Ii]\/[Bb][Oo][Oo][Tt]\/?$' "$cmdpath"; then
        cmdpath="${isodevice}/EFI/BOOT"
    fi
fi
configfile "${cmdpath}/grub.cfg"
EOF

cp /usr/lib/ISOLINUX/isolinux.bin "${STAGING_DIR}/isolinux/"
cp /usr/lib/syslinux/modules/bios/* "${STAGING_DIR}/isolinux/"
cp -r /usr/lib/grub/x86_64-efi/* "${STAGING_DIR}/boot/grub/x86_64-efi/"

grub-mkstandalone -O x86_64-efi \
    --modules="part_gpt part_msdos fat iso9660" \
    --locales="" \
    --themes="" \
    --fonts="" \
    --output="${STAGING_DIR}/EFI/BOOT/BOOTx64.EFI" \
    "boot/grub/grub.cfg=${BUILD_DIR}/tmp/grub-embed.cfg"

(cd "${STAGING_DIR}" && \
    dd if=/dev/zero of=efiboot.img bs=1M count=20 && \
    mkfs.vfat efiboot.img && \
    mmd -i efiboot.img ::/EFI ::/EFI/BOOT && \
    mcopy -vi efiboot.img \
        ${STAGING_DIR}/EFI/BOOT/BOOTx64.EFI \
        ${STAGING_DIR}/boot/grub/grub.cfg \
        ::/EFI/BOOT/
)

xorriso \
    -as mkisofs \
    -iso-level 3 \
    -o "debian-custom.iso" \
    -full-iso9660-filenames \
    -volid "DEBLIVE" \
    --mbr-force-bootable -partition_offset 16 \
    -joliet -joliet-long -rational-rock \
    -isohybrid-mbr /usr/lib/ISOLINUX/isohdpfx.bin \
    -eltorito-boot \
        isolinux/isolinux.bin \
        -no-emul-boot \
        -boot-load-size 4 \
        -boot-info-table \
        --eltorito-catalog isolinux/isolinux.cat \
    -eltorito-alt-boot \
        -e --interval:appended_partition_2:all:: \
        -no-emul-boot \
        -isohybrid-gpt-basdat \
    -append_partition 2 C12A7328-F81F-11D2-BA4B-00A0C93EC93B ${STAGING_DIR}/efiboot.img \
    "${STAGING_DIR}"
