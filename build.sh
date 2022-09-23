#!/bin/bash

BUILD_DIR="/tmp/build"
CHROOT_DIR="${BUILD_DIR}/chroot"
STAGING_DIR="${BUILD_DIR}/staging"

PACKAGES="pve-kernel-5.19 systemd-sysv live-boot xz-utils"
PACKAGES="${PACKAGES} locales localepurge"
PACKAGES="${PACKAGES} vim git htop tmux zsh curl wget"
PACKAGES="${PACKAGES} iproute2 net-tools ethtool tcpdump iputils-ping"
PACKAGES="${PACKAGES} cryptsetup zfsutils"
PACKAGES="${PACKAGES} gdisk parted"
PACKAGES="${PACKAGES} dosfstools e2fsprogs"
PACKAGES="${PACKAGES} network-manager openssh-server"
PACKAGES="${PACKAGES} ipmitool"

debootstrap --arch=amd64 --variant=minbase bullseye "${CHROOT_DIR}" http://ftp.de.debian.org/debian/
cp -R files/rootfs/* "${CHROOT_DIR}/"

chroot "${CHROOT_DIR}" apt-get -qq update
chroot "${CHROOT_DIR}" env DEBIAN_FRONTEND=noninteractive apt-get -qqy dist-upgrade
chroot "${CHROOT_DIR}" env DEBIAN_FRONTEND=noninteractive apt-get -qqy install --no-install-recommends ${PACKAGES}
echo root:root | chroot "${CHROOT_DIR}" chpasswd

git clone https://github.com/lukas2511/dotfiles.git "${CHROOT_DIR}/root/.dotfiles"
ln -s .dotfiles/zshrc "${CHROOT_DIR}/root/.zshrc"
chroot "${CHROOT_DIR}" chsh -s /usr/bin/zsh root

rm -rf "${CHROOT_DIR}/usr/share/man" "${CHROOT_DIR}/var/lib/apt" "${CHROOT_DIR}/var/cache/apt" "${CHROOT_DIR}/var/log"/*

mkdir -p "${STAGING_DIR}"
cp -R files/staging/* "${STAGING_DIR}/"
mksquashfs "${CHROOT_DIR}" "${STAGING_DIR}/live/filesystem.squashfs"
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
