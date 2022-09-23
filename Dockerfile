FROM debian:latest

RUN apt-get -qq update && \
		apt-get -qqy install debootstrap squashfs-tools xorriso isolinux syslinux-efi grub-pc-bin grub-efi-amd64-bin mtools dosfstools git && \
		apt-get clean && \
		rm -rf /var/lib/apt /var/cache/apt

