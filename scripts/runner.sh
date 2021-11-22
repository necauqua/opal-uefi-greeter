#!/bin/bash

mkdir -p target/run/mnt/EFI/BOOT
cp "$1" target/run/mnt/EFI/BOOT/BOOTX64.efi
cp config-example target/run/mnt/config

cp /usr/share/edk2-ovmf/x64/OVMF_CODE.fd target/run || exit 1

# keep vars dirty so that you can set the BootOrder and stuff
if [ ! -f target/run/OVMF_VARS.fd ]; then
  cp /usr/share/edk2-ovmf/x64/OVMF_VARS.fd target/run || exit 1
fi

. scripts/nvme_device.sh

# sadly need sudo to attach the pci device
if lsblk | grep -q "$BLK_NVM"; then
  echo -n "/dev/$BLK_NVM is attached to host system, want to detach? [y/N]: "
  read -r
  if [ "$REPLY" == y ]; then
    pushd scripts || exit
    ./vfio_nvme.sh
    popd || exit
  else
    exit 0
  fi
fi

qemu-system-x86_64 \
    -nodefaults \
    -vga std \
    -machine q35 \
    -m 1G \
    -nic user,model=virtio-net-pci \
    -drive if=pflash,format=raw,file=target/run/OVMF_CODE.fd,readonly=on \
    -drive if=pflash,format=raw,file=target/run/OVMF_VARS.fd \
    -device vfio-pci,host="${PCI_NVM}" \
    -drive format=raw,file=fat:rw:target/run/mnt \
    -serial stdio \
    -monitor vc:1920x1080
