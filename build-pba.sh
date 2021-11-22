#!/bin/bash

if ! which cargo gdisk mkfs.fat realpath > /dev/null; then
  echo 'No cargo, gdisk, mkfs.fat or realpath'
  exit 1
fi

EFI_FILE=EFI/BOOT/BOOTX64.efi
OFFSET=1048576
SECTOR_SIZE=512

IMG=$(test -n "$1" && echo "$1" || echo pba.gptdisk)

pushd "$(dirname "$(realpath "$0")")" || exit 1

cargo b --release || exit 1

# 1mb for gpt stuff & align,
# 1 remaining is more than enough for our image + config + remaining gpt stuff
dd if=/dev/zero of="$IMG" bs=1M count=2
mkdir mnt

function error {
  rm "$IMG"
  rmdir mnt
  echo
  echo "Failed to build the PBA image"
  echo
  exit 1
}

gdisk "$IMG" << END || error
o
y
n



ef00
w
Y
END

mkfs.fat --offset $(("$OFFSET" / "$SECTOR_SIZE")) "${IMG}" || error

echo
echo "Asking for sudo permissions to mount the image"
echo

sudo mount -o loop,offset="$OFFSET" "$IMG" mnt || error
sudo mkdir -p mnt/"${EFI_FILE%/*}"
sudo cp -r target/x86_64-unknown-uefi/release/opal-uefi-greeter.efi mnt/"$EFI_FILE" || error
sudo cp -r config-example mnt/config || error
sudo umount mnt || error

rmdir mnt

echo
echo "Built the PBA image successfully"
echo
