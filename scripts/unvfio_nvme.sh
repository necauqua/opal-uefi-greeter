#!/bin/bash

. nvme_device.sh

if ! lsblk | grep -q "$BLK_NVM"; then
  echo 1 > /sys/bus/pci/devices/"$PCI_NVM"/remove
  echo 1 > /sys/bus/pci/rescan
  modprobe -rv vfio-pci
fi
