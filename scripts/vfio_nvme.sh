#!/bin/bash

. nvme_device.sh

if lsblk | grep -q "$BLK_NVM"; then
  modprobe -v vfio-pci

  echo "$DEV_NVM" > /sys/bus/pci/drivers/vfio-pci/new_id
  echo "$PCI_NVM" > /sys/bus/pci/devices/"$PCI_NVM"/driver/unbind
  echo "$PCI_NVM" > /sys/bus/pci/drivers/vfio-pci/bind
  echo "$DEV_NVM" > /sys/bus/pci/drivers/vfio-pci/remove_id
fi
