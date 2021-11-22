#!/bin/bash

. nvme_device.sh

P=$(getpasswd)

./unvfio_nvme.sh
sudo sedutil-cli --setmbrdone off "$P" "/dev/$BLK_NVM"
sudo sedutil-cli --setlockingrange 0 lk "$P" "/dev/$BLK_NVM"
./vfio_nvme.sh
