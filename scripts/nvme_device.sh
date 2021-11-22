
# To list ur devices to find pci numbers and dev ids,
# as well as to check if unvfio_nvme.sh would work (would have a [RESET] prefix)
# beforehand:
#
# for iommu_group in $(find /sys/kernel/iommu_groups/ -maxdepth 1 -mindepth 1 -type d); do
#   echo "IOMMU group $(basename "$iommu_group")"
#   for device in $(\ls -1 "$iommu_group"/devices/); do
#     if [[ -e "$iommu_group"/devices/"$device"/reset ]]; then
#       echo -n "[RESET]"
#     fi
#     echo -n $'\t'
#     lspci -nns "$device"
#   done;
# done

# too lazy to do it more universally with less parameters
# also block device doesn't exist once we unbind the pci..
PCI_NVM='0000:01:00.0'
DEV_NVM='144d a80a' # yes I have this, and yes at the time of writing this is not a boot drive lul
BLK_NVM='nvme0n1'
