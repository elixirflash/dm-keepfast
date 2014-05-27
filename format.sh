#!/system/bin/sh

busybox mkfs.vfat /dev/block/mmcblk1p4
mount -t vfat /dev/block/mmcblk1p4 fatfs
