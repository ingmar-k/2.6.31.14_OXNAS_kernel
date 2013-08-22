#!/bin/sh -x

DISK_PATH="/zyxel/mnt/sysdisk2"
INFO_PATH=${DISK_PATH}/info
IMG_NAME="sysdisk.img"	# new img name is same as old img name

### yaffs2 --> sda1 ###

# check if HDD /dev/sda exists
/bin/fdisk -l /dev/sda | /bin/grep sda > /dev/null 2>&1
if [ $? -ne 0 ]; then
	echo "HDD (/dev/sda) does not exist!"
	exit 0
fi

/bin/cat /proc/mounts | grep sda1 | grep "/zyxel/mnt/sysdisk" > /dev/null 2>&1
if [ $? -eq 0 ]; then
	echo "/dev/sda1 is sysdisk already, skip this transformation!"
	exit 0
fi


###### After this line, the yaffs2-to-sda1 transformation starts! ######



# Make sure that /dev/sda1 is not mounted.
umount /dev/sda1
swapoff /dev/sda1

# check if /dev/sda1 is formatted & mounted
/bin/fdisk -l /dev/sda1 | /bin/grep sda1
if [ $? -ne 0 ]; then
	echo "/dev/sda1 does not exist! Create /dev/sda1 partition!"
	echo -e "n\np\n1\n1\n64\nw\n" | /bin/fdisk /dev/sda
fi

# Try to format & mount /dev/sda1 to ${DISK_PATH}
mkdir -p ${DISK_PATH}
/bin/mount -t ext2 /dev/sda1 ${DISK_PATH}
if [ $? -ne 0 ]; then
	echo "/dev/sda1 is not formatted! Formatting..."
	mke2fs -m 0 /dev/sda1
	/bin/mount -t ext2 /dev/sda1 ${DISK_PATH}
fi

# Remove all files within /dev/sda1; How to do this safely?
/bin/rm -rf ${DISK_PATH}/*

### Copy necessary files to ${DISK_PATH}

mkdir -p ${DISK_PATH}/info
mkdir -p ${DISK_PATH}/zyxel

# ${DISK_PATH}/info

cp -R /zyxel/mnt/info/* ${DISK_PATH}/info

# Write firmware version
/bin/echo `/bin/cat /mnt/ram1/DATA_0001` > ${INFO_PATH}/fwversion
# Write firmware revision
/bin/echo `/bin/cat /mnt/ram1/DATA_0002` > ${INFO_PATH}/revision
# Write model ID
/bin/echo `/bin/cat /mnt/ram1/DATA_0101` > ${INFO_PATH}/modelid
# Write core checksum
/bin/echo `/bin/cat /mnt/ram1/DATA_0200` > ${INFO_PATH}/core_checksum
# Write ZLD checksum (sysdisk.img.gz)
/bin/echo `/bin/cat /mnt/ram1/DATA_0201` > ${INFO_PATH}/zld_checksum
# Write ROM checksum
/bin/echo `/bin/cat /mnt/ram1/DATA_0202` > ${INFO_PATH}/romfile_checksum
# Write InitRD checksum
#/bin/echo `/bin/cat /mnt/ram1/DATA_0203` > ${INFO_PATH}/initrd_checksum
# Write image checksum (sysdisk.img)
/bin/echo `/bin/cat /mnt/ram1/DATA_0204` > ${INFO_PATH}/image_checksum


# ${DISK_PATH}/zyxel

# Ensure the old files existence
/bin/cp -R /etc/zyxel/* ${DISK_PATH}/zyxel/

# sysdisk.img

echo "`date '+%Y-%m-%d %H:%M:%S'` Start decompressing ${IMG_NAME} ..."
/bin/gzip -cd /mnt/ram1/DATA_1004 > ${DISK_PATH}/${IMG_NAME}

echo "`date '+%Y-%m-%d %H:%M:%S'` Start calculating the MD5 checksum of ${IMG_NAME} ..."
IMG_MD5=`md5sum "${DISK_PATH}/${IMG_NAME}" | awk '{print $1}'`
IMG_FILE=`cat /mnt/ram1/DATA_0204`

echo "`date '+%Y-%m-%d %H:%M:%S'` End of checksum calculation."
if [ "${IMG_MD5}" == "${IMG_FILE}" ]; then
	echo "The checksum verification of system image on NAND flash passes!"
else
	echo "-12" > ${PROGRESS_LOG}
	echo -e "upgrade_fw\n-12\nFail to extract firmware file." > /tmp/LCD.txt
	echo "The checksum of system image MISMATCH!"

	# enable reboot/shutdown ability
	echo 1 > /proc/shutdownStatus
	sleep 1
	/sbin/reboot

	exit 1
fi


exit 0

