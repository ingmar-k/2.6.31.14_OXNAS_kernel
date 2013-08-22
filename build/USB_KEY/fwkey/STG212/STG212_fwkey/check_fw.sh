#!/bin/sh
#########################################################################
#	This script is used to check the information of firmware	#
#########################################################################

MODELNAME=`cat /etc/modelname`

#show fw version
cat /zyxel/mnt/info/fwversion

#show the build time of kernel
uname -a

#show checksum
#core
cat /zyxel/mnt/info/core_checksum
#rom
cat /zyxel/mnt/info/romfile_checksum
#zld
cat /zyxel/mnt/info/zld_checksum
#image
cat /zyxel/mnt/info/image_checksum
INFO_IMG_CHKSUM=`cat /zyxel/mnt/info/image_checksum`
sleep 1

#check checksum of sysdisk.img
echo "Start checking checksum of sysdisk.img"
MD5SUM=/sbin/md5sum

REAL_IMG_CHKSUM=`md5sum /zyxel/mnt/sysdisk/sysdisk.img | awk '{print $1}'`

if [ "x"${REAL_IMG_CHKSUM} == "x"${INFO_IMG_CHKSUM} ]; then
	SYSIMG_CHECKSUM_MATCH="OK"
else
	SYSIMG_CHECKSUM_MATCH="NG"
fi

echo "Press enter to show checksum result"
read a
echo "       Checksum of sysdisk.img : ${REAL_IMG_CHKSUM}"
echo "Checksum from INFO sysdisk.img : ${INFO_IMG_CHKSUM}"
echo " Compare result of sysdisk.img : ${SYSIMG_CHECKSUM_MATCH}"
echo ""

echo "checking checksum of kernel"
NAND_MBLOCK_KERNEL=/dev/mtd4
#Check the first 9MB of the kernel block.
NAND_SIZE_KERNEL=9437184
./kernelcheck ${NAND_MBLOCK_KERNEL} ${NAND_SIZE_KERNEL}
if [ $? == 0 ]; then
	KERNEL_CHECK_RESULT="OK"
else
	KERNEL_CHECK_RESULT="NG"
fi
echo "check result of kernel : ${KERNEL_CHECK_RESULT}"

MODEL_ID=`mrd_model -p`
echo ${MODEL_ID}
