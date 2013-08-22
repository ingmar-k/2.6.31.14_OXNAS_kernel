#!/bin/sh

RM=/bin/rm
MODEL_ID=`cat /etc/modelname`
STAGE1_DATA=/mnt/ram1/DATA_1006
INFO_PATH=/zyxel/mnt/info
STAGE1_MD5=${INFO_PATH}/stage1_checksum

/bin/rm -rf ${INFO_PATH}/stage1_checksum
echo "ff3388ca1ba5cca5797d5234e020729d" > ${INFO_PATH}/stage1_checksum
"`/sbin/nanddump -i -b -f /tmp/mtd1 /dev/mtd1`"
STAGE1_FLASH=`/sbin/md5sum /tmp/mtd1 | awk {'print $1'}`
/bin/rm -rf /tmp/mtd1
echo "Doing post-install ..." > /dev/console

# We only need update stage1 for STG-212
#if [ ${MODEL_ID} == "NAS-SERVER" ] && [ -f ${STAGE1_DATA} ] && [ "`/sbin/md5sum ${STAGE1_DATA} | awk {'print $1'}`" != "`cat ${STAGE1_MD5}`" ]; then
if [ ${MODEL_ID} == "NAS-SERVER" ] && [ $STAGE1_FLASH != "`cat ${STAGE1_MD5}`" ]; then
    echo "Upgrading stage1 ..." > /dev/console

	/sbin/flash_eraseall /dev/mtd1
	/sbin/nandbd -f ${STAGE1_DATA} -t fec -o 0x0 /dev/mtd1
	/sbin/nandbd -f ${STAGE1_DATA} -t fec -o 0x20000 /dev/mtd1

	/bin/mount -o remount,rw ${INFO_PATH}
	echo `/sbin/md5sum ${STAGE1_DATA} | awk {'print $1'}` > ${STAGE1_MD5}
	/bin/mount -o remount,ro ${INFO_PATH}

	${RM} -rf ${STAGE1_DATA}
fi

echo " ... post-install finishes!" > /dev/console
exit 0

