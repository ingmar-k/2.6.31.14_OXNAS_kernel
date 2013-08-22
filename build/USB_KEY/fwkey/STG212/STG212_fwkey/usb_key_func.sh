#!/bin/sh

#----------------------------------------------
# Version Date: 2009-05-22
#----------------------------------------------
KEY_PATH="/mnt/parnerkey/STG212_fwkey"
HTP_PATH="/zyxel/htp"
FWKEY_DESTPATH="/zyxel/mnt/info"
FWKEY_DESTFN="${FWKEY_DESTPATH}/fw_key"
#/bin/SetNetwork.sh static 192.168.1.3 255.255.255.0 192.168.1.254
${KEY_PATH}/SetNetwork.sh static 192.168.1.3 255.255.255.0 192.168.1.254

if [ -x /sbin/telnetd ]; then
        echo "Starting telnet daemon..."
        /sbin/telnetd
fi

#Show checksum info
cat /zyxel/mnt/info/core_checksum
cat /zyxel/mnt/info/zld_checksum
cat /zyxel/mnt/info/romfile_checksum
cat /zyxel/mnt/info/image_checksum

#Show fwversion
cat /zyxel/mnt/info/fwversion

#Execute sg_map so that it detects the SD_Card
sg_map -x -i

#Copy htppk.sh in partnerkey to file system
cp ${KEY_PATH}/htppk.sh ${HTP_PATH}/htppk.sh
cp ${KEY_PATH}/htppt.sh ${HTP_PATH}/htppt.sh
cp ${KEY_PATH}/htpfqc.sh ${HTP_PATH}/htpfqc.sh
cp ${KEY_PATH}/storage_test.sh ${HTP_PATH}/storage_test.sh
cp ${KEY_PATH}/led_test.sh ${HTP_PATH}/led_test.sh
#cp ${KEY_PATH}/testButton ${HTP_PATH}/testButton
cp ${KEY_PATH}/check_fw.sh ${HTP_PATH}/check_fw.sh
cp ${KEY_PATH}/kernelcheck ${HTP_PATH}/kernelcheck

cd /zyxel/htp/
#./htppk.sh
cd -

MAC_ADDR=`mrd_mac eth0`
FN_KEY=`echo ${MAC_ADDR} | sed 's/://g'`.key
if [ -f ${KEY_PATH}/${FN_KEY} ]; then
	echo "Found FW_KEY for this machine, copying FW_KEY: ${FN_KEY}"
	mount -o remount,rw ${FWKEY_DESTPATH}
	cp ${KEY_PATH}/${FN_KEY} ${FWKEY_DESTFN}
	mount -o remount,ro ${FWKEY_DESTPATH}

	# If ${FWKEY_DESTPATH} is at HDD, force to copy FW KEY to NAND flash.
	cat /proc/mounts | grep sysdisk | grep sda1 > /dev/null 2>&1
	if [ $? -eq 0 ]; then
		# can grep sda1 & sysdisk, so FWKEY_DESTPATH is at HDD
		mount -t yaffs2 /dev/mtdblock6 /zyxel/mnt/info2
		cp ${KEY_PATH}/${FN_KEY} /zyxel/mnt/info2/fw_key
		umount /zyxel/mnt/info2
	fi

	echo "COMPLETE!"
	setLED SYS BLUE FAST_BLINK
else
	echo "Can not find FW_KEY for this machine: ${FN_KEY}"
	setLED SYS RED FAST_BLINK
	buzzerc -t 31
fi

echo "Stopped here"

exit 0

