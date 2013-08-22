#!/bin/sh
##########################################################################
#       This htpfqc.sh is for FQC on STG211			         #
#       Only one ethernet device is equiped on the device.               #
##########################################################################

echo "HTP FQC Start."

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



#show thermal sensor input
Temp_sensor=`cat /proc/therm-fan | grep temperature | awk '{print $3}'`

##cat /sys/devices/platform/i2c-0/0-002e/fan1_input
FAN_speed=`cat /tmp/fan1_average` # fan average file name should be refer to usb_key_func.sh
echo Fan:${FAN_speed}
echo Temperature:${Temp_sensor}
read a
#./htp_main -f htp.lst.external
./storage_test.sh

printf "LED test.................."
./led_test.sh 1>/dev/null
printf "OK\n"

printf "Buzzer testing............"
buzzerc	-t 6
sleep 6
printf "OK\n"

printf "COPY Button test.........."
./testButton COPY

printf "RESET Button test.........."
./testButton RESET

#In FQC, we don't need to set the MAC address.
#./htp_test_items mac

MODEL_ID=`mrd_model -p`
FirstMAC=`mrd_mac eth0`
LastMAC=`mrd_mac eth0`
MAC_Quantity=1 #For STG series have only one ethernet device
echo ${MODEL_ID}
echo ${FirstMAC}
echo ${LastMAC}
echo ${MAC_Quantity}

echo "HTP Done."
