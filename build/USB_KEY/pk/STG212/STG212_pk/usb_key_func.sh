#!/bin/sh

#----------------------------------------------
# Version Date: 2009-05-22
#----------------------------------------------
KEY_PATH="/mnt/parnerkey/STG212_pk"
HTP_PATH="/zyxel/htp"
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
### Get FAN speed 5 times, and calculate average start ###
#---------------------------------------------------------#

#Speed up the fan.
#echo 255 > /proc/therm-fan
#sleep 3

#fans=0
#LIMIT=5
#a=1
MODELNAME=`cat /etc/modelname`

#while [ "$a" -le $LIMIT ]
#do
#	fan=`cat /proc/therm-fan  | grep measured_fan_speed | awk '{print $3}'`
#	fans=$((fans+fan))
#	let "a+=1"
#	echo "FAN1 speed $fan1">>/tmp/fan1_total
#	sleep 1
#done

#echo "Total $fans">>/tmp/fan1_total
#fans=$((fans/5))
#echo "$fans">/tmp/fan1_average
#-------------------------------------------------------#
### Get FAN speed 5 times, and calculate average end ###

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

echo "Stopped here for HTP external test!"

exit 0

