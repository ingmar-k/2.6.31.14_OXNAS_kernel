#!/bin/sh
#########################################################################
#  This script is used to perform eSATA, SATA, USB test on NSA310.	#
#########################################################################

SG_MAP="/bin/sg_map"

InternalDisk=`${SG_MAP} -x -i | grep " 0 0 0 0"`
if [ "${InternalDisk}" == "" ]; then
	InternalDisk="fail"
else
	InternalDisk="OK"
fi

MODELNAME=`cat /etc/modelname`

if [ "${MODELNAME}" == "STG211" ]; then
	echo "Internal disk test........${InternalDisk}"
fi
sleep 1

ExternalDisk=`${SG_MAP} -x -i | grep " 1 0 0 0"`
if [ "${ExternalDisk}" == "" ]; then
	ExternalDisk="fail"
else
	ExternalDisk="OK"
fi

sleep 1

if [ "${MODELNAME}" == "STG211" ]; then
	echo "External disk test........${ExternalDisk}"
fi

if [ "${MODELNAME}" == "STG211" ]; then	
	USB_NUM="2"
fi

USB_TEST=`${SG_MAP} -x -i | grep -v " 0 0 0 0" | grep -v " -1 -1 -1 -1" | grep -v " Generic"| grep -c -v " 1 0 0 0"`
if [ "${USB_TEST}" == "${USB_NUM}" ]; then
	USB_TEST="OK"
else
	USB_TEST="fail"
	check_front_usb=`ls /sys/devices/platform/oxnas-ehci.0/usb1/1-2/1-2.3/1-2.3:1.0/host*|grep target|sed -e 's/target\([0-9]*\)\:\([0-9]\)\:\([0-9]\)/\1 \2 \3/g'`
	if [ "${check_front_usb}" == "" ]; then
		echo "Fail to detect front USB"
	fi

	check_rear_usb=`ls /sys/devices/platform/oxnas-ehci.0/usb1/1-1/1-1:1.0/host*|grep target|sed -e 's/target\([0-9]*\)\:\([0-9]\)\:\([0-9]\)/\1 \2 \3/g'`
	if [ "${check_rear_usb}" == "" ]; then
		echo "Fail to detect rear USB"
	fi
	
fi

echo "USB test..................${USB_TEST}"


SD_Card_dev=`sg_map -x -i | grep "Generic   STORAGE DEVICE    0206" | awk '{print $7}' | cut -d"/" -f3`
Size=`cat /sys/block/${SD_Card_dev}/size`
if [ ${Size} -eq 0 ]; then
	SD_Card_test="fail"
else
	SD_Card_test="OK"
fi

echo "SD Card test.............${SD_Card_test}"

