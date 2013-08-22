#!/bin/sh

echo "Doing pre-install ..." > /dev/console

# yaffs2 --> sda1

if [ -f /mnt/ram1/DATA_a004 ]; then
	sh /mnt/ram1/DATA_a004
fi

echo " ... pre-install finishes!" > /dev/console
exit 0

