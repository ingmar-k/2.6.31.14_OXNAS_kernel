#!/bin/sh

CONF_TGZ=zyconf.tgz
CONF_ROM=zyconf.rom

METADATA=fw.txt
ROMBIN_HEADER_VER="1.1"

if [ -e $CONF_TGZ ]
then
	echo
	echo "*** ATTENTION! $CONF_TGZ already exists ***"
elif [ -d fs.initrd/etc/zyxel ] 
then
	cd fs.initrd/etc/zyxel
	tar -zcvf ../../../$CONF_TGZ .
	cd ../../../
else
	echo "*** Directory fs.initrd/etc/zyxel doesn't exist, cannot create $CONF_TGZ ***"
	exit 1
fi

# get model id from fw.txt
MODEL_ID=`grep "^MODEL1" $METADATA | awk -F" " '{print $3}'`
echo "MODEL ID is $MODEL_ID"
echo "ROMBIN Header Version is $ROMBIN_HEADER_VER"

# type 9 means ROM file
CHECKSUM=`./ram2bin -i $CONF_TGZ -o $CONF_ROM -e $ROMBIN_HEADER_VER -t 9 -q -m $MODEL_ID`

# Update RomChecksum to mmct.tab
sed -i -e "s/^ROM_CHECKSUM.*/ROM_CHECKSUM\tvalue\t`echo $CHECKSUM`/g" ${METADATA}

if [ $? -ge 0 ]; then
	echo "File $CONF_ROM is created successfully."
else
	echo "*** Fail to create $CONF_ROM ***"
	exit 1
fi

