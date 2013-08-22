#!/bin/sh

# This script creates 2 files.
# 1. ramdisk.tar.gz: contains /bin /sbin /etc /var /tmp /lib, for RAM disk.
# 2. fs.tar.gz: generally contains /usr and ramdisk.tar.gz; for NAND flash.

#TMPDIR=`/bin/mktemp -d -q ./fs.XXXXXX`

#if [ $? -ne 0 ]; then
#	echo "Can't create temp dir $TMPDIR, exiting..."
#	exit 1
#fi

OUTPUT_FILE="sysdisk.img.gz"

echo "Create sysdisk.img.gz ..."
echo -e " \033[1;31m>> Enter Critcal Section! DO NOT CTRL+C <<\033[0m"

# create tmp.tar.gz for extracting to ramdisk
echo -n " ==> create tmp.tar.gz ..."
cd fs; tar zcf tmp.tar.gz tmp; cd ..
echo " done"

# fs/* -> sysdisk.tar.gz
rm -rf sysdisk.tar.gz
rm -rf sysdisk
mv fs sysdisk
cd sysdisk; tar zcf ../sysdisk.tar.gz * .mtoolsrc ; cd ..
mv sysdisk fs

# dd ext2 image
SYSDISK_SIZE=`du -sm fs | awk '{print $1}'`
SYSDISK_SIZE=$(($SYSDISK_SIZE+3))
dd if=/dev/zero of=sysdisk.img bs=1M count=${SYSDISK_SIZE}
/sbin/mkfs.ext2 -F -v -m0 sysdisk.img
mkdir -p sysdisk
sudo mount -o loop sysdisk.img sysdisk/
tar zxf sysdisk.tar.gz -C sysdisk/
sudo umount sysdisk/

echo -e " \033[1;32m<< Exit Critcal Section! >>\033[0m"

IMG_CHECKSUM=`md5sum sysdisk.img | awk '{print $1}'`

gzip -9 < sysdisk.img > sysdisk.img.gz

IMG_GZ_CHECKSUM=`md5sum sysdisk.img.gz | awk '{print $1}'`

rm -rf sysdisk/
rm -rf sysdisk.tar.gz
#rm -rf sysdisk.img

# ZLD_CHECKSUM in fw.txt : sysdisk.img.gz
# IMG_CHECKSUM in fw.txt : sysdisk.img
sed -i -e "s/^ZLD_CHECKSUM.*/ZLD_CHECKSUM\tvalue\t`echo ${IMG_GZ_CHECKSUM}`/g" ${METADATA}
sed -i -e "s/^IMG_CHECKSUM.*/IMG_CHECKSUM\tvalue\t`echo ${IMG_CHECKSUM}`/g" ${METADATA}


