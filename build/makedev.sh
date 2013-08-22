#!/bin/sh



if [ x$1 == "x" ]; then
	echo ""
	echo "Usage:   makedev ROOTDIR"
	echo ""
	echo "  ROOTDIR is the directory of root FS, please use full path."
	echo ""
	exit 0
fi

rm -rf $1/dev/*
cd $1/dev/

DEVINDEX=(a b c d e f g h i j k l m n o p q r s t u v w x y z)
NODEINDEX=(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
M_NUM=8
N_NUM=0
DEVNODE=sd
TYPE=b

major=${M_NUM}
minor=${N_NUM}

for i in ${DEVINDEX[@]} ; do
	mknod -m 660 ${DEVNODE}${i} ${TYPE} ${major} ${minor}
	let minor=minor+1

	for j in ${NODEINDEX[@]}; do
		mknod -m 660 ${DEVNODE}${i}${j} ${TYPE} ${major} ${minor}
		let minor=minor+1
	done

	if [ $minor -gt 255 ]; then
		let major=65
		let minor=0
	fi
done


mknod -m 600 mem	c 1 1
mknod -m 666 null	c 1 3
mknod -m 666 zero	c 1 5
mknod -m 666 full	c 1 7
mknod -m 644 random	c 1 8
mknod -m 444 urandom	c 1 9
mknod -m 600 tty0	c 4 0
mknod -m 600 tty1	c 4 1
mknod -m 600 tty2	c 4 2
mknod -m 600 tty3	c 4 3
mknod -m 600 tty4	c 4 4
mknod -m 600 tty5	c 4 5
mknod -m 600 ttys0	c 3 48
mknod -m 600 ttyS0	c 4 64
mknod -m 600 ttys1	c 3 49
mknod -m 600 ttyS1	c 4 65
mknod -m 600 ttys2	c 3 50
mknod -m 600 ttyS2	c 4 66
mknod -m 666 tty	c 5 0
mknod -m 600 console	c 5 1
mknod -m 755 ram0	b 1 0
mknod -m 755 ram1	b 1 1
mknod -m 755 ram2	b 1 2
mknod -m 755 ram3	b 1 3
mknod -m 755 ram4	b 1 4
mknod -m 660 loop0	b 7 0
mknod -m 660 loop1	b 7 1
mknod -m 660 loop2	b 7 2
mknod -m 660 loop3	b 7 3
mknod -m 644 crypto	c 10 70
mknod -m 644 cesa	c 10 71
if [ $MODEL == NSA310 ]; then
	mknod -m 660 rtc	c 10 135
else
	mknod -m 660 rtc        c 254 0
fi

for i in $(seq 0 8)
do
mknod mtd$i c 90 $(expr $i + $i)
mknod mtdblock$i b 31 $i
done



mknod md0 b 9 0
mknod md1 b 9 1
mknod md2 b 9 2
mknod md3 b 9 3
mknod md4 b 9 4

mknod sg0 c 21 0
mknod sg1 c 21 1
mknod sg2 c 21 2
mknod sg3 c 21 3
mknod sg4 c 21 4
mknod sg5 c 21 5
mknod sg6 c 21 6
mknod sg7 c 21 7
mknod sg8 c 21 8
mknod sg9 c 21 9
mknod sg10 c 21 10
mknod sg11 c 21 11
mknod sg12 c 21 12
mknod sg13 c 21 13
mknod sg14 c 21 14
mknod sg15 c 21 15

mknod sr0 b 11 0
mknod sr1 b 11 1
mknod sr2 b 11 2
mknod sr3 b 11 3
mknod sr4 b 11 4
mknod sr5 b 11 5
mknod sr6 b 11 6
mknod sr7 b 11 7
mknod sr8 b 11 8
mknod sr9 b 11 9
mknod sr10 b 11 10
mknod sr11 b 11 11
mknod sr12 b 11 12
mknod sr13 b 11 13
mknod sr14 b 11 14
mknod sr15 b 11 15

mknod -m 666 ptmx	c 5 2

mknod ppp c 108 0

mknod fuse c 10 229

mkdir shm

#i2c
I2C_INDEX=(0 1 2)
for i in ${I2C_INDEX[@]}; do
	mknod -m 600 i2c$i c 89 $i
	mknod -m 600 i2c-$i c 89 $i
done

#1394
mknod -m 600 raw1394 c 171 0

#for sshd, added by Joseph Wang 2008-2-28
mknod ptyp0 c 2 0
mknod ptyp1 c 2 1
mknod ptyp2 c 2 2
mknod ttyp0 c 3 0
mknod ttyp1 c 3 1
mknod ttyp2 c 3 2

#pts
mkdir pts; cd pts
mknod -m 640 0		c 136 0
mknod -m 640 1		c 136 1
mknod -m 640 2		c 136 2
mknod -m 640 3		c 136 3
mknod -m 640 4		c 136 4
mknod -m 640 5		c 136 5
cd ..

#printer. Add by Elaine Lin 2007-6-22
mkdir usb; chmod 0777 usb; cd usb
mknod -m 666 lp0        c 180 0
mknod -m 666 lp1        c 180 1
mknod -m 666 lp2        c 180 2
mknod -m 666 lp3        c 180 3
mknod -m 666 lp4        c 180 4
mknod -m 666 lp5        c 180 5
mknod -m 666 lp6        c 180 6
mknod -m 666 lp7        c 180 7
mknod -m 666 lp8        c 180 8
mknod -m 666 lp9        c 180 9
mknod -m 666 lp10       c 180 10
mknod -m 666 lp11       c 180 11
mknod -m 666 lp12       c 180 12
mknod -m 666 lp13       c 180 13
mknod -m 666 lp14       c 180 14

mknod hiddev0 	c 180 96
cd ..



cd ../../

exit 0
