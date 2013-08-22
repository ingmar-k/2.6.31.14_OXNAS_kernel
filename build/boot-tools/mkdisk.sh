#!/bin/sh

if [ -z $1 ]; then
	echo "Example: $0 /dev/sdb"
	exit 0
fi


CMD_PARTED=`which parted 2>/dev/null`
CMD_PARTED=${CMD_PARTED:=/sbin/parted}

CMD_MKFS_EXT3=`which mkfs.ext3 2>/dev/null`
CMD_MKFS_EXT3=${CMD_MKFS_EXT3:=/sbin/mkfs.ext3}

CMD_MKFS_NTFS=`which mkfs.ntfs 2>/dev/null`
CMD_MKFS_NTFS=${CMD_MKFS_NTFS:=/sbin/mkfs.ntfs}

CMD_MKSWAP=`which mkswap 2>/dev/null`
CMD_MKSWAP=${CMD_MKSWAP:=/sbin/mkswap}


check_size()
{
	local disk=`basename $1`

	# Minimum disk size is ~4GB; 3800 * 1024 * 1024 bytes = 7782400 blocks.
	MIN_BLOCKS=7782400

	BLOCKS=`cat /sys/block/$disk/size`

	if [ -z ${BLOCKS} ]; then
		echo "Can not recognize the disk size of $disk."
		exit 1
	fi

	if [ ${BLOCKS} -lt ${MIN_BLOCKS} ]; then
		echo "The size of $disk is too small; at least 4GB is required."
		exit 1
	fi
}

create_partitions()
{
	local disk=$1
	dd if=/dev/zero of=$1 bs=1M count=32

#	parted $1 mklabel msdos

	# 1st, 32MB, cylinder 4~7, etc/zyxel/conf
	echo -e "n\np\n1\n4\n7\nw\n" | fdisk $1

	# 2nd, 32MB, cylinder 8~11, etc/zyxel/conf
	echo -e "n\np\n2\n8\n11\nw\n" | fdisk $1

	# 3rd, 512MB, cylinder 12~75, System
	echo -e "n\np\n3\n12\n75\nw\n" | fdisk $1

	# Win95 extended partition(LBA-mapped), ID = 0xf, cylinder 76~end
	echo -e "n\ne\n76\n\nt\n4\nf\nw\n" | fdisk $1

	# 5th, 512MB, cylinder 76~139, SWAP
	echo -e "n\n76\n139\nt\n5\n82\nw\n" | fdisk $1

	# 4th, cylinder 140~end, NTFS
	echo -e "n\n140\n\nt\n6\n7\nw\n" | fdisk $1
}

write_bootrom_directions()
{
	local disk=$1

	# ymtseng.20100720:
	#
	# Format of the following hex data (from Oxford):
	#   2nd checksum (location + length)
	#   2nd stage1.wrapped location in sectors(blocks)
	#   2nd length of stage1.wrapped in sectors(blocks), (minus half a sector due to boot ROM bug)
	#   1st checksum (location + length)
	#   1st stage1.wrapped location in sectors(blocks)
	#   1st length of stage1.wrapped in sectors(blocks), (minus half a sector due to boot ROM bug)
	#
	# My explanation of the format:
	#   2nd checksum (location of stage1 in block + length of stage1 in byte; the sum of the following 2 numbers)
	#   2nd stage1.wrapped location in blocks.
	#   2nd length of stage1.wrapped in bytes.
	#   1st checksum (location of stage1 in block + length of stage1 in byte; the sum of the following 2 numbers)
	#   1st stage1.wrapped location in blocks.
	#   1st length of stage1.wrapped in bytes.
	#
	# Example:
	#   \x22\x03\x00\x00 --> 0x322 = 802 == 34 + 768 == 0x22 + 0x300
	#   \x22\x00\x00\x00 --> 0x22 == block 34.
	#   \x00\x03\x00\x00 --> 0x300 == 768 bytes == 1.5 blocks == size of stage1.wrapped.

	perl <<EOF | dd of="$disk" bs=512
		print "\x00" x 0x1a4;
		print "\x00\xe2\x00\x00";
		print "\x00\xdf\x00\x00";
		print "\x00\x03\x00\x00";
		print "\x00" x (0x1b0 -0x1a4 -12 );
		print "\x22\x03\x00\x00";
		print "\x22\x00\x00\x00";
		print "\x00\x03\x00\x00";
EOF
}

write_hidden_sectors()
{
	local disk=$1

	dd if=stage1.wrapped of="$disk" bs=512 seek=34
	dd if=u-boot.wrapped of="$disk" bs=512 seek=36
	dd if=uImage         of="$disk" bs=512 seek=290		# uImage needs 20480 blocks (10MB)
#	dd if=uImage.1       of="$disk" bs=512 seek=8482
#	dd if=uUpgradeRootfs of="$disk" bs=512 seek=16674
#	dd if=stage1.wrapped of="$disk" bs=512 seek=57088
#	dd if=u-boot.wrapped of="$disk" bs=512 seek=57090
#	dd if=uImage         of="$disk" bs=512 seek=57344

}

format_partitions()
{
	local disk=$1

	$CMD_MKFS_EXT3		${disk}1
	$CMD_MKFS_EXT3		${disk}2
	$CMD_MKFS_EXT3		${disk}3
	$CMD_MKSWAP		${disk}5
	$CMD_MKFS_NTFS -f	${disk}6

}

check_size $1
create_partitions $1
write_bootrom_directions $1
write_hidden_sectors $1
format_partitions $1

exit 0

