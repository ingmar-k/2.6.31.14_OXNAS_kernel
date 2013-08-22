#!/bin/bash -x

INPUT=$*
export VER=$INPUT
export REVnum=`svn info ./makeras.sh | /bin/grep Revision | awk -F" " '{print $2}'`
export REV="Rev."$REVnum
export DATE=`date +%F_%H_%M_%S`

# default
export PRODUCT_METADATA=fw.stg100.txt
export METADATA=fw.txt

# default version
export MODELNAME="STG100"
export FWID="UAD.0"

Usage ()
{
	echo ""
        echo "Usage: $0 [-b <BETA_VERSION>] [-c <FCS_VERSION>] [-k <KERNEL_VERSION>] [-f <ROOTFS TYPE>] [-m <MODEL NAME>]"
        echo ""
        echo "  -b       Beta version. Default is \"${vBETA}\""
	echo ""
        echo "  -c       FCS version. Default is \"${vFCS}\""
	echo ""
	echo "  -k       KERNEL version. Default is \"${vKERNEL}\""
	echo ""
	echo "  -f	 ROOTFS type. Default is \"${tROOTFS}\""
	echo "  		support squash and ext2"
	echo "  -m	 Model name. Default is \"${MODELNAME}\""
	echo ""
}


Usage

while getopts "b:c:k:f:m:" opt; do
	case $opt in
	b )
	if [ x"$OPTARG" != x"" ]; then
		export vBETA=$OPTARG
	fi
	;;
	c )
	if [ y"$OPTARG" != y"" ]; then
		export vFCS=$OPTARG
	fi
	;;
	k)
		export vKERNEL=$OPTARG
	;;
	f)
		export tROOTFS=$OPTARG
	;;
	m)
		export MODELNAME=$OPTARG
	;;
	esac
done
shift $(($OPTIND - 1))

if [ "$MODELNAME" == "STG100" ]; then
	export FWID="UAD.0"
	export PRODUCT_METADATA=fw.stg100.txt
elif [ "$MODELNAME" == "STG211" ]; then
	export FWID="UAF.0"
	export PRODUCT_METADATA=fw.stg211.txt
elif [ "$MODELNAME" == "STG212" ]; then
	export FWID="UZD.0"
	export PRODUCT_METADATA=fw.stg212.txt
else
	echo "No Support Model"
	exit 255
fi

EXAMPLE="V1.00(${FWID})b1"

# default version
export vBETA="V"$DATE"(${FWID})b1"
export vFCS="V"$DATE"(${FWID})C0"
export vKERNEL="2.6.31.6"
export tROOTFS="squash"

echo "Beta version is \"${vBETA}\""
echo "FCS version is \"${vFCS}\""
echo "KERNEL version is \"${vKERNEL}\""

# Copy PRODUCT_METADATA to METADATA
cp -f ${PRODUCT_METADATA} ${METADATA}


# output file
fBETA=${vBETA}.bin
fFCS=${vFCS}.bin


# Create BETA version file
# Use Beta firmware version in {METADATA}
sed -i -e "s/^VERSION.*/VERSION\t\tvalue\t`echo $vBETA`/g" ${METADATA}

# Update revision number into ${METADATA}
sed -i -e "s/^REVISION.*/REVISION\tvalue\t`echo $REVnum`/g" ${METADATA}

# Update Model ID to build/fs/usr/etc/modelid
MODEL_ID=`grep MODEL1 ${METADATA} | awk -F" " '{print $3}'`

# Updates ROM_CHECKSUM in {METADATA}, generate romfile_checksum, zyconf.tgz and zyconf.rom
./make_zyconf.sh

# Updates CORE_CHECKSUM in ${METADATA}, generate core_checksum
./make_kernel.sh

# Update ZLD_CHECKSUM in ${METADATA}, generate sysdisk.img.gz and zld_checksum
./make_sysdisk.sh

# Update INITRD_CHECKSUM in ${METADATA}, generate initrd.img.gz and initrd_checksum
./make_initrd.sh

# pack firmware with BETA version
./fw_pack -r ${METADATA} -o tlv.bin
./ram2bin -i tlv.bin -o ras.bin -e "${MODELNAME}" -t 4
mv ras.bin ${fBETA}
chmod 644 ${fBETA}

echo " ==> Beta version file ${fBETA} is created. --> ${vBETA}"





# Create FCS version file
# Use FCS firmware version in METADATA
sed -i -e "s/^VERSION.*/VERSION\t\tvalue\t`echo $vFCS`/g" ${METADATA}

# pack firmware with FCS version
# tools comes from sysapps/Fw_Header
./fw_pack -r ${METADATA} -o tlv.bin
./ram2bin -i tlv.bin -o ras.bin -e "${MODELNAME}" -t 4
mv ras.bin ${fFCS}
chmod 644 ${fFCS}

echo " ==> FCS version file ${fFCS} is created. --> ${vFCS}"




mkdir -p ./final_images
# backup Init RD (gzip ext2) image
cp -f ./initrd.img.gz ./final_images
# backup kernel image (u-Image format)
cp -f ./uImage ./final_images
# backup final released ras image
cp -f ${fBETA} ./final_images
# rename BETA.bin to ras.bin
mv -f ${fBETA} ./ras.bin
# backup final released ras image
mv -f ${fFCS} ./final_images
# backup default config file
mv -f ./zyconf.tgz ./final_images
# bakcup default config file with rombin header(header including romfile checksum)
mv -f ./zyconf.rom ./final_images


echo ""
echo "All necessary files are copied to directory 'final_images' for release."
echo ""
echo "Model ID -->" `grep "^MODEL1" ${METADATA} | awk -F" " '{print $3}'`
echo "Core Checksum -->" `grep "^CORE_CHECKSUM" ${METADATA} | awk -F" " '{print $3}'`
echo "InitRD Checksum -->" `grep "^INITRD_CHECKSUM" ${METADATA} | awk -F" " '{print $3}'`
echo "ZLD Checksum -->" `grep "^ZLD_CHECKSUM" ${METADATA} | awk -F" " '{print $3}'`
echo "ROM Checksum -->" `grep "^ROM_CHECKSUM" ${METADATA} | awk -F" " '{print $3}'`
echo ""
echo "Revision -->" `grep "^REVISION" ${METADATA} | awk -F" " '{print $3}'`
echo "Beta version file is ${fBETA} --> ${vBETA}"
echo "FCS version file is ${fFCS} --> ${vFCS}"
echo ""

