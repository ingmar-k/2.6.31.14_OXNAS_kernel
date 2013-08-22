#!/bin/sh

# Purpose: build zyfw related file for on-line fw upgrade feature
# Step1: Collect firmware file from final_images/${1}
# Step2: Generate checksum, FW version to zyfw_info
# Step3: Generate pdf
# Step4: Pack FW_INFO.tgz
# Step5: Put generated file in folder zyfw/build/

if [ $# -ne 2 ]; then
	echo "Usage: ${0} fw_filename_without_.bin modelname"
	echo "Example: (assume fw file is in final_images/330AFK0b1p1)"
	echo "	${0} 330AFK0b1p1 NSA310"
	exit -1
fi

#FOLDERNAME="nsa310.firmware.${DATE}n"
#FW_NAME="nsa310.ras.bin.${DATE}n"
FW_REVISION="`cat fw.txt  | grep ^REVISION  | awk '{print $3}'`"
FW_VERSION="`cat fw.txt | grep ^VERSION | awk '{print $3}'`"
FW_NAME=${1}
FW_FN=${1}.bin
PDF_FN=${1}.pdf
FW_FILE=final_images/${FW_FN}
MODEL_NAME=${2}
mkdir -p zyfw/build

cp ${FW_FILE} zyfw/

cd zyfw
# create zyfw_info
echo "Model: ${MODEL_NAME}"              > zyfw_info
echo "FW file: ${FW_NAME}.bin"          >> zyfw_info
echo "FW version: ${FW_VERSION}"        >> zyfw_info
echo "Revision: ${FW_REVISION}"         >> zyfw_info
echo "Release date: `date +%Y-%m-%d`"   >> zyfw_info
echo "Release note: ${PDF_FN}"     >> zyfw_info
echo "Size: `du -b ${FW_FN} | awk '{print $1}'`" >> zyfw_info
echo "Checksum: `md5sum ${FW_FN} | awk '{print $1}'`" >> zyfw_info

# generate FW_INFO.tgz (release note is fake empty file now)
cp normal.pdf ${1}.pdf
tar zcvf FW_INFO.tgz zyfw_info ${FW_NAME}.pdf
cd ..
rm -f zyfw/build/*
mv zyfw/${FW_FN} zyfw/FW_INFO.tgz zyfw/build/
exit 0
