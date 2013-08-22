#!/bin/sh

if [ $# -ne 0 ]; then
	MODEL=$1
fi
pushd ../../ >/dev/null 2>&1
export PRODUCT_ROOT=`pwd`
popd >/dev/null 2>&1

export BUILD_RAS_PATH=${PRODUCT_ROOT}/build
export SYSAPPS_PATH=${PRODUCT_ROOT}/sysapps
export MD5_KEY=${PRODUCT_ROOT}/build/fs.initrd/etc/Zy_Private
export USB_KEY_ROOT=${PRODUCT_ROOT}/build/USB_KEY

export COMMON_PATH=${USB_KEY_ROOT}/common_script/${MODEL}
export PK_KEY_PATH=${USB_KEY_ROOT}/pk/${MODEL}/${MODEL}_pk
export FQC_KEY_PATH=${USB_KEY_ROOT}/fqc/${MODEL}/${MODEL}_fqc
export FWKEY_KEY_PATH=${USB_KEY_ROOT}/fwkey/${MODEL}/${MODEL}_fwkey

export PWR_TEST_KEY_PATH=${USB_KEY_ROOT}/pwr_test/${MODEL}/${MODEL}_pwr
export UPGRADE_KEY_PATH=${USB_KEY_ROOT}/upgrade/${MODEL}/${MODEL}_fw


echo "Make USB Keys"

echo "==== Make PK Test Key ===="
### Create MD5
cat ${MD5_KEY} ${PK_KEY_PATH}/usb_key_func.sh | md5sum > ${PK_KEY_PATH}/run_htp_external
cp ${COMMON_PATH}/SetNetwork.sh ${PK_KEY_PATH}/
cp ${COMMON_PATH}/storage_test.sh ${PK_KEY_PATH}/
cp ${COMMON_PATH}/led_test.sh ${PK_KEY_PATH}/
cp ${COMMON_PATH}/kernelcheck ${PK_KEY_PATH}/

echo "==== Make FQC Test Key ===="
### Create MD5
cat ${MD5_KEY} ${FQC_KEY_PATH}/usb_key_func.sh | md5sum > ${FQC_KEY_PATH}/run_htp_external
cp ${COMMON_PATH}/SetNetwork.sh ${FQC_KEY_PATH}/
cp ${COMMON_PATH}/storage_test.sh ${FQC_KEY_PATH}/
cp ${COMMON_PATH}/led_test.sh ${FQC_KEY_PATH}/
cp ${COMMON_PATH}/kernelcheck ${FQC_KEY_PATH}/

echo "==== Make FWKEY Test Key ===="
### Create MD5
cat ${MD5_KEY} ${FWKEY_KEY_PATH}/usb_key_func.sh | md5sum > ${FWKEY_KEY_PATH}/run_htp_external
cp ${COMMON_PATH}/SetNetwork.sh ${FWKEY_KEY_PATH}/
cp ${COMMON_PATH}/storage_test.sh ${FWKEY_KEY_PATH}/
cp ${COMMON_PATH}/led_test.sh ${FWKEY_KEY_PATH}/
cp ${COMMON_PATH}/kernelcheck ${FWKEY_KEY_PATH}/


echo "==== Make Power Function Checking key ===="
### Create MD5
#cp ${BUILD_RAS_PATH}/fs/sbin/md5sum  ${PWR_FUNC_KEY_PATH}/../
#cp ${BUILD_RAS_PATH}/fs/sbin/setLED ${PWR_FUNC_KEY_PATH}/
#cp ${BUILD_RAS_PATH}/fs/usr/bin/rtcAccess ${PWR_FUNC_KEY_PATH}/
#cp ${BUILD_RAS_PATH}/fs/sbin/pwr_resume ${PWR_FUNC_KEY_PATH}/
#cp ${BUILD_RAS_PATH}/fs/sbin/i2cset ${PWR_FUNC_KEY_PATH}/
cat ${MD5_KEY} ${PWR_TEST_KEY_PATH}/usb_key_func.sh | md5sum > ${PWR_TEST_KEY_PATH}/pwr_test

echo "==== Make Upgrade  key ===="
#cd ${UPGRADE_KEY_PATH}
#rm -f upgrade_key_image.tar.gz
#cp -p -f   ${BUILD_RAS_PATH}/ras.bin ${BUILD_RAS_PATH}/fs/usr/sbin/ram2bin ${BUILD_RAS_PATH}/fs/usr/sbin/fw_unpack  ${BUILD_RAS_PATH}/fs/usr/sbin/bin2ram  ${BUILD_RAS_PATH}/fs/sbin/flashcp  .
#tar czvf upgrade_key_image.tar.gz ras.bin ram2bin fw_unpack bin2ram flashcp
#rm -f ras.bin ram2bin fw_unpack bin2ram flashcp

#cat ${MD5_KEY} ${UPGRADE_KEY_PATH}/usb_key_func.sh ${UPGRADE_KEY_PATH}/upgrade_key_image.tar.gz  | md5sum > ${UPGRADE_KEY_PATH}/upgrade_func

echo "==== Done ===="
