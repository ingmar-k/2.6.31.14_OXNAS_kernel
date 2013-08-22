#!/bin/sh

# Update CORE_CHECKSUM in ${METADATA}
CORECHECKSUM=`md5sum uImage | awk '{print $1}'`
sed -i -e "s/^CORE_CHECKSUM.*/CORE_CHECKSUM\tvalue\t`echo $CORECHECKSUM`/g" ${METADATA}

