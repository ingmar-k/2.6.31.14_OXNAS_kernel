#!/bin/sh

if [ -f ARM/header.bin ] && [ -f u-boot.bin ]; then
	cat ARM/header.bin > u-boot.wrapped
	cat u-boot.bin >> u-boot.wrapped
	src/update_header u-boot.wrapped
fi

exit 0
