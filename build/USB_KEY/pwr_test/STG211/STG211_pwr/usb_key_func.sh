#!/bin/sh
#----------------------------------------------
# Version Date: 2008-08-20
#----------------------------------------------

CUT="/bin/cut"
RTCACCESS="rtcAccess"
PWR_RESUME="/sbin/pwr_resume"
I2CSET="/sbin/i2cset"
SETLED="/sbin/setLED"
GREP="/bin/grep"
POWEROFF="/sbin/poweroff"

Time="00:00:00"
Year="2008"
Month="01"
Day="01"
Hour="00"
Minute="00"
Second="00"


IsRTCEnable=`${RTCACCESS} get | ${GREP} enable`
echo "Start to Run Power test..."

if [ "${IsRTCEnable}" == "" ]; then
        #RTC is OFF. Take it as the start of test.
        echo "RTC off. Start Power-On test."

        #To reduce the time of testing, set a current time we want like 10:10:30 and reboot time 10:11:00

        SettingTime="2008-08-29 10:10:40"

        #Set current time as 2008-08-29 10:10:00
        ${I2CSET} -y 0x0 0x51 0x02 0x00
        ${I2CSET} -y 0x0 0x51 0x03 0x10
	${I2CSET} -y 0x0 0x51 0x04 0x10
	${I2CSET} -y 0x0 0x51 0x05 0x29
	${I2CSET} -y 0x0 0x51 0x06 0x05
	${I2CSET} -y 0x0 0x51 0x07 0x08
	${I2CSET} -y 0x0 0x51 0x08 0x08

	CurTime=`hwclock`

	echo "Current time is ${CurTime}"
	echo "System will boot up by ${SettingTime}"

	${RTCACCESS} "${SettingTime}"

	${POWEROFF}

	else
        #RTC is ON. Take it as the Power-On test is done.

        echo "RTC on. Start Power-Resume test."
        ${RTCACCESS} disable
        ${RTCACCESS} clearAF
        ${PWR_RESUME} enable
        ${SETLED} HD RED BLINK

        echo "Power-Resume setting Done!!"
fi

