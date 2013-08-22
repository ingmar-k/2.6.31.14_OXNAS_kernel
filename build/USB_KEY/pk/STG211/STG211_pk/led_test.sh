#!/bin/sh
###################################################
#	This script is for NSA310 LED test.	  #
###################################################
#Set all LEDs green
setLED HD GREEN ON
setLED COPY GREEN ON
setLED ESATA GREEN ON
setLED USB GREEN ON
setLED SYS GREEN ON

sleep 1

#Set all LEDs red
setLED HD RED ON
setLED COPY RED ON
setLED ESATA RED ON
setLED USB RED ON
setLED SYS RED ON

sleep 1

#Set all LEDs blink in green
setLED HD GREEN BLINK
setLED COPY GREEN BLINK
setLED ESATA GREEN BLINK
setLED USB GREEN BLINK
setLED SYS GREEN BLINK

sleep 1

#Set all LEDs blink in red
setLED HD RED BLINK
setLED COPY RED BLINK
setLED ESATA RED BLINK
setLED USB RED BLINK
setLED SYS RED BLINK

sleep 1

#Set all LEDs fast blink in green
setLED HD GREEN FAST_BLINK
setLED COPY GREEN FAST_BLINK
setLED ESATA GREEN FAST_BLINK
setLED USB GREEN FAST_BLINK
setLED SYS GREEN FAST_BLINK

sleep 1

#Set all LEDs fast blink in green
setLED HD RED FAST_BLINK
setLED COPY RED FAST_BLINK
setLED ESATA RED FAST_BLINK
setLED USB RED FAST_BLINK
setLED SYS RED FAST_BLINK

sleep 1

#Set sys LED green on; the others off
setLED HD OFF
setLED COPY OFF
setLED ESATA OFF
setLED USB OFF
setLED SYS GREEN ON

