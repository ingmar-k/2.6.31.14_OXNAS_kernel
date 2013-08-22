#!/bin/sh
###################################################
#	This script is for NSA310 LED test.	  #
###################################################
#Set all LEDs green
setLED COPY GREEN ON
setLED SYS BLUE ON

sleep 1

#Set all LEDs red
setLED SYS RED ON

sleep 1

#Set all LEDs fast blink in green
setLED COPY GREEN FAST_BLINK
setLED SYS BLUE FAST_BLINK

sleep 1

#Set all LEDs fast blink in green
setLED SYS RED FAST_BLINK

sleep 1

#Set sys LED green on; the others off
setLED COPY OFF
setLED SYS BLUE ON

