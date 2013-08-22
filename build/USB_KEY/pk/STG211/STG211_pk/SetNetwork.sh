#!/bin/sh -x

usage ()
{
	echo
	echo "Usage: `basename $0` [ { dynamic | static <IP> <MASK> <GW> } [ <DNS1> [ <DNS2> ] ] ]"
	echo "Ex: SetNetwork.sh dynamic 172.23.5.1 172.23.6.1 ==> Set dynamic IP with static DNS"
	echo "Ex: SetNetwork.sh dynamic ==> Set dynamic IP and DNS"
	echo "Update network interface configuration."
	echo
}

INTERFACE="egiga0"
IFCONFIG="ifconfig"
ROUTE="route"

RESOLV_CONF="/etc/resolv.conf"

if [ "$1" == "--help" ]; then
	usage
	exit 0
fi

case "$1" in
	"dynamic")
		if [ $# -gt 3 ]; then
			usage
		fi

		MODE="$1"

		if [ $# -eq 1 ]; then  
			DNSMODE="dynamic"
		else
			DNSMODE="static"
			PRIMARY_DNS="$2"
			SECONDARY_DNS="$3"
		fi
	;;
	"static")
		if [ $# -lt 4 -o $# -gt 6 ]; then
			usage
		fi	
		
		MODE="$1"
		DNSMODE="static"
		IP="$2"
		NETMASK="$3"
		GATEWAY="$4"
		PRIMARY_DNS="$5"
		SECONDARY_DNS="$6"
	;;
	*)#Invalid arguments
		usage
		exit 0
	;;

esac

#Kill udhcpc to make sure there exists only one udhcpc when we set it as dynmac, and no udhcpc when we set it as static.
killall -9 udhcpc

case "$MODE" in
	"dynamic")
	#Run dhcpcd
	#Set -n makes udhcpc terminate itself if fails to reach the dhcp server.
	udhcpc -i egiga0 -n -T 1 -s /usr/share/udhcpc/default.script
	;;

	"static")
		${IFCONFIG} ${INTERFACE} ${IP} netmask ${NETMASK}
		${ROUTE} del -net 0.0.0.0
		if ! ${ROUTE} add default gw ${GATEWAY}; then
			${ROUTE} add -net 0/0 ${INTERFACE}
		fi
	;;
	*)
		exit 0
	;;
esac

#regenerate  "/etc/resolv.conf"
#If DNSMODE is dynamic, the udhcpc grep the DNS and write to /etc/resolv.conf automatically.
if [ "${DNSMODE}" == "static" ]; then
	echo "###Regenerate by init_NDU with static" > ${RESOLV_CONF}
	[ -n "${PRIMARY_DNS}" ] && echo "nameserver ${PRIMARY_DNS}" >> ${RESOLV_CONF}
	[ -n "${SECONDARY_DNS}" ] && echo "nameserver ${SECONDARY_DNS}" >> ${RESOLV_CONF}		
fi


