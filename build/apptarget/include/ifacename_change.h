/* $Id: */

/*
 * $Log:
 */

#ifndef _K_IFACENAME_CHANGE_H_
#define _K_IFACENAME_CHANGE_H_
#ifdef __KERNEL__

#include <linux/if.h>

#define K_INTERFACE_CONVERT_FAIL 1

#if 0
/*use in ioctl*/
enum ifacename_change_action_ioctl {
	IFACENAME_CHANGE_ACTION_IOCTL_WRITE = 1,
	IFACENAME_CHANGE_ACTION_IOCTL_READ
};
#endif
int k_eth_to_user_define (char *iface, char *ud_iface);/*eth convert to user define*/
int k_user_define_to_eth (char *ud_iface, char *iface);/*user define convert to eth*/
#endif /* __KERNEL__ */

#ifndef IFNAMSIZ
#define MAX_IFACE_NAME_LEN 16
#else
#define MAX_IFACE_NAME_LEN IFNAMSIZ
#endif

#ifndef MAX_ETH
#define MAX_ETH 5
#endif

#ifndef PER_IFACE_VIR_NUM //vir case
#define PER_IFACE_VIR_NUM 4 //vir case
#endif

#ifndef	MAX_VIR_ETH
#define MAX_VIR_ETH MAX_ETH*PER_IFACE_VIR_NUM //vir case
#endif

#define EXTERNAL_ETH_IFACENAME "ge"
#define INTERNAL_ETH_IFACENAME "egiga"


/* wireless LAN */
#ifndef MAX_WLAN
#define MAX_WLAN 1
#endif
#define EXTERNAL_WLAN_IFACENAME "wlan"
#define INTERNAL_WLAN_IFACENAME "ra"

/*base structure*/
typedef struct k_interface {
	char ifacename[MAX_IFACE_NAME_LEN];
	char external_name[MAX_IFACE_NAME_LEN];
} k_interface_t;

#endif /* !(_K_IFACENAME_CHANGE_H_) */
