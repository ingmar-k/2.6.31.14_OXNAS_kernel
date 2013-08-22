/*********************************************************************************
 * Filename:  iscsi_auth_kernel.h
 *
 * Copyright (c) 2003-2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007-2009 Linux-iSCSI.org
 * 
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef ISCSI_AUTH_KERNEL_H
#define ISCSI_AUTH_KERNEL_H

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <target/target_core_base.h>

#include <iscsi_auth.h>
#include <iscsi_auth_chap.h>

extern iscsi_global_t *iscsi_global;

extern void convert_null_to_semi(char *buf, int len)
{
        int i;

        for (i = 0; i < len; i++)
                if (buf[i] == '\0')
                        buf[i] = ';';
}

extern int strlen_semi(char *buf)
{
        int i = 0;

        while (buf[i] != '\0') {
		if (buf[i] == ';')
			return i;
		i++;
        }
         
        return -1;
}

extern int extract_param(
	const char *in_buf,
	const char *pattern,
	unsigned int max_length,
	char *out_buf,
	unsigned char *type)
{
	char *ptr;
	int len;

	if (!in_buf || !pattern || !out_buf || !type)
		return -1;

	ptr = strstr(in_buf, pattern);
	if (!ptr)
		return -1;

	ptr = strstr(ptr, "=");
	if (!ptr)
	return -1;

	ptr += 1;
	if (*ptr== '0' && (*(ptr+1) == 'x' || *(ptr+1) == 'X')) {
		ptr += 2; /* skip 0x */
		*type = HEX;
	} else
		*type = DECIMAL;

	len = strlen_semi(ptr);
	if (len < 0)
		return -1;

	if (len > max_length) {
		printk(KERN_ERR "Length of input: %d exeeds max_length:"
			" %d\n", len, max_length);
		return -1;
	}
	memcpy(out_buf, ptr, len);
	out_buf[len] = '\0';

        return 0;
}


/*	iscsi_handle_authetication():
 *
 *
 */
extern u32 iscsi_handle_authentication (
	iscsi_conn_t *conn,
	char *in_buf,
	char *out_buf,
	int in_length,
	int *out_length,
	unsigned char *authtype,
	int role)
{
	iscsi_session_t *sess = SESS(conn);
	iscsi_node_auth_t *auth;
	iscsi_node_acl_t *iscsi_nacl;
	se_node_acl_t *se_nacl;

	if (!(SESS_OPS(sess)->SessionType)) {
		/*
		 * For SessionType=Normal
		 */
		se_nacl = SESS(conn)->se_sess->se_node_acl;
		if (!(se_nacl)) {
			printk(KERN_ERR "Unable to locate se_node_acl_t for"
					" CHAP auth\n");
			return -1;
		}
		iscsi_nacl = container_of(se_nacl, struct iscsi_node_acl_s,
					se_node_acl);
		if (!(iscsi_nacl)) {
			printk(KERN_ERR "Unable to locate iscsi_node_acl_t for"
					" CHAP auth\n");
			return -1;
		}

		auth = ISCSI_NODE_AUTH(iscsi_nacl);
	} else {
		/*
		 * For SessionType=Discovery
		 */
		auth = &iscsi_global->discovery_auth;	
	}

#ifdef SNMP_SUPPORT
	if (strstr("CHAP", authtype))
		strcpy(SESS(conn)->auth_type, "CHAP");
	else
		strcpy(SESS(conn)->auth_type, NONE);
#endif /* SNMP_SUPPORT */

	if (strstr("None", authtype))
		return 1;
#ifdef CANSRP
	else if (strstr("SRP", authtype))
		return srp_main_loop(conn, auth, role, in_buf, out_buf,
				&in_length, out_length);
#endif
	else if (strstr("CHAP", authtype))
		return chap_main_loop(conn, auth, in_buf, out_buf,
				&in_length, out_length);
	else if (strstr("SPKM1", authtype))
		return 2;
	else if (strstr("SPKM2", authtype))
		return 2;
	else if (strstr("KRB5", authtype))
		return 2;
	else
		return 2;
}

/*	iscsi_remove_failed_auth_entry():
 *
 *
 */
extern void iscsi_remove_failed_auth_entry (
	iscsi_conn_t *conn,
	int role)
{
	kfree(conn->auth_protocol);
}

#endif   /*** ISCSI_AUTH_KERNEL_H ***/

