/*********************************************************************************
 * Filename:  iscsi_target_tpg.c
 *
 * This file contains iSCSI Target Portal Group related functions.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
 * Copyright (c) 2007 Rising Tide Software, Inc.
 * Copyright (c) 2008 Linux-iSCSI.org
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *********************************************************************************/


#define ISCSI_TARGET_TPG_C

#include <linux/net.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_lists.h>
#include <iscsi_debug.h>
#include <iscsi_protocol.h>

#include <target/target_core_base.h>
#include <target/target_core_transport.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>
#include <target/target_core_hba.h>
#include <target/target_core_tpg.h>

#include <iscsi_target_core.h>
#include <iscsi_target_device.h>
#include <iscsi_target_erl0.h>
#include <iscsi_target_error.h>
#include <iscsi_target_login.h>
#include <iscsi_target_nodeattrib.h>
#include <iscsi_target_tpg.h>
#include <iscsi_target_util.h>
#include <iscsi_target.h>
#include <iscsi_parameters.h>

#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>

#undef ISCSI_TARGET_TPG_C

extern iscsi_global_t *iscsi_global;
extern struct target_fabric_configfs *lio_target_fabric_configfs;
extern struct kmem_cache *lio_tpg_cache;

extern int iscsi_close_session (iscsi_session_t *); 
extern int iscsi_free_session (iscsi_session_t *);
extern int iscsi_release_sessions_for_tpg (iscsi_portal_group_t *, int);
extern int iscsi_ta_authentication (iscsi_portal_group_t *, __u32);

extern char *lio_tpg_get_endpoint_wwn (se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return(&tpg->tpg_tiqn->tiqn[0]);
}

extern u16 lio_tpg_get_tag (se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return(tpg->tpgt);
}

extern u32 lio_tpg_get_default_depth (se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return(ISCSI_TPG_ATTRIB(tpg)->default_cmdsn_depth);
}

extern u32 lio_tpg_get_pr_transport_id (
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl,
	t10_pr_registration_t *pr_reg,
	int *format_code,
	unsigned char *buf)
{
	u32 off = 4, padding = 0;
	u16 len = 0;

	spin_lock(&se_nacl->nacl_sess_lock);
	/*
	 * Set PROTOCOL IDENTIFIER to 5h for iSCSI
	 */
	buf[0] = 0x05;
	/*
	 * From spc4r17 Section 7.5.4.6: TransportID for initiator
	 * ports using SCSI over iSCSI.
	 *
	 * The null-terminated, null-padded (see 4.4.2) ISCSI NAME field
	 * shall contain the iSCSI name of an iSCSI initiator node (see
	 * RFC 3720). The first ISCSI NAME field byte containing an ASCII
	 * null character terminates the ISCSI NAME field without regard for
	 * the specified length of the iSCSI TransportID or the contents of
	 * the ADDITIONAL LENGTH field.
	 */
	len = sprintf(&buf[off], "%s", se_nacl->initiatorname);
	/*
	 * Add Extra byte for NULL terminator
	 */
	len++;
	/*
	 * If there is ISID present with the registration and *format code == 1
	 * 1, use iSCSI Initiator port TransportID format.
	 *
	 * Otherwise use iSCSI Initiator device TransportID format that
	 * does not contain the ASCII encoded iSCSI Initiator iSID value
	 * provied by the iSCSi Initiator during the iSCSI login process.
	 */
	if ((*format_code == 1) &&
	    (pr_reg->pr_reg_flags & PRF_ISID_PRESENT_AT_REG)) {
		/*
		 * Set FORMAT CODE 01b for iSCSI Initiator port TransportID
		 * format.
		 */
		buf[0] |= 0x40;
		/*
		 * From spc4r17 Section 7.5.4.6: TransportID for initiator
		 * ports using SCSI over iSCSI.  Table 390
		 *
		 * The SEPARATOR field shall contain the five ASCII
		 * characters ",i,0x".
		 *
		 * The null-terminated, null-padded ISCSI INITIATOR SESSION ID
		 * field shall contain the iSCSI initiator session identifier
		 * (see RFC 3720) in the form of ASCII characters that are the
		 * hexadecimal digits converted from the binary iSCSI initiator
		 * session identifier value. The first ISCSI INITIATOR SESSION
		 * ID field byte containing an ASCII null character
		 */
		buf[off+len] = 0x2c; off++; /* ASCII Character: "," */
		buf[off+len] = 0x69; off++; /* ASCII Character: "i" */
		buf[off+len] = 0x2c; off++; /* ASCII Character: "," */
		buf[off+len] = 0x30; off++; /* ASCII Character: "0" */
		buf[off+len] = 0x78; off++; /* ASCII Character: "x" */
		len += 5;
		buf[off+len] = pr_reg->pr_reg_isid[0]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[1]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[2]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[3]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[4]; off++;
		buf[off+len] = pr_reg->pr_reg_isid[5]; off++;
		buf[off+len] = '\0'; off++;
		len += 7;
	}
	spin_unlock(&se_nacl->nacl_sess_lock);
	/*
	 * The ADDITIONAL LENGTH field specifies the number of bytes that follow
	 * in the TransportID. The additional length shall be at least 20 and
	 * shall be a multiple of four.
	 */
	if ((padding = ((-len) & 3)) != 0) 
		len += padding;

	buf[2] = ((len >> 8) & 0xff);
	buf[3] = (len & 0xff);
	/*
	 * Increment value for total payload + header length for
	 * full status descriptor
	 */
	len += 4;

	return(len);
}

extern u32 lio_tpg_get_pr_transport_id_len (
	se_portal_group_t *se_tpg,
	se_node_acl_t *se_nacl,
	t10_pr_registration_t *pr_reg,
	int *format_code)
{
	u32 len = 0, padding = 0;

	spin_lock(&se_nacl->nacl_sess_lock);
	len = strlen(se_nacl->initiatorname);
	/*
	 * Add extra byte for NULL terminator
	 */
	len++;
	/*
	 * If there is ISID present with the registration, use format code:
	 * 01b: iSCSI Initiator port TransportID format
	 *
	 * If there is not an active iSCSI session, use format code:
	 * 00b: iSCSI Initiator device TransportID format
	 */
	if (pr_reg->pr_reg_flags & PRF_ISID_PRESENT_AT_REG) {
		len += 5; /* For ",i,0x" ASCII seperator */
		len += 7; /* For iSCSI Initiator Session ID + Null terminator */
		*format_code = 1;
	} else
		*format_code = 0;
	spin_unlock(&se_nacl->nacl_sess_lock);
	/*
	 * The ADDITIONAL LENGTH field specifies the number of bytes that follow
	 * in the TransportID. The additional length shall be at least 20 and
	 * shall be a multiple of four.
	 */
	if ((padding = ((-len) & 3)) != 0)
		len += padding;
	/*
	 * Increment value for total payload + header length for
	 * full status descriptor
	 */
	len += 4;

	return(len);
}

extern char *lio_tpg_parse_pr_out_transport_id(
	const char *buf,
	u32 *out_tid_len,
	char **port_nexus_ptr)
{
	char *p;
	u32 tid_len, padding;
	int i;
	u16 add_len;
	u8 format_code = (buf[0] & 0xc0);
	/*
	 * Check for FORMAT CODE 00b or 01b from spc4r17, section 7.5.4.6:
	 *
	 *	 TransportID for initiator ports using SCSI over iSCSI,
	 * 	 from Table 388 -- iSCSI TransportID formats.
	 *
	 *    00b     Initiator port is identified using the world wide unique
	 *	      SCSI device name of the iSCSI initiator
	 *            device containing the initiator port (see table 389).
	 *    01b     Initiator port is identified using the world wide unique
	 *            initiator port identifier (see table 390).10b to 11b Reserved
	 */
	if ((format_code != 0x00) && (format_code != 0x40)) {
		printk(KERN_ERR "Illegal format code: 0x%02x for iSCSI"
			" Initiator Transport ID\n", format_code);
		return NULL;
	}
	/*
	 * If the caller wants the TransportID Length, we set that value for the
	 * entire iSCSI Tarnsport ID now.
	 */
	if (out_tid_len != NULL) {
		add_len = ((buf[2] >> 8) & 0xff);
		add_len |= (buf[3] & 0xff);

		tid_len = strlen((char *)&buf[4]);
		tid_len += 4; /* Add four bytes for iSCSI Transport ID header */
		tid_len += 1; /* Add one byte for NULL terminator */
		if ((padding = ((-tid_len) & 3)) != 0)
			tid_len += padding;

		if ((add_len + 4) != tid_len) {
			printk(KERN_INFO "LIO-Target Extracted add_len: %hu "
				"does not match calculated tid_len: %u,"
				" using tid_len instead\n", add_len+4, tid_len);
			*out_tid_len = tid_len;
		} else 
			*out_tid_len = (add_len + 4);
	}
	/*
	 * Check for the ',i,0x' seperator between iSCSI Name and iSCSI Initiator
	 * Session ID as defined in Table 390 -- iSCSI initiator port TransportID
	 * format.
	 */
	if (format_code == 0x40) {
		p = strstr((char *)&buf[4], ",i,0x");	
		if (!(p)) {
			printk(KERN_ERR "Unable to locate \",i,0x\" seperator"
				" for Initiator port identifier: %s\n",
				(char *)&buf[4]);
			return NULL;
		}
		*p = '\0'; /* Terminate iSCSI Name */
		p += 5; /* Skip over ",i,0x" seperator */

		*port_nexus_ptr = p;	
		/*
		 * Go ahead and do the lower case conversion of the received
		 * 12 ASCII characters representing the ISID in the TransportID
		 * for comparision against the running iSCSI session's ISID from
		 * iscsi_target.c:lio_sess_get_initiator_sid()
		 */
		for (i = 0; i < 12; i++) {
			if (isdigit(*p)) {
				p++;
				continue;
			}
			*p = tolower(*p);
			p++;
		}
	}

	return (char *)&buf[4];
}

extern int lio_tpg_check_demo_mode (se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return(ISCSI_TPG_ATTRIB(tpg)->generate_node_acls);
}

extern int lio_tpg_check_demo_mode_cache (se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return(ISCSI_TPG_ATTRIB(tpg)->cache_dynamic_acls);
}

extern int lio_tpg_check_demo_mode_write_protect (se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return(ISCSI_TPG_ATTRIB(tpg)->demo_mode_write_protect);
}

extern struct se_node_acl_s *lio_tpg_alloc_fabric_acl (
	se_portal_group_t *se_tpg)
{
	iscsi_node_acl_t *acl;

	if (!(acl = kzalloc(sizeof(iscsi_node_acl_t), GFP_KERNEL))) {
		printk(KERN_ERR "Unable to allocate memory for iscsi_node_acl_t\n");
		return(NULL);
        }

	return(&acl->se_node_acl);
}

extern void lio_tpg_release_fabric_acl (se_portal_group_t *se_tpg, se_node_acl_t *se_acl)
{
	iscsi_node_acl_t *acl = container_of(se_acl, struct iscsi_node_acl_s,
					se_node_acl);

	kfree(acl);
	return;
}

/*
 * Called with spin_lock_bh(se_portal_group_t->session_lock) held..
 *
 * Also, this function calls iscsi_inc_session_usage_count() on the
 * iscsi_session_t in question.
 */
extern int lio_tpg_shutdown_session (se_session_t *se_sess)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

	spin_lock(&sess->conn_lock);
	if (atomic_read(&sess->session_fall_back_to_erl0) ||
	    atomic_read(&sess->session_logout) ||
	    (sess->time2retain_timer_flags & T2R_TF_EXPIRED)) {
		spin_unlock(&sess->conn_lock);
		return(0);
	}
	atomic_set(&sess->session_reinstatement, 1);
	spin_unlock(&sess->conn_lock);

	iscsi_inc_session_usage_count(sess);
	iscsi_stop_time2retain_timer(sess);

	return(1);
}

/*
 * Calls iscsi_dec_session_usage_count() as inverse of lio_tpg_shutdown_session()
 */
extern void lio_tpg_close_session (se_session_t *se_sess)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;
	/*
	 * If the iSCSI Session for the iSCSI Initiator Node exists,
	 * forcefully shutdown the iSCSI NEXUS.
	 */
	iscsi_stop_session(sess, 1, 1);
	iscsi_dec_session_usage_count(sess);
	iscsi_close_session(sess);

	return;
}

extern void lio_tpg_stop_session (se_session_t *se_sess, int sess_sleep, int conn_sleep)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

	iscsi_stop_session(sess, sess_sleep, conn_sleep);
	return;
}

extern void lio_tpg_fall_back_to_erl0 (se_session_t *se_sess)
{
	iscsi_session_t *sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

	iscsi_fall_back_to_erl0(sess);	
	return;
}

#ifdef SNMP_SUPPORT
extern u32 lio_tpg_get_inst_index (se_portal_group_t *se_tpg)
{
	iscsi_portal_group_t *tpg = (iscsi_portal_group_t *)se_tpg->se_tpg_fabric_ptr;

	return(tpg->tpg_tiqn->tiqn_index);
}
#endif /* SNMP_SUPPORT */

extern void lio_set_default_node_attributes (se_node_acl_t *se_acl)
{
	iscsi_node_acl_t *acl = container_of(se_acl, struct iscsi_node_acl_s,
					se_node_acl);

	ISCSI_NODE_ATTRIB(acl)->nacl = acl;
	iscsi_set_default_node_attribues(acl);
	return;
}

extern iscsi_portal_group_t *core_alloc_portal_group (iscsi_tiqn_t *tiqn, u16 tpgt)
{
	iscsi_portal_group_t *tpg;

	tpg = kmem_cache_zalloc(lio_tpg_cache, GFP_KERNEL);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to get tpg from lio_tpg_cache\n");
		return NULL;
	}

	tpg->tpgt = tpgt;
	tpg->tpg_state = TPG_STATE_FREE;
	tpg->tpg_tiqn = tiqn;
	INIT_LIST_HEAD(&tpg->tpg_gnp_list);
	INIT_LIST_HEAD(&tpg->g_tpg_list);
	INIT_LIST_HEAD(&tpg->tpg_list);
	init_MUTEX(&tpg->tpg_access_sem);
	init_MUTEX(&tpg->np_login_sem);
	spin_lock_init(&tpg->tpg_state_lock);
	spin_lock_init(&tpg->tpg_np_lock);
	tpg->sid        = 1; /* First Assigned LIO-Target Session ID */

	return tpg;
}

static void iscsi_set_default_tpg_attribs (iscsi_portal_group_t *);

extern int core_load_discovery_tpg (void)
{
	iscsi_param_t *param;
	iscsi_portal_group_t *tpg;

	tpg = core_alloc_portal_group(NULL, 1);
	if (!(tpg)) {
		printk(KERN_ERR "Unable to allocate iscsi_portal_group_t\n");
		return(-1);
	}

	if (!(tpg->tpg_se_tpg = core_tpg_register(
			&lio_target_fabric_configfs->tf_ops, (void *)tpg,
			TRANSPORT_TPG_TYPE_DISCOVERY))) {
		kfree(tpg);
		return(-1);
	}

	tpg->sid        = 1; /* First Assigned LIO Session ID */
	INIT_LIST_HEAD(&tpg->tpg_gnp_list);
	INIT_LIST_HEAD(&tpg->g_tpg_list);
	INIT_LIST_HEAD(&tpg->tpg_list);
	init_MUTEX(&tpg->tpg_access_sem);
	init_MUTEX(&tpg->np_login_sem);
	spin_lock_init(&tpg->tpg_state_lock);
	spin_lock_init(&tpg->tpg_np_lock);

	iscsi_set_default_tpg_attribs(tpg);

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto out;
	/*
	 * By default we disable authentication for discovery sessions,
	 * this can be changed with:
	 *
	 * /sys/kernel/config/target/iscsi/discovery_auth/enforce_discovery_auth
	 */
	param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list);
	if (!(param))
		goto out;

	if (iscsi_update_param_value(param, "CHAP,None") < 0)
		goto out;

	tpg->tpg_attrib.authentication = 0;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state  = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_global->discovery_tpg = tpg;
	PYXPRINT("CORE[0] - Allocated Discovery TPG\n");

	return(0);
out:
	if (tpg->tpg_se_tpg)
		core_tpg_deregister(tpg->tpg_se_tpg);
	kfree(tpg);
	return(-1);
}

extern void core_release_discovery_tpg (void)
{
	iscsi_portal_group_t *tpg = iscsi_global->discovery_tpg;

	core_tpg_deregister(tpg->tpg_se_tpg);

	kmem_cache_free(lio_tpg_cache, tpg);
	iscsi_global->discovery_tpg = NULL;

	return;
}

extern iscsi_portal_group_t *core_get_tpg_from_np (
	iscsi_tiqn_t *tiqn,
	iscsi_np_t *np)
{
	iscsi_portal_group_t *tpg = NULL;
	iscsi_tpg_np_t *tpg_np;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {

		spin_lock(&tpg->tpg_state_lock);
		if (tpg->tpg_state == TPG_STATE_FREE) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);

		spin_lock(&tpg->tpg_np_lock);
		list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
			if (tpg_np->tpg_np == np) {
				spin_unlock(&tpg->tpg_np_lock);
				spin_unlock(&tiqn->tiqn_tpg_lock);
				return(tpg);
			}
		}
		spin_unlock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return(NULL);
}

extern int iscsi_get_tpg (
	iscsi_portal_group_t *tpg)
{
	if (down_interruptible(&tpg->tpg_access_sem))
		printk(KERN_ERR "failed to get tpg_access_sem %s/%u\n", __FILE__, __LINE__);
	return (signal_pending(current)) ? -1 : 0;
}

/*	iscsi_put_tpg():
 *
 *
 */
extern void iscsi_put_tpg (iscsi_portal_group_t *tpg)
{
	up(&tpg->tpg_access_sem);
	return;
}

static void iscsi_clear_tpg_np_login_thread (
	iscsi_tpg_np_t *tpg_np,
	iscsi_portal_group_t *tpg,
	int shutdown)
{
	if (!tpg_np->tpg_np) {
		TRACE_ERROR("iscsi_tpg_np_t->tpg_np is NULL!\n");
		return;
	}

	core_reset_np_thread(tpg_np->tpg_np, tpg_np, tpg, shutdown);
	return;
}

/*	iscsi_clear_tpg_np_login_threads():
 *
 *
 */
extern void iscsi_clear_tpg_np_login_threads (
	iscsi_portal_group_t *tpg,
	int shutdown)
{
	iscsi_tpg_np_t *tpg_np;

	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry(tpg_np, &tpg->tpg_gnp_list, tpg_np_list) {
		if (!tpg_np->tpg_np) {
			TRACE_ERROR("iscsi_tpg_np_t->tpg_np is NULL!\n");
			continue;
		}
		spin_unlock(&tpg->tpg_np_lock);
		iscsi_clear_tpg_np_login_thread(tpg_np, tpg, shutdown);
		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);

	return;
}

/*	iscsi_tpg_dump_params():
 *
 *
 */
extern void iscsi_tpg_dump_params (iscsi_portal_group_t *tpg)
{
	iscsi_print_params(tpg->param_list);
}

/*	iscsi_tpg_free_network_portals():
 *
 *
 */
static void iscsi_tpg_free_network_portals (iscsi_portal_group_t *tpg)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np, *tpg_np_t;
	unsigned char buf_ipv4[IPV4_BUF_SIZE], *ip;
	
	spin_lock(&tpg->tpg_np_lock);
	list_for_each_entry_safe(tpg_np, tpg_np_t, &tpg->tpg_gnp_list, tpg_np_list) {
		np = tpg_np->tpg_np;
		list_del(&tpg_np->tpg_np_list);
		tpg->num_tpg_nps--;
		tpg->tpg_tiqn->tiqn_num_tpg_nps--;

		if (np->np_net_size == IPV6_ADDRESS_SPACE)
			ip = &np->np_ipv6[0];
		else {
			memset(buf_ipv4, 0, IPV4_BUF_SIZE);
			iscsi_ntoa2(buf_ipv4, np->np_ipv4);
			ip = &buf_ipv4[0];
		}

		PYXPRINT("CORE[%s] - Removed Network Portal: %s:%hu,%hu on %s on"
			" network device: %s\n", tpg->tpg_tiqn->tiqn, ip,
			np->np_port, tpg->tpgt, (np->np_network_transport == ISCSI_TCP) ?
			"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
			(char *)np->np_net_dev : "None");

		tpg_np->tpg_np = NULL;
		kfree(tpg_np);
		spin_unlock(&tpg->tpg_np_lock);

		spin_lock(&np->np_state_lock);
		np->np_exports--;
		PYXPRINT("CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
			tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
		spin_unlock(&np->np_state_lock);

		spin_lock(&tpg->tpg_np_lock);
	}
	spin_unlock(&tpg->tpg_np_lock);

	return;
}

/*	iscsi_set_default_tpg_attribs():
 *
 *
 */
static void iscsi_set_default_tpg_attribs (iscsi_portal_group_t *tpg)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	a->authentication = TA_AUTHENTICATION;
	a->login_timeout = TA_LOGIN_TIMEOUT;
	a->netif_timeout = TA_NETIF_TIMEOUT;
	a->default_cmdsn_depth = TA_DEFAULT_CMDSN_DEPTH;
	a->generate_node_acls = TA_GENERATE_NODE_ACLS;
	a->cache_dynamic_acls = TA_CACHE_DYNAMIC_ACLS;
	a->demo_mode_write_protect = TA_DEMO_MODE_WRITE_PROTECT;
	a->prod_mode_write_protect = TA_PROD_MODE_WRITE_PROTECT;
	a->crc32c_x86_offload = TA_CRC32C_X86_OFFLOAD;
	a->cache_core_nps = TA_CACHE_CORE_NPS;
		
	return;
}

/*	iscsi_tpg_add_portal_group():
 *
 *
 */
extern int iscsi_tpg_add_portal_group (iscsi_tiqn_t *tiqn, iscsi_portal_group_t *tpg)
{
	if (tpg->tpg_state != TPG_STATE_FREE) {
		TRACE_ERROR("Unable to add iSCSI Target Portal Group: %d while"
			" not in TPG_STATE_FREE state.\n", tpg->tpgt);
		return -EEXIST;
	}
	iscsi_set_default_tpg_attribs(tpg);

	if (iscsi_create_default_params(&tpg->param_list) < 0)
		goto err_out;

	ISCSI_TPG_ATTRIB(tpg)->tpg = tpg;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state	= TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_add_tail(&tpg->tpg_list, &tiqn->tiqn_tpg_list);
	tiqn->tiqn_ntpgs++;
	PYXPRINT("CORE[%s]_TPG[%hu] - Added iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	spin_lock_bh(&iscsi_global->g_tpg_lock);
	list_add_tail(&tpg->g_tpg_list, &iscsi_global->g_tpg_list);
	spin_unlock_bh(&iscsi_global->g_tpg_lock);

	return 0;
err_out:
	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}
	kfree(tpg);
	return -ENOMEM;
}	

extern int iscsi_tpg_del_portal_group (
	iscsi_tiqn_t *tiqn,
	iscsi_portal_group_t *tpg,
	int force)
{
	u8 old_state = tpg->tpg_state;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);

	iscsi_clear_tpg_np_login_threads(tpg, 1);
	
	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		TRACE_ERROR("Unable to delete iSCSI Target Portal Group: %hu"
		" while active sessions exist, and force=0\n", tpg->tpgt);
		tpg->tpg_state = old_state;
		return(ERR_DELTPG_SESSIONS_ACTIVE);
	}

	core_tpg_clear_object_luns(tpg->tpg_se_tpg);
	iscsi_tpg_free_network_portals(tpg);
	core_tpg_free_node_acls(tpg->tpg_se_tpg);

	spin_lock_bh(&iscsi_global->g_tpg_lock);
	list_del(&tpg->g_tpg_list);
	spin_unlock_bh(&iscsi_global->g_tpg_lock);
	
	if (tpg->param_list) {
		iscsi_release_param_list(tpg->param_list);
		tpg->param_list = NULL;
	}

	core_tpg_deregister(tpg->tpg_se_tpg);
	tpg->tpg_se_tpg = NULL;

	spin_lock(&tpg->tpg_state_lock);
	tpg->tpg_state = TPG_STATE_FREE;
	spin_unlock(&tpg->tpg_state_lock);

	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_ntpgs--;
	list_del(&tpg->tpg_list);	
	spin_unlock(&tiqn->tiqn_tpg_lock);

	PYXPRINT("CORE[%s]_TPG[%hu] - Deleted iSCSI Target Portal Group\n",
			tiqn->tiqn, tpg->tpgt);

	kmem_cache_free(lio_tpg_cache, tpg);
	return 0;
}

/*	iscsi_tpg_enable_portal_group():
 *      
 *
 */             
extern int iscsi_tpg_enable_portal_group (iscsi_portal_group_t *tpg)
{
	iscsi_param_t *param;
	iscsi_tiqn_t *tiqn = tpg->tpg_tiqn;
	
	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_ACTIVE) {
		TRACE_ERROR("iSCSI target portal group: %hu is already active,"
				" ignoring request.\n", tpg->tpgt);
		spin_unlock(&tpg->tpg_state_lock);
		return(ERR_ENABLETPG_ALREADY_ACTIVE);
	}
	/*
	 * Make sure that AuthMethod does not contain None as an option
	 * unless explictly disabled.  Set the default to CHAP if authentication
	 * is enforced (as per default), and remove the NONE option.
	 */
	if (!(param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list))) {
		spin_unlock(&tpg->tpg_state_lock);
		return(ERR_NO_MEMORY);
	}

	if (ISCSI_TPG_ATTRIB(tpg)->authentication) {
		if (!strcmp(param->value, NONE))
			if (iscsi_update_param_value(param, CHAP) < 0) {
				spin_unlock(&tpg->tpg_state_lock);
				return(ERR_NO_MEMORY);
			}
		if (iscsi_ta_authentication(tpg, 1) < 0) {
			spin_unlock(&tpg->tpg_state_lock);
			return(ERR_NO_MEMORY);
		}
	}
		
	tpg->tpg_state = TPG_STATE_ACTIVE;
	spin_unlock(&tpg->tpg_state_lock);
	
	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs++;
	PYXPRINT("iSCSI_TPG[%hu] - Enabled iSCSI Target Portal Group\n", tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return(0);
}		

/*	iscsi_tpg_disable_portal_group():
 *
 *
 */
extern int iscsi_tpg_disable_portal_group (iscsi_portal_group_t *tpg, int force)
{
	iscsi_tiqn_t *tiqn;
	u8 old_state = tpg->tpg_state;
	
	spin_lock(&tpg->tpg_state_lock);
	if (tpg->tpg_state == TPG_STATE_INACTIVE) {
		TRACE_ERROR("iSCSI Target Portal Group: %hu is already"
			" inactive, ignoring request.\n", tpg->tpgt);
		spin_unlock(&tpg->tpg_state_lock);
		return(ERR_DISABLETPG_NOT_ACTIVE);
	}
	tpg->tpg_state = TPG_STATE_INACTIVE;
	spin_unlock(&tpg->tpg_state_lock);
	
	iscsi_clear_tpg_np_login_threads(tpg, 0);
	
	if (iscsi_release_sessions_for_tpg(tpg, force) < 0) {
		spin_lock(&tpg->tpg_state_lock);
		tpg->tpg_state = old_state;
		spin_unlock(&tpg->tpg_state_lock);
		TRACE_ERROR("Unable to disable iSCSI Target Portal Group: %hu"
		" while active sessions exist, and force=0\n", tpg->tpgt);
		return(ERR_DISABLETPG_SESSIONS_ACTIVE);
	}

	tiqn = tpg->tpg_tiqn;
	if (!(tiqn) || (tpg == iscsi_global->discovery_tpg))
		return 0;
	
	spin_lock(&tiqn->tiqn_tpg_lock);
	tiqn->tiqn_active_tpgs--;
	PYXPRINT("iSCSI_TPG[%hu] - Disabled iSCSI Target Portal Group\n", tpg->tpgt);
	spin_unlock(&tiqn->tiqn_tpg_lock);
	
	return(0);
}

/*	iscsi_tpg_add_initiator_node_acl():
 *
 *
 */
extern iscsi_node_acl_t *iscsi_tpg_add_initiator_node_acl (
	iscsi_portal_group_t *tpg,
	const char *initiatorname,
	u32 queue_depth)
{
	se_node_acl_t *se_nacl;
	iscsi_node_acl_t *nacl;

	se_nacl = core_tpg_add_initiator_node_acl(tpg->tpg_se_tpg,
			initiatorname, queue_depth);
	if ((IS_ERR(se_nacl)) || !(se_nacl))
		return(NULL);

	nacl = container_of(se_nacl, struct iscsi_node_acl_s,
				se_node_acl);
	return(nacl);
}

/*	iscsi_tpg_del_initiator_node_acl():
 *
 *
 */
extern void iscsi_tpg_del_initiator_node_acl (
	iscsi_portal_group_t *tpg,
	se_node_acl_t *se_nacl)
{
	/*
	 * TPG_TFO(tpg)->tpg_release_acl() will kfree the iscsi_node_acl_t..
	 */
	core_tpg_del_initiator_node_acl(tpg->tpg_se_tpg, se_nacl, 1);
}

extern iscsi_node_attrib_t *iscsi_tpg_get_node_attrib (
	iscsi_session_t *sess)
{
	se_session_t *se_sess = sess->se_sess;
	se_node_acl_t *se_nacl = se_sess->se_node_acl;
	iscsi_node_acl_t *acl = container_of(se_nacl, struct iscsi_node_acl_s,
					se_node_acl);

	return(&acl->node_attrib);
}	

extern iscsi_tpg_np_t *iscsi_tpg_locate_child_np (
	iscsi_tpg_np_t *tpg_np,
	int network_transport)
{
	iscsi_tpg_np_t *tpg_np_child, *tpg_np_child_tmp;

	spin_lock(&tpg_np->tpg_np_parent_lock);
	list_for_each_entry_safe(tpg_np_child, tpg_np_child_tmp,
			&tpg_np->tpg_np_parent_list, tpg_np_child_list) {
		if (tpg_np_child->tpg_np->np_network_transport ==
				network_transport) {
			spin_unlock(&tpg_np->tpg_np_parent_lock);
			return(tpg_np_child);
		}
	}	
	spin_unlock(&tpg_np->tpg_np_parent_lock);

	return(NULL);
}

/*	iscsi_tpg_add_network_portal():
 *
 *
 */
extern iscsi_tpg_np_t *iscsi_tpg_add_network_portal (
	iscsi_portal_group_t *tpg,
	iscsi_np_addr_t *np_addr,
	iscsi_tpg_np_t *tpg_np_parent,
	int network_transport)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np;
	char *ip_buf;
	void *ip;
	int ret = 0;
	unsigned char buf_ipv4[IPV4_BUF_SIZE];

	if (np_addr->np_flags & NPF_NET_IPV6) {
		ip_buf = (char *)&np_addr->np_ipv6[0];
		ip = (void *)&np_addr->np_ipv6[0];
	} else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np_addr->np_ipv4);
		ip_buf = &buf_ipv4[0];
		ip = (void *)&np_addr->np_ipv4;
	}
	/*
	 * If the Network Portal does not currently exist, start it up now.
	 */
	if (!(np = core_get_np(ip, np_addr->np_port, network_transport))) {
		if (!(np = core_add_np(np_addr, network_transport, &ret)))
			return(ERR_PTR(ret));
	}

	if (!(tpg_np = (iscsi_tpg_np_t *) kzalloc(
			sizeof(iscsi_tpg_np_t), GFP_KERNEL))) {
		TRACE_ERROR("Unable to allocate memory for iscsi_tpg_np_t.\n");
		return(ERR_PTR(-ENOMEM));
	}
#ifdef SNMP_SUPPORT
	tpg_np->tpg_np_index	= iscsi_get_new_index(ISCSI_PORTAL_INDEX);
#endif /* SNMP_SUPPORT */
	INIT_LIST_HEAD(&tpg_np->tpg_np_list);
	INIT_LIST_HEAD(&tpg_np->tpg_np_child_list);
	INIT_LIST_HEAD(&tpg_np->tpg_np_parent_list);
	spin_lock_init(&tpg_np->tpg_np_parent_lock);
	tpg_np->tpg_np		= np;
	tpg_np->tpg		= tpg;

	spin_lock(&tpg->tpg_np_lock);
	list_add_tail(&tpg_np->tpg_np_list, &tpg->tpg_gnp_list);
	tpg->num_tpg_nps++;
	if (tpg->tpg_tiqn)
		tpg->tpg_tiqn->tiqn_num_tpg_nps++;
	spin_unlock(&tpg->tpg_np_lock);

	if (tpg_np_parent) {
		tpg_np->tpg_np_parent = tpg_np_parent;
		spin_lock(&tpg_np_parent->tpg_np_parent_lock);
		list_add_tail(&tpg_np->tpg_np_child_list,
			&tpg_np_parent->tpg_np_parent_list);
		spin_unlock(&tpg_np_parent->tpg_np_parent_lock);
	}

	PYXPRINT("CORE[%s] - Added Network Portal: %s:%hu,%hu on %s on network"
		" device: %s\n", tpg->tpg_tiqn->tiqn, ip_buf, np->np_port,
		tpg->tpgt, (np->np_network_transport == ISCSI_TCP) ?
		"TCP" : "SCTP", (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");

	spin_lock(&np->np_state_lock);
	np->np_exports++;
	PYXPRINT("CORE[%s]_TPG[%hu] - Incremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
	spin_unlock(&np->np_state_lock);

	return(tpg_np);
}

static int iscsi_tpg_release_np (
	iscsi_tpg_np_t *tpg_np,
	iscsi_portal_group_t *tpg,
	iscsi_np_t *np)
{
	char *ip;
	char buf_ipv4[IPV4_BUF_SIZE];
	
	if (np->np_net_size == IPV6_ADDRESS_SPACE)
		ip = &np->np_ipv6[0];
	else {
		memset(buf_ipv4, 0, IPV4_BUF_SIZE);
		iscsi_ntoa2(buf_ipv4, np->np_ipv4);
		ip = &buf_ipv4[0];
	}
	
	iscsi_clear_tpg_np_login_thread(tpg_np, tpg, 1);

	PYXPRINT("CORE[%s] - Removed Network Portal: %s:%hu,%hu on %s on network"
		" device: %s\n", tpg->tpg_tiqn->tiqn, ip,
		np->np_port, tpg->tpgt, (np->np_network_transport == ISCSI_TCP) ? 
		"TCP" : "SCTP",  (strlen(np->np_net_dev)) ?
		(char *)np->np_net_dev : "None");

	tpg_np->tpg_np = NULL;
	tpg_np->tpg = NULL;
	kfree(tpg_np);

	/*
	 * Shutdown Network Portal when last TPG reference is released.
	 */
	spin_lock(&np->np_state_lock);
	if ((--np->np_exports == 0) && !(ISCSI_TPG_ATTRIB(tpg)->cache_core_nps))
		atomic_set(&np->np_shutdown, 1);
	PYXPRINT("CORE[%s]_TPG[%hu] - Decremented np_exports to %u\n",
		tpg->tpg_tiqn->tiqn, tpg->tpgt, np->np_exports);
	spin_unlock(&np->np_state_lock);

	if (atomic_read(&np->np_shutdown))
		core_del_np(np);

	return(0);
}

/*	iscsi_tpg_del_network_portal():
 *
 *
 */
extern int iscsi_tpg_del_network_portal (
	iscsi_portal_group_t *tpg,
	iscsi_tpg_np_t *tpg_np)
{
	iscsi_np_t *np;
	iscsi_tpg_np_t *tpg_np_child, *tpg_np_child_tmp;
	int ret = 0;

	if (!(np = tpg_np->tpg_np)) {
		printk(KERN_ERR "Unable to locate iscsi_np_t from iscsi_tpg_np_t\n");
		return(-EINVAL);
	}
	
	if (!tpg_np->tpg_np_parent) {
		/*
		 * We are the parent tpg network portal.  Release all of the
		 * child tpg_np's (eg: the non ISCSI_TCP ones) on our parent list
		 * first.
		 */
		list_for_each_entry_safe(tpg_np_child, tpg_np_child_tmp,
				&tpg_np->tpg_np_parent_list, tpg_np_child_list) {
			if ((ret = iscsi_tpg_del_network_portal(tpg, tpg_np_child)) < 0)
				printk(KERN_ERR "iscsi_tpg_del_network_portal()"
					" failed: %d\n", ret);
		}
	} else {
		/*
		 * We are not the parent ISCSI_TCP tpg network portal.  Release
		 * our own network portals from the child list.
		 */
		spin_lock(&tpg_np->tpg_np_parent->tpg_np_parent_lock);
		list_del(&tpg_np->tpg_np_child_list);
		spin_unlock(&tpg_np->tpg_np_parent->tpg_np_parent_lock);
	}

	spin_lock(&tpg->tpg_np_lock);
	list_del(&tpg_np->tpg_np_list);
	tpg->num_tpg_nps--;
	if (tpg->tpg_tiqn)
		tpg->tpg_tiqn->tiqn_num_tpg_nps--;
	spin_unlock(&tpg->tpg_np_lock);

	return(iscsi_tpg_release_np(tpg_np, tpg, np)); 
}

/*	iscsi_tpg_set_initiator_node_queue_depth():
 *
 *
 */
extern int iscsi_tpg_set_initiator_node_queue_depth (
	iscsi_portal_group_t *tpg,
	unsigned char *initiatorname,
	u32 queue_depth,
	int force)
{
	return(core_tpg_set_initiator_node_queue_depth(tpg->tpg_se_tpg,
		initiatorname, queue_depth, force));
}

/*	iscsi_ta_authentication():
 *
 *
 */
extern int iscsi_ta_authentication (iscsi_portal_group_t *tpg, u32 authentication)
{
	unsigned char buf1[256], buf2[256], *none = NULL;
	int len;
	iscsi_param_t *param;
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	if ((authentication != 1) && (authentication != 0)) {
		TRACE_ERROR("Illegal value for authentication parameter: %u,"
			" ignoring request.\n", authentication);
		return(-1);
	}
		
	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	if (!(param = iscsi_find_param_from_key(AUTHMETHOD, tpg->param_list)))
		return(-EINVAL);

	if (authentication) {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		if (!(none = strstr(buf1, NONE)))
			goto out;
		if (!strncmp(none + 4, ",", 1)) {
			if (!strcmp(buf1, none))
				sprintf(buf2, "%s", none+5);
			else {
				none--;
				*none = '\0';
				len = sprintf(buf2, "%s", buf1);
				none += 5;
				sprintf(buf2 + len, "%s", none);
			}
		} else {
			none--;
			*none = '\0';
			sprintf(buf2, "%s", buf1);
		}
		if (iscsi_update_param_value(param, buf2) < 0)
			return(-EINVAL);
	} else {
		snprintf(buf1, sizeof(buf1), "%s", param->value);
		if ((none = strstr(buf1, NONE)))
			goto out;
		strncat(buf1, ",", strlen(","));
		strncat(buf1, NONE, strlen(NONE));
		if (iscsi_update_param_value(param, buf1) < 0)
			return(-EINVAL);
	}

out:	
	a->authentication = authentication;
	PYXPRINT("%s iSCSI Authentication Methods for TPG: %hu.\n",
		a->authentication ? "Enforcing" : "Disabling", tpg->tpgt);
	
	return(0);
}

/*	iscsi_ta_login_timeout():
 *
 *
 */
extern int iscsi_ta_login_timeout (
	iscsi_portal_group_t *tpg,
	u32 login_timeout)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	if (login_timeout > TA_LOGIN_TIMEOUT_MAX) {
		TRACE_ERROR("Requested Login Timeout %u larger than maximum"
			" %u\n", login_timeout, TA_LOGIN_TIMEOUT_MAX);
		return(-EINVAL);
	} else if (login_timeout < TA_LOGIN_TIMEOUT_MIN) {
		TRACE_ERROR("Requested Logout Timeout %u smaller than minimum"
			" %u\n", login_timeout, TA_LOGIN_TIMEOUT_MIN);
		return(-EINVAL);
	}

	a->login_timeout = login_timeout;
	PYXPRINT("Set Logout Timeout to %u for Target Portal Group"
		" %hu\n", a->login_timeout, tpg->tpgt);
	
	return(0);
}

/*	iscsi_ta_netif_timeout():
 *
 *
 */
extern int iscsi_ta_netif_timeout (
	iscsi_portal_group_t *tpg,
	u32 netif_timeout)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if (netif_timeout > TA_NETIF_TIMEOUT_MAX) {
		TRACE_ERROR("Requested Network Interface Timeout %u larger"
			" than maximum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MAX);	
		return(-EINVAL);
	} else if (netif_timeout < TA_NETIF_TIMEOUT_MIN) {
		TRACE_ERROR("Requested Network Interface Timeout %u smaller"
			" than minimum %u\n", netif_timeout,
				TA_NETIF_TIMEOUT_MIN);
		return(-EINVAL);
	}

	a->netif_timeout = netif_timeout;
	PYXPRINT("Set Network Interface Timeout to %u for"
		" Target Portal Group %hu\n", a->netif_timeout, tpg->tpgt);
		
	return(0);
}

extern int iscsi_ta_generate_node_acls (
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-EINVAL);
	}

	a->generate_node_acls = flag;
	PYXPRINT("iSCSI_TPG[%hu] - Generate Initiator Portal Group ACLs: %s\n",
		tpg->tpgt, (a->generate_node_acls) ? "Enabled" : "Disabled");
	
	return(0);
}

extern int iscsi_ta_default_cmdsn_depth (
	iscsi_portal_group_t *tpg,
	u32 tcq_depth)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;
	
	if (tcq_depth > TA_DEFAULT_CMDSN_DEPTH_MAX) {
		TRACE_ERROR("Requested Default Queue Depth: %u larger"
			" than maximum %u\n", tcq_depth,
				TA_DEFAULT_CMDSN_DEPTH_MAX);
		return(-EINVAL);
	} else if (tcq_depth < TA_DEFAULT_CMDSN_DEPTH_MIN) {
		TRACE_ERROR("Requested Default Queue Depth: %u smaller"
			" than minimum %u\n", tcq_depth,
				TA_DEFAULT_CMDSN_DEPTH_MIN);
		return(-EINVAL);
	}

	a->default_cmdsn_depth = tcq_depth;
	PYXPRINT("iSCSI_TPG[%hu] - Set Default CmdSN TCQ Depth to %u\n", tpg->tpgt,
			a->default_cmdsn_depth);

	return(0);
}

extern int iscsi_ta_cache_dynamic_acls (
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-EINVAL);
	}

	a->cache_dynamic_acls = flag;
	PYXPRINT("iSCSI_TPG[%hu] - Cache Dynamic Initiator Portal Group ACLs: %s\n",
		tpg->tpgt, (a->cache_dynamic_acls) ? "Enabled" : "Disabled");

	return(0);
}

extern int iscsi_ta_demo_mode_write_protect (
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-EINVAL);
	}

	a->demo_mode_write_protect = flag;
	PYXPRINT("iSCSI_TPG[%hu] - Demo Mode Write Protect bit: %s\n",
		tpg->tpgt, (a->demo_mode_write_protect) ? "ON" : "OFF");

	return(0);
}

extern int iscsi_ta_prod_mode_write_protect (
	iscsi_portal_group_t *tpg,
	u32 flag)
{
	iscsi_tpg_attrib_t *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		TRACE_ERROR("Illegal value %d\n", flag);
		return(-EINVAL);
	}

	a->prod_mode_write_protect = flag;
	PYXPRINT("iSCSI_TPG[%hu] - Production Mode Write Protect bit: %s\n",
		tpg->tpgt, (a->prod_mode_write_protect) ? "ON" : "OFF");

	return(0);
}

int iscsi_ta_crc32c_x86_offload(
	struct iscsi_portal_group_s *tpg,
	u32 flag)
{
	struct iscsi_tpg_attrib_s *a = &tpg->tpg_attrib;

	if ((flag != 0) && (flag != 1)) {
		printk(KERN_ERR "Illegal value %d\n", flag);
		return -EINVAL;
	}

	a->crc32c_x86_offload = flag;
	printk(KERN_INFO "iSCSI_TPG[%hu] - CRC32C x86 Offload: %s\n",
		tpg->tpgt, (a->crc32c_x86_offload) ? "ON" : "OFF");

	return 0;
}

extern void iscsi_disable_tpgs (iscsi_tiqn_t *tiqn)
{
	iscsi_portal_group_t *tpg;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry(tpg, &tiqn->tiqn_tpg_list, tpg_list) {

		spin_lock(&tpg->tpg_state_lock);
		if ((tpg->tpg_state == TPG_STATE_FREE) ||
		    (tpg->tpg_state == TPG_STATE_INACTIVE)) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);
		spin_unlock(&tiqn->tiqn_tpg_lock);

		iscsi_tpg_disable_portal_group(tpg, 1);

		spin_lock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return;
}

/*	iscsi_disable_all_tpgs():
 *
 *
 */
extern void iscsi_disable_all_tpgs (void)
{
	iscsi_tiqn_t *tiqn;

	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_disable_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);
		
	return;
}

extern void iscsi_remove_tpgs (iscsi_tiqn_t *tiqn)
{
	iscsi_portal_group_t *tpg, *tpg_tmp;

	spin_lock(&tiqn->tiqn_tpg_lock);
	list_for_each_entry_safe(tpg, tpg_tmp, &tiqn->tiqn_tpg_list, tpg_list) {

		spin_lock(&tpg->tpg_state_lock);
		if (tpg->tpg_state == TPG_STATE_FREE) {
			spin_unlock(&tpg->tpg_state_lock);
			continue;
		}
		spin_unlock(&tpg->tpg_state_lock);
		spin_unlock(&tiqn->tiqn_tpg_lock);

		iscsi_tpg_del_portal_group(tiqn, tpg, 1);

		spin_lock(&tiqn->tiqn_tpg_lock);
	}
	spin_unlock(&tiqn->tiqn_tpg_lock);

	return;
}

/*	iscsi_remove_all_tpgs():
 *
 *
 */
extern void iscsi_remove_all_tpgs (void)
{
	iscsi_tiqn_t *tiqn;
	
	spin_lock(&iscsi_global->tiqn_lock);
	list_for_each_entry(tiqn, &iscsi_global->g_tiqn_list, tiqn_list) {
		spin_unlock(&iscsi_global->tiqn_lock);
		iscsi_remove_tpgs(tiqn);
		spin_lock(&iscsi_global->tiqn_lock);
	}
	spin_unlock(&iscsi_global->tiqn_lock);

	return;
}
