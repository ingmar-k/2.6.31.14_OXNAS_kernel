/*********************************************************************************
 * Filename:  iscsi_target_nodeattrib.c
 *
 * This file contains the main functions related to Initiator Node Attributes.
 *
 * Copyright (c) 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007 Rising Tide Software, Inc.
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


#define ISCSI_TARGET_NODEATTRIB_C

#include <linux/string.h>
#include <linux/timer.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>

#include <iscsi_debug.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <target/target_core_base.h>
#include <iscsi_target_device.h>
#include <iscsi_target_error.h>
#include <iscsi_target_tpg.h>
#include <target/target_core_transport.h>
#include <iscsi_target_util.h>
#include <iscsi_target_nodeattrib.h>

#undef ISCSI_TARGET_NODEATTRIB_C

/*	iscsi_set_default_node_attribues():
 *
 *
 */
extern void iscsi_set_default_node_attribues (
	iscsi_node_acl_t *acl)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	TRACE_ENTER
	
	a->dataout_timeout = NA_DATAOUT_TIMEOUT;
	a->dataout_timeout_retries = NA_DATAOUT_TIMEOUT_RETRIES;
	a->nopin_timeout = NA_NOPIN_TIMEOUT;
	a->nopin_response_timeout = NA_NOPIN_RESPONSE_TIMEOUT;
	a->random_datain_pdu_offsets = NA_RANDOM_DATAIN_PDU_OFFSETS;
	a->random_datain_seq_offsets = NA_RANDOM_DATAIN_SEQ_OFFSETS;
	a->random_r2t_offsets = NA_RANDOM_R2T_OFFSETS;
	a->default_erl = NA_DEFAULT_ERL;
		
	TRACE_LEAVE
	return;
}

/*	iscsi_na_dataout_timeout():
 *
 *
 */
extern int iscsi_na_dataout_timeout (
	iscsi_node_acl_t *acl,
	u32 dataout_timeout)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;
	
	TRACE_ENTER

	if (dataout_timeout > NA_DATAOUT_TIMEOUT_MAX) {
		TRACE_ERROR("Requested DataOut Timeout %u larger than maximum"
			" %u\n", dataout_timeout, NA_DATAOUT_TIMEOUT_MAX);
		return(-EINVAL);
	} else if (dataout_timeout < NA_DATAOUT_TIMEOUT_MIX) {
		TRACE_ERROR("Requested DataOut Timeout %u smaller than minimum"
			" %u\n", dataout_timeout, NA_DATAOUT_TIMEOUT_MIX);
		return(-EINVAL);
	}

	a->dataout_timeout = dataout_timeout;
	TRACE(TRACE_NODEATTRIB, "Set DataOut Timeout to %u for Initiator Node"
			" %s\n", a->dataout_timeout, acl->initiatorname);
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_na_dataout_timeout_retries():
 *
 *
 */
extern int iscsi_na_dataout_timeout_retries (
	iscsi_node_acl_t *acl,
	u32 dataout_timeout_retries)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;
	
	TRACE_ENTER

	if (dataout_timeout_retries > NA_DATAOUT_TIMEOUT_RETRIES_MAX) {
		TRACE_ERROR("Requested DataOut Timeout Retries %u larger than"
			" maximum %u", dataout_timeout_retries,
				NA_DATAOUT_TIMEOUT_RETRIES_MAX);
		return(-EINVAL);
	} else if (dataout_timeout_retries < NA_DATAOUT_TIMEOUT_RETRIES_MIN) {
		TRACE_ERROR("Requested DataOut Timeout Retries %u smaller than"
			" minimum %u", dataout_timeout_retries,
				NA_DATAOUT_TIMEOUT_RETRIES_MIN);
		return(-EINVAL);
	}

	a->dataout_timeout_retries = dataout_timeout_retries;
	TRACE(TRACE_NODEATTRIB, "Set DataOut Timeout Retries to %u for Initiator"
		" Node %s\n", a->dataout_timeout_retries, acl->initiatorname);
	
	TRACE_LEAVE
	return(0);
}

/*	iscsi_na_nopin_timeout():
 *
 *
 */
extern int iscsi_na_nopin_timeout (
	iscsi_node_acl_t *acl,
	u32 nopin_timeout)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;
	iscsi_session_t *sess;
	iscsi_conn_t *conn;
	se_node_acl_t *se_nacl = &a->nacl->se_node_acl;
	se_session_t *se_sess;
	u32 orig_nopin_timeout = a->nopin_timeout;

	TRACE_ENTER

	if (nopin_timeout > NA_NOPIN_TIMEOUT_MAX) {
		TRACE_ERROR("Requested NopIn Timeout %u larger than maximum"
			" %u\n", nopin_timeout, NA_NOPIN_TIMEOUT_MAX);
		return(-EINVAL);
	} else if ((nopin_timeout < NA_NOPIN_TIMEOUT_MIN) &&
		   (nopin_timeout != 0)) {
		TRACE_ERROR("Requested NopIn Timeout %u smaller than minimum"
			" %u and not 0\n", nopin_timeout, NA_NOPIN_TIMEOUT_MIN);
		return(-EINVAL);
	}

	a->nopin_timeout = nopin_timeout;
	TRACE(TRACE_NODEATTRIB, "Set NopIn Timeout to %u for Initiator"
		" Node %s\n", a->nopin_timeout, acl->initiatorname);
	/*
	 * Reenable disabled nopin_timeout timer for all iSCSI connections.
	 */
	if (!(orig_nopin_timeout)) {
		spin_lock_bh(&se_nacl->nacl_sess_lock);
		se_sess = se_nacl->nacl_sess;
		if (se_sess) {
			sess = (iscsi_session_t *)se_sess->fabric_sess_ptr;

			spin_lock(&sess->conn_lock);		
			for (conn = sess->conn_head; conn; conn = conn->next) {
				if (conn->conn_state != TARG_CONN_STATE_LOGGED_IN)
					continue;

				spin_lock(&conn->nopin_timer_lock);
				__iscsi_start_nopin_timer(conn);
				spin_unlock(&conn->nopin_timer_lock);
			}
			spin_unlock(&sess->conn_lock);
		}
		spin_unlock_bh(&se_nacl->nacl_sess_lock);
	}

	TRACE_LEAVE
	return(0);
}

/*	iscsi_na_nopin_response_timeout():
 *
 *
 */
extern int iscsi_na_nopin_response_timeout (
	iscsi_node_acl_t *acl,
	u32 nopin_response_timeout)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	TRACE_ENTER

	if (nopin_response_timeout > NA_NOPIN_RESPONSE_TIMEOUT_MAX) {
		TRACE_ERROR("Requested NopIn Response Timeout %u larger than"
			" maximum %u\n", nopin_response_timeout,
				NA_NOPIN_RESPONSE_TIMEOUT_MAX);
		return(-EINVAL);
	} else if (nopin_response_timeout < NA_NOPIN_RESPONSE_TIMEOUT_MIN) {
		TRACE_ERROR("Requested NopIn Response Timeout %u smaller than"
			" minimum %u\n", nopin_response_timeout,
				NA_NOPIN_RESPONSE_TIMEOUT_MIN);
		return(-EINVAL);
	}

	a->nopin_response_timeout = nopin_response_timeout;
	TRACE(TRACE_NODEATTRIB, "Set NopIn Response Timeout to %u for"
		" Initiator Node %s\n", a->nopin_timeout, acl->initiatorname);
		
	TRACE_LEAVE
	return(0);
}

/*	iscsi_na_random_datain_pdu_offsets():
 *
 *
 */
extern int iscsi_na_random_datain_pdu_offsets (
	iscsi_node_acl_t *acl,
	u32 random_datain_pdu_offsets)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	TRACE_ENTER
	
	if (random_datain_pdu_offsets != 0 && random_datain_pdu_offsets != 1) {
		TRACE_ERROR("Requested Random DataIN PDU Offsets: %u not"
			" 0 or 1\n", random_datain_pdu_offsets);
		return(-EINVAL);
	}

	a->random_datain_pdu_offsets = random_datain_pdu_offsets;
	TRACE(TRACE_NODEATTRIB, "Set Random DataIN PDU Offsets to %u for"
		" Initiator Node %s\n", a->random_datain_pdu_offsets,
			acl->initiatorname);

	TRACE_LEAVE
	return(0);
}

/*	iscsi_na_random_datain_seq_offsets():
 *
 *
 */
extern int iscsi_na_random_datain_seq_offsets (
	iscsi_node_acl_t *acl,
	u32 random_datain_seq_offsets)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	TRACE_ENTER

	if (random_datain_seq_offsets != 0 && random_datain_seq_offsets != 1) {
		TRACE_ERROR("Requested Random DataIN Sequence Offsets: %u not"
			" 0 or 1\n", random_datain_seq_offsets);
		return(-EINVAL);
	}

	a->random_datain_seq_offsets = random_datain_seq_offsets;
	TRACE(TRACE_NODEATTRIB, "Set Random DataIN Sequence Offsets to %u for"
		" Initiator Node %s\n", a->random_datain_seq_offsets,
			acl->initiatorname);

	TRACE_LEAVE
	return(0);
}

/*	iscsi_na_random_r2t_offsets():
 *
 *
 */
extern int iscsi_na_random_r2t_offsets (
	iscsi_node_acl_t *acl,
	u32 random_r2t_offsets)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;

	TRACE_ENTER

	if (random_r2t_offsets != 0 && random_r2t_offsets != 1) {
		TRACE_ERROR("Requested Random R2T Offsets: %u not"
			" 0 or 1\n", random_r2t_offsets);
		return(-EINVAL);
	}

	a->random_r2t_offsets = random_r2t_offsets;
	TRACE(TRACE_NODEATTRIB, "Set Random R2T Offsets to %u for"
		" Initiator Node %s\n", a->random_r2t_offsets,
			acl->initiatorname);

	TRACE_LEAVE
	return(0);
}

extern int iscsi_na_default_erl (
	iscsi_node_acl_t *acl,
	u32 default_erl)
{
	iscsi_node_attrib_t *a = &acl->node_attrib;
	
	if (default_erl != 0 && default_erl != 1 && default_erl != 2) {
		TRACE_ERROR("Requested default ERL: %u not 0, 1, or 2\n",
				default_erl);
		return(-EINVAL);
	}

	a->default_erl = default_erl;
	TRACE(TRACE_NODEATTRIB, "Set use ERL0 flag to %u for Initiator"
		" Node Node %s\n", a->default_erl, acl->initiatorname);
	
	return(0);
}
