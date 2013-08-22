/*********************************************************************************
 * Filename:  iscsi_target.h
 *
 * This file contains definitions related to the main iSCSI Target driver.
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc. 
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


#ifndef ISCSI_TARGET_H
#define ISCSI_TARGET_H

extern struct iscsi_tiqn_s *core_get_tiqn_for_login (unsigned char *);
extern struct iscsi_tiqn_s *core_get_tiqn (unsigned char *, int);
extern void core_put_tiqn_for_login (iscsi_tiqn_t *);
extern iscsi_tiqn_t *core_add_tiqn (unsigned char *, int *);
extern int core_del_tiqn (iscsi_tiqn_t *);
extern int core_access_np (iscsi_np_t *, iscsi_portal_group_t *);
extern int core_deaccess_np (iscsi_np_t *, iscsi_portal_group_t *);
extern void *core_get_np_ip (iscsi_np_t *np);
extern struct iscsi_np_s *core_get_np (void *, u16, int);
extern int __core_del_np_ex (iscsi_np_t *, iscsi_np_ex_t *);
extern struct iscsi_np_s *core_add_np (iscsi_np_addr_t *, int, int *);
extern int core_reset_np_thread (struct iscsi_np_s *, struct iscsi_tpg_np_s *, struct iscsi_portal_group_s *, int);
extern int core_del_np (iscsi_np_t *);
extern char *iscsi_get_fabric_name (void);
extern u8 iscsi_get_fabric_proto_ident (void);
extern iscsi_cmd_t *iscsi_get_cmd (struct se_cmd_s *);
extern u32 iscsi_get_task_tag (struct se_cmd_s *);
extern int iscsi_get_cmd_state (struct se_cmd_s *);
extern void iscsi_new_cmd_failure (struct se_cmd_s *);
extern int iscsi_is_state_remove (struct se_cmd_s *);
extern int lio_sess_logged_in (struct se_session_s *);
#ifdef SNMP_SUPPORT
extern u32 lio_sess_get_index (struct se_session_s *);
#endif /* SNMP_SUPPORT */
extern u32 lio_sess_get_initiator_sid (struct se_session_s *, unsigned char *, u32);
extern int iscsi_send_async_msg (iscsi_conn_t *, __u16, __u8, __u8);
extern int lio_queue_data_in (struct se_cmd_s *);
extern int iscsi_send_r2t (iscsi_cmd_t *, iscsi_conn_t *);
extern int iscsi_build_r2ts_for_cmd (iscsi_cmd_t *, iscsi_conn_t *, int);
extern int lio_write_pending (struct se_cmd_s *);
extern int lio_write_pending_status(struct se_cmd_s *);
extern int lio_queue_status (struct se_cmd_s *);
extern u16 lio_set_fabric_sense_len (struct se_cmd_s *, u32);
extern u16 lio_get_fabric_sense_len (void);
extern int lio_queue_tm_rsp (struct se_cmd_s *);
extern void iscsi_thread_get_cpumask(struct iscsi_conn_s *);
extern int iscsi_target_tx_thread (void *);
extern int iscsi_target_rx_thread (void *);
extern int iscsi_close_connection (iscsi_conn_t *);
extern int iscsi_close_session (iscsi_session_t *);
extern void iscsi_fail_session (iscsi_session_t *);
extern int iscsi_free_session (iscsi_session_t *);
extern void iscsi_stop_session (iscsi_session_t *, int, int);
extern int iscsi_release_sessions_for_tpg (iscsi_portal_group_t *, int);

#endif   /*** ISCSI_TARGET_H ***/
