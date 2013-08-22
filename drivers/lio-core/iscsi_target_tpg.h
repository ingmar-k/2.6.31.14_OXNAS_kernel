/*********************************************************************************
 * Filename:  iscsi_target_tpg.h
 *
 * This file contains iSCSI Target Portal Group related definitions.
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


#ifndef ISCSI_TARGET_TPG_H
#define ISCSI_TARGET_TPG_H

extern char *lio_tpg_get_endpoint_wwn(struct se_portal_group_s *);
extern u16 lio_tpg_get_tag(struct se_portal_group_s *);
extern u32 lio_tpg_get_default_depth(struct se_portal_group_s *);
extern u32 lio_tpg_get_pr_transport_id(struct se_portal_group_s *,
			struct se_node_acl_s *, struct t10_pr_registration_s *,
			int *, unsigned char *);
extern u32 lio_tpg_get_pr_transport_id_len(struct se_portal_group_s *,
			struct se_node_acl_s *, struct t10_pr_registration_s *,
			int *);
extern char *lio_tpg_parse_pr_out_transport_id(const char *, u32 *, char **);
extern int lio_tpg_check_demo_mode (struct se_portal_group_s *);
extern int lio_tpg_check_demo_mode_cache (struct se_portal_group_s *);
extern int lio_tpg_check_demo_mode_write_protect (struct se_portal_group_s *);
extern struct se_node_acl_s *lio_tpg_alloc_fabric_acl (struct se_portal_group_s *);
extern void lio_tpg_release_fabric_acl (struct se_portal_group_s *, struct se_node_acl_s *);
extern int lio_tpg_shutdown_session (struct se_session_s *);
extern void lio_tpg_close_session (struct se_session_s *);
extern void lio_tpg_stop_session (struct se_session_s *, int, int);
extern void lio_tpg_fall_back_to_erl0 (struct se_session_s *);
#ifdef SNMP_SUPPORT
extern u32 lio_tpg_get_inst_index (struct se_portal_group_s *);
#endif /* SNMP_SUPPORT */
extern void lio_set_default_node_attributes (struct se_node_acl_s *);

extern iscsi_portal_group_t *core_alloc_portal_group (iscsi_tiqn_t *, u16);
extern int core_load_discovery_tpg (void);
extern void core_release_discovery_tpg (void);
extern iscsi_portal_group_t *core_get_tpg_from_np (struct iscsi_tiqn_s *, struct iscsi_np_s *);
extern int iscsi_get_tpg (struct iscsi_portal_group_s *);
extern void iscsi_put_tpg (iscsi_portal_group_t *);
extern void iscsi_clear_tpg_np_login_threads (iscsi_portal_group_t *, int);
extern void iscsi_tpg_dump_params (iscsi_portal_group_t *);
extern int iscsi_tpg_add_portal_group (iscsi_tiqn_t *, iscsi_portal_group_t *);
extern int iscsi_tpg_del_portal_group (iscsi_tiqn_t *, iscsi_portal_group_t *, int);
extern int iscsi_tpg_enable_portal_group (iscsi_portal_group_t *);
extern int iscsi_tpg_disable_portal_group (iscsi_portal_group_t *, int);
extern iscsi_node_acl_t *iscsi_tpg_add_initiator_node_acl (iscsi_portal_group_t *, const char *, u32);
extern void iscsi_tpg_del_initiator_node_acl (iscsi_portal_group_t *, struct se_node_acl_s *);
extern iscsi_node_attrib_t *iscsi_tpg_get_node_attrib (iscsi_session_t *);
extern void iscsi_tpg_del_external_nps (iscsi_tpg_np_t *);
extern iscsi_tpg_np_t *iscsi_tpg_locate_child_np (iscsi_tpg_np_t *, int);
extern iscsi_tpg_np_t *iscsi_tpg_add_network_portal (iscsi_portal_group_t *, iscsi_np_addr_t *, iscsi_tpg_np_t *, int);
extern int iscsi_tpg_del_network_portal (iscsi_portal_group_t *, iscsi_tpg_np_t *);
extern int iscsi_tpg_set_initiator_node_queue_depth (iscsi_portal_group_t *, unsigned char *, u32, int);
extern int iscsi_ta_authentication (iscsi_portal_group_t *, u32);
extern int iscsi_ta_login_timeout (iscsi_portal_group_t *, u32);
extern int iscsi_ta_netif_timeout (iscsi_portal_group_t *, u32);
extern int iscsi_ta_generate_node_acls (iscsi_portal_group_t *, u32);
extern int iscsi_ta_default_cmdsn_depth (iscsi_portal_group_t *, u32);
extern int iscsi_ta_cache_dynamic_acls (iscsi_portal_group_t *, u32);
extern int iscsi_ta_demo_mode_write_protect (iscsi_portal_group_t *, u32);
extern int iscsi_ta_prod_mode_write_protect (iscsi_portal_group_t *, u32);
extern int iscsi_ta_crc32c_x86_offload(iscsi_portal_group_t *, u32);
extern void iscsi_disable_tpgs (struct iscsi_tiqn_s *);
extern void iscsi_disable_all_tpgs (void);
extern void iscsi_remove_tpgs (struct iscsi_tiqn_s *);
extern void iscsi_remove_all_tpgs (void);

#endif /* ISCSI_TARGET_TPG_H */
