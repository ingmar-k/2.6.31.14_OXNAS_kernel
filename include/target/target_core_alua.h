#ifndef TARGET_CORE_ALUA_H
#define TARGET_CORE_ALUA_H

/*
 * INQUIRY response data, TPGS Field
 *
 * from spc4r17 section 6.4.2 Table 135
 */
#define TPGS_NO_ALUA				0x00
#define TPGS_IMPLICT_ALUA			0x10
#define TPGS_EXPLICT_ALUA			0x20

/*
 * ASYMMETRIC ACCESS STATE field
 *
 * from spc4r17 section 6.27 Table 245
 */
#define ALUA_ACCESS_STATE_ACTIVE_OPTMIZED	0x0
#define ALUA_ACCESS_STATE_ACTIVE_NON_OPTIMIZED	0x1
#define ALUA_ACCESS_STATE_STANDBY		0x2
#define ALUA_ACCESS_STATE_UNAVAILABLE		0x3
#define ALUA_ACCESS_STATE_OFFLINE		0xe
#define ALUA_ACCESS_STATE_TRANSITION		0xf

/*
 * REPORT_TARGET_PORT_GROUP STATUS CODE
 *
 * from spc4r17 section 6.27 Table 246
 */
#define ALUA_STATUS_NONE				0x00
#define ALUA_STATUS_ALTERED_BY_EXPLICT_STPG		0x01
#define ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA		0x02

/*
 * From spc4r17, Table D.1: ASC and ASCQ Assignement
 */
#define ASCQ_04H_ALUA_STATE_TRANSITION			0x0a
#define ASCQ_04H_ALUA_TG_PT_STANDBY			0x0b
#define ASCQ_04H_ALUA_TG_PT_UNAVAILABLE			0x0c
#define ASCQ_04H_ALUA_OFFLINE				0x12

/*
 * Used as the default for Active/NonOptimized delay (in milliseconds)
 * This can also be changed via configfs on a per target port group basis..
 */
#define ALUA_DEFAULT_NONOP_DELAY_MSECS			100
#define ALUA_MAX_NONOP_DELAY_MSECS			10000 /* 10 seconds */
/*
 * Used for implict and explict ALUA transitional delay, that is disabled
 * by default, and is intended to be used for debugging client side ALUA code.
 */
#define ALUA_DEFAULT_TRANS_DELAY_MSECS			0
#define ALUA_MAX_TRANS_DELAY_MSECS			30000 /* 30 seconds */


extern se_global_t *se_global;

extern struct kmem_cache *t10_alua_lu_gp_cache;
extern struct kmem_cache *t10_alua_lu_gp_mem_cache;
extern struct kmem_cache *t10_alua_tg_pt_gp_cache;
extern struct kmem_cache *t10_alua_tg_pt_gp_mem_cache;

extern int core_scsi3_emulate_report_target_port_groups(struct se_cmd_s *);
extern int core_scsi3_emulate_set_target_port_groups(struct se_cmd_s *);
extern int core_alua_check_transition(int, int *);
extern int core_alua_check_nonop_delay(struct se_cmd_s *);
extern int core_alua_do_transition_tg_pt(struct t10_alua_tg_pt_gp_s *,
				struct se_port_s *, struct se_node_acl_s *,
				unsigned char *, int, int);
extern int core_alua_do_port_transition(struct t10_alua_tg_pt_gp_s *,
				struct se_device_s *, struct se_port_s *,
				struct se_node_acl_s *, int, int);
extern int core_alua_set_tg_pt_secondary_state(
		struct t10_alua_tg_pt_gp_member_s *, se_port_t *, int, int);
extern char *core_alua_dump_state(int);
extern char *core_alua_dump_status(int);
extern struct t10_alua_lu_gp_s *core_alua_allocate_lu_gp(const char *, int);
extern int core_alua_set_lu_gp_id(struct t10_alua_lu_gp_s *, u16);
extern struct t10_alua_lu_gp_member_s *core_alua_allocate_lu_gp_mem(
					struct se_device_s *);
extern void core_alua_free_lu_gp(struct t10_alua_lu_gp_s *);
extern void core_alua_free_lu_gp_mem(struct se_device_s *);
extern struct t10_alua_lu_gp_s *core_alua_get_lu_gp_by_name(const char *);
extern void core_alua_put_lu_gp_from_name(struct t10_alua_lu_gp_s *);
extern void __core_alua_attach_lu_gp_mem(struct t10_alua_lu_gp_member_s *,
					struct t10_alua_lu_gp_s *);
extern void __core_alua_drop_lu_gp_mem(struct t10_alua_lu_gp_member_s *,
					struct t10_alua_lu_gp_s *);
extern void core_alua_drop_lu_gp_dev(struct se_device_s *);
extern struct t10_alua_tg_pt_gp_s *core_alua_allocate_tg_pt_gp(
			struct se_subsystem_dev_s *, const char *, int);
extern int core_alua_set_tg_pt_gp_id(struct t10_alua_tg_pt_gp_s *, u16);
extern struct t10_alua_tg_pt_gp_member_s *core_alua_allocate_tg_pt_gp_mem(
					struct se_port_s *);
extern void core_alua_free_tg_pt_gp(struct t10_alua_tg_pt_gp_s *);
extern void core_alua_free_tg_pt_gp_mem(struct se_port_s *);
extern struct t10_alua_tg_pt_gp_s *core_alua_get_tg_pt_gp_by_name(
				struct se_subsystem_dev_s *, const char *);
extern void core_alua_put_tg_pt_gp_from_name(struct t10_alua_tg_pt_gp_s *);
extern void __core_alua_attach_tg_pt_gp_mem(struct t10_alua_tg_pt_gp_member_s *,
					struct t10_alua_tg_pt_gp_s *);
extern void __core_alua_drop_tg_pt_gp_mem(struct t10_alua_tg_pt_gp_member_s *,
					struct t10_alua_tg_pt_gp_s *);
extern ssize_t core_alua_show_tg_pt_gp_info(struct se_port_s *, char *);
extern ssize_t core_alua_store_tg_pt_gp_info(struct se_port_s *, const char *,
						size_t);
extern ssize_t core_alua_show_access_type(struct t10_alua_tg_pt_gp_s *, char *);
extern ssize_t core_alua_store_access_type(struct t10_alua_tg_pt_gp_s *,
					const char *, size_t);
extern ssize_t core_alua_show_nonop_delay_msecs(struct t10_alua_tg_pt_gp_s *,
						char *);
extern ssize_t core_alua_store_nonop_delay_msecs(struct t10_alua_tg_pt_gp_s *,
					const char *, size_t);
extern ssize_t core_alua_show_trans_delay_msecs(struct t10_alua_tg_pt_gp_s *,
					char *);
extern ssize_t core_alua_store_trans_delay_msecs(struct t10_alua_tg_pt_gp_s *,
					const char *, size_t);
extern ssize_t core_alua_show_preferred_bit(struct t10_alua_tg_pt_gp_s *,
					char *);
extern ssize_t core_alua_store_preferred_bit(struct t10_alua_tg_pt_gp_s *,
					const char *, size_t);
extern ssize_t core_alua_show_offline_bit(struct se_lun_s *, char *);
extern ssize_t core_alua_store_offline_bit(struct se_lun_s *, const char *,
					size_t);
extern ssize_t core_alua_show_secondary_status(struct se_lun_s *, char *);
extern ssize_t core_alua_store_secondary_status(struct se_lun_s *,
					const char *, size_t);
extern ssize_t core_alua_show_secondary_write_metadata(struct se_lun_s *,
					char *);
extern ssize_t core_alua_store_secondary_write_metadata(struct se_lun_s *,
					const char *, size_t);
extern int core_setup_alua(struct se_device_s *, int);

#endif /* TARGET_CORE_ALUA_H */
