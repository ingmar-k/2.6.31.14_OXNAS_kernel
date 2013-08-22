/****************************************************************************
 * Filename:  target_core_base.h
 *
 * This file contains definitions related to the Target Core Engine.
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
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
 ****************************************************************************/


#ifndef TARGET_CORE_BASE_H
#define TARGET_CORE_BASE_H

#include <linux/in.h>
#include <linux/configfs.h>
#include <net/sock.h>
#include <net/tcp.h>
#ifdef SNMP_SUPPORT
#include <target/target_core_mib.h>
#endif /* SNMP_SUPPORT */

#define TARGET_CORE_MOD_VERSION		"v3.5.2"
#define SHUTDOWN_SIGS	(sigmask(SIGKILL)|sigmask(SIGINT)|sigmask(SIGABRT))

/* SCSI Command Descriptor Block Size a la SCSI's MAX_COMMAND_SIZE */
#define SCSI_CDB_SIZE			16
#define TRANSPORT_IOV_DATA_BUFFER	5

/* Maximum Number of LUNs per Target Portal Group */
#define TRANSPORT_MAX_LUNS_PER_TPG	    256

/* From include/scsi/scsi_cmnd.h:SCSI_SENSE_BUFFERSIZE */
#define TRANSPORT_SENSE_BUFFER              SCSI_SENSE_BUFFERSIZE

#define SPC_SENSE_KEY_OFFSET			2
#define SPC_ASC_KEY_OFFSET			12
#define SPC_ASCQ_KEY_OFFSET			13

/* Currently same as ISCSI_IQN_LEN */
#define TRANSPORT_IQN_LEN			224
#define LU_GROUP_NAME_BUF			256
#define TG_PT_GROUP_NAME_BUF			256
/* Used to parse VPD into t10_vpd_t */
#define VPD_TMP_BUF_SIZE			128
/* Used for target_core-pscsi.c:pscsi_transport_complete() */
#define VPD_BUF_LEN				256
/* Used for se_subsystem_dev_t-->se_dev_alias, must be less than
   PAGE_SIZE */
#define SE_DEV_ALIAS_LEN			512
/* Used for se_subsystem_dev_t->se_dev_udev_path[], must be less than
   PAGE_SIZE */
#define SE_UDEV_PATH_LEN			512
/* Used for se_dev_snap_attrib_t->contact */
#define SNAP_CONTACT_LEN			128
/* Used for se_dev_snap_attrib_t->lv_group */
#define SNAP_GROUP_LEN				128
/* Used for se_dev_snap_attrib->lvc_size */
#define SNAP_LVC_LEN				32
/* Used by t10_reservation_template_s->pr_[i,t]_port[] */
#define PR_APTPL_MAX_IPORT_LEN			256
#define PR_APTPL_MAX_TPORT_LEN			256
/* Used by t10_reservation_template_s->pr_aptpl_buf_len */
#define PR_APTPL_BUF_LEN			8192
/* Used by t10_alua_tg_pt_gp_t->tg_pt_gp_md_buf_len */
#define ALUA_MD_BUF_LEN				1024
/* Used by t10_pr_registration_t->pr_reg_isid */
#define PR_REG_ISID_LEN				16
/* PR_REG_ISID_LEN + ',i,0x' */
#define PR_REG_ISID_ID_LEN			(PR_REG_ISID_LEN + 5)

/* used by PSCSI and iBlock Transport drivers */
#define READ_BLOCK_LEN          		6
#define READ_CAP_LEN            		8
#define READ_POSITION_LEN       		20
#define INQUIRY_LEN				36
#define INQUIRY_VPD_SERIAL_LEN			254
#define INQUIRY_VPD_DEVICE_IDENTIFIER_LEN	254

/* se_cmd_t->data_direction */
#define SE_DIRECTION_NONE			0
#define SE_DIRECTION_READ			1
#define SE_DIRECTION_WRITE			2
#define SE_DIRECTION_BIDI			3

/* se_hba_t->hba_flags */
#define HBA_FLAGS_INTERNAL_USE			0x00000001
#define HBA_FLAGS_PSCSI_MODE			0x00000002

/* se_hba_t->hba_status and iscsi_tpg_hba->thba_status */
#define HBA_STATUS_FREE				0x00000001
#define HBA_STATUS_ACTIVE			0x00000002
#define HBA_STATUS_INACTIVE			0x00000004
#define HBA_STATUS_SHUTDOWN			0x00000008

/* se_lun_t->lun_status */
#define TRANSPORT_LUN_STATUS_FREE		0
#define TRANSPORT_LUN_STATUS_ACTIVE		1

/* se_lun_t->lun_type */
#define TRANSPORT_LUN_TYPE_NONE			0
#define TRANSPORT_LUN_TYPE_DEVICE		1

/* se_portal_group_t->se_tpg_type */
#define TRANSPORT_TPG_TYPE_NORMAL		0
#define TRANSPORT_TPG_TYPE_DISCOVERY		1

/* Used for se_node_acl->nodeacl_flags */
#define NAF_DYNAMIC_NODE_ACL                    0x01

/* se_map_sg_t->map_flags */
#define MAP_SG_KMAP				0x01

/* Used for generate timer flags */
#define TF_RUNNING				0x01
#define TF_STOP					0x02

/* Special transport agnostic se_cmd_t->t_states */
#define TRANSPORT_NO_STATE			240
#define TRANSPORT_NEW_CMD			241
#define TRANSPORT_DEFERRED_CMD			242
#define TRANSPORT_WRITE_PENDING			243
#define TRANSPORT_PROCESS_WRITE			244
#define TRANSPORT_PROCESSING			245
#define TRANSPORT_COMPLETE_OK			246
#define TRANSPORT_COMPLETE_FAILURE		247
#define TRANSPORT_COMPLETE_TIMEOUT		248
#define TRANSPORT_PROCESS_TMR			249
#define TRANSPORT_TMR_COMPLETE			250
#define TRANSPORT_ISTATE_PROCESSING 		251
#define TRANSPORT_ISTATE_PROCESSED  		252
#define TRANSPORT_KILL				253
#define TRANSPORT_REMOVE			254
#define TRANSPORT_FREE				255

#define SCF_SUPPORTED_SAM_OPCODE                0x00000001
#define SCF_TRANSPORT_TASK_SENSE                0x00000002
#define SCF_EMULATED_TASK_SENSE                 0x00000004
#define SCF_SCSI_DATA_SG_IO_CDB                 0x00000008
#define SCF_SCSI_CONTROL_SG_IO_CDB              0x00000010
#define SCF_SCSI_CONTROL_NONSG_IO_CDB           0x00000020
#define SCF_SCSI_NON_DATA_CDB                   0x00000040
#define SCF_SCSI_CDB_EXCEPTION                  0x00000080
#define SCF_SCSI_RESERVATION_CONFLICT           0x00000100
#define SCF_CMD_PASSTHROUGH                     0x00000200
#define SCF_CMD_PASSTHROUGH_NOALLOC             0x00000400
#define SCF_SE_CMD_FAILED                       0x00000800
#define SCF_SE_LUN_CMD                          0x00001000
#define SCF_SE_ALLOW_EOO                        0x00002000
#define SCF_SE_DISABLE_ONLINE_CHECK             0x00004000
#define SCF_SENT_CHECK_CONDITION		0x00008000
#define SCF_OVERFLOW_BIT                        0x00010000
#define SCF_UNDERFLOW_BIT                       0x00020000
#define SCF_SENT_DELAYED_TAS			0x00040000
#define SCF_ALUA_NON_OPTIMIZED			0x00080000
#define SCF_DELAYED_CMD_FROM_SAM_ATTR		0x00100000
#define SCF_PASSTHROUGH_SG_TO_MEM		0x00200000
#define SCF_PASSTHROUGH_CONTIG_TO_SG		0x00400000
#define SCF_PASSTHROUGH_SG_TO_MEM_NOALLOC	0x00800000

/* se_device_t->type */
#define PSCSI					1
#define STGT					2
#define PATA					3
#define IBLOCK					4
#define RAMDISK_DR				5
#define RAMDISK_MCP				6
#define FILEIO					7
#define VROM					8
#define VTAPE					9
#define MEDIA_CHANGER				10

/* se_dev_entry_t->lun_flags and se_lun_t->lun_access */
#define TRANSPORT_LUNFLAGS_NO_ACCESS		0x00000000
#define TRANSPORT_LUNFLAGS_INITIATOR_ACCESS	0x00000001
#define TRANSPORT_LUNFLAGS_READ_ONLY		0x00000002
#define TRANSPORT_LUNFLAGS_READ_WRITE		0x00000004

/* se_device_t->dev_status */
#define TRANSPORT_DEVICE_ACTIVATED		0x01
#define	TRANSPORT_DEVICE_DEACTIVATED		0x02
#define TRANSPORT_DEVICE_QUEUE_FULL		0x04
#define	TRANSPORT_DEVICE_SHUTDOWN		0x08
#define TRANSPORT_DEVICE_OFFLINE_ACTIVATED	0x10
#define TRANSPORT_DEVICE_OFFLINE_DEACTIVATED	0x20

#define	DEV_STATUS_THR_TUR			1
#define DEV_STATUS_THR_TAKE_ONLINE		2
#define DEV_STATUS_THR_TAKE_OFFLINE		3
#define DEV_STATUS_THR_SHUTDOWN			4

/* se_dev_entry_t->deve_flags */
#define DEF_PR_REGISTERED			0x01

/* Used for t10_pr_registration_t->pr_reg_flags */
#define PRF_ISID_PRESENT_AT_REG			0x01

/* transport_send_check_condition_and_sense() */
#define NON_EXISTENT_LUN			0x1
#define UNSUPPORTED_SCSI_OPCODE			0x2
#define INCORRECT_AMOUNT_OF_DATA		0x3
#define UNEXPECTED_UNSOLICITED_DATA		0x4
#define SERVICE_CRC_ERROR			0x5
#define SNACK_REJECTED				0x6
#define SECTOR_COUNT_TOO_MANY			0x7
#define INVALID_CDB_FIELD			0x8
#define INVALID_PARAMETER_LIST			0x9
#define LOGICAL_UNIT_COMMUNICATION_FAILURE	0xa
#define UNKNOWN_MODE_PAGE			0xb
#define WRITE_PROTECTED				0xc
#define CHECK_CONDITION_ABORT_CMD		0xd
#define CHECK_CONDITION_UNIT_ATTENTION		0xe
#define CHECK_CONDITION_NOT_READY		0xf

typedef struct se_obj_s {
	atomic_t obj_access_count;
} ____cacheline_aligned se_obj_t;

typedef enum {
	SPC_ALUA_PASSTHROUGH,
	SPC2_ALUA_DISABLED,
	SPC3_ALUA_EMULATED
} t10_alua_index_t;

typedef enum {
	SAM_TASK_ATTR_PASSTHROUGH,
	SAM_TASK_ATTR_UNTAGGED,
	SAM_TASK_ATTR_EMULATED
} t10_task_attr_index_t;

struct se_cmd_s;

typedef struct t10_alua_s {
	t10_alua_index_t alua_type;
	/* ALUA Target Port Group ID */
	u16	alua_tg_pt_gps_counter;
	u32	alua_tg_pt_gps_count;
	spinlock_t tg_pt_gps_lock;
	struct se_subsystem_dev_s *t10_sub_dev;
	/* Used for default ALUA Target Port Group */
	struct t10_alua_tg_pt_gp_s *default_tg_pt_gp;
	/* Used for default ALUA Target Port Group ConfigFS group */
	struct config_group alua_tg_pt_gps_group;
	int (*alua_state_check)(struct se_cmd_s *, unsigned char *, u8 *);
	struct list_head tg_pt_gps_list;
} ____cacheline_aligned t10_alua_t;

typedef struct t10_alua_lu_gp_s {
	u16	lu_gp_id;
	int	lu_gp_valid_id;
	u32	lu_gp_members;
	atomic_t lu_gp_shutdown;
	atomic_t lu_gp_ref_cnt;
	spinlock_t lu_gp_lock;
	struct config_group lu_gp_group;
	struct list_head lu_gp_list;
	struct list_head lu_gp_mem_list;
} ____cacheline_aligned t10_alua_lu_gp_t;

typedef struct t10_alua_lu_gp_member_s {
	int lu_gp_assoc;
	atomic_t lu_gp_mem_ref_cnt;
	spinlock_t lu_gp_mem_lock;
	t10_alua_lu_gp_t *lu_gp;
	struct se_device_s *lu_gp_mem_dev;
	struct list_head lu_gp_mem_list;
} ____cacheline_aligned t10_alua_lu_gp_member_t;

typedef struct t10_alua_tg_pt_gp_s {
	u16	tg_pt_gp_id;
	int	tg_pt_gp_valid_id;
	int	tg_pt_gp_alua_access_status;
	int	tg_pt_gp_alua_access_type;
	int	tg_pt_gp_nonop_delay_msecs;
	int	tg_pt_gp_trans_delay_msecs;
	int	tg_pt_gp_pref;
	int	tg_pt_gp_write_metadata;
	u32	tg_pt_gp_md_buf_len;
	u32	tg_pt_gp_members;
	atomic_t tg_pt_gp_alua_access_state;
	atomic_t tg_pt_gp_ref_cnt;
	spinlock_t tg_pt_gp_lock;
	struct mutex tg_pt_gp_md_mutex;
	struct se_subsystem_dev_s *tg_pt_gp_su_dev;
	struct config_group tg_pt_gp_group;
	struct list_head tg_pt_gp_list;
	struct list_head tg_pt_gp_mem_list;
} ____cacheline_aligned t10_alua_tg_pt_gp_t;

typedef struct t10_alua_tg_pt_gp_member_s {
	int tg_pt_gp_assoc;
	atomic_t tg_pt_gp_mem_ref_cnt;
	spinlock_t tg_pt_gp_mem_lock;
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	struct se_port_s *tg_pt;
	struct list_head tg_pt_gp_mem_list;
} ____cacheline_aligned t10_alua_tg_pt_gp_member_t;

typedef struct t10_vpd_s {
	unsigned char device_identifier[INQUIRY_VPD_DEVICE_IDENTIFIER_LEN];
	int protocol_identifier_set;
	u32 protocol_identifier;
	u32 device_identifier_code_set;
	u32 association;
	u32 device_identifier_type;
	struct list_head vpd_list;
} ____cacheline_aligned t10_vpd_t;

typedef struct t10_wwn_s {
	unsigned char vendor[8];
	unsigned char model[16];
	unsigned char revision[4];
	unsigned char unit_serial[INQUIRY_VPD_SERIAL_LEN];
	spinlock_t t10_vpd_lock;
	struct se_subsystem_dev_s *t10_sub_dev;
	struct config_group t10_wwn_group;
	struct list_head t10_vpd_list;
} ____cacheline_aligned t10_wwn_t;

typedef enum {
	SPC_PASSTHROUGH,
	SPC2_RESERVATIONS,
	SPC3_PERSISTENT_RESERVATIONS
} t10_reservations_index_t;

typedef struct t10_pr_registration_s {
	/* Used for fabrics that contain WWN+ISID */
	char pr_reg_isid[PR_REG_ISID_LEN];
	/* Used during APTPL metadata reading */
	unsigned char pr_iport[PR_APTPL_MAX_IPORT_LEN];
	/* Used during APTPL metadata reading */
	unsigned char pr_tport[PR_APTPL_MAX_TPORT_LEN];
	/* For writing out live meta data */
	unsigned char *pr_aptpl_buf;
	u16 pr_aptpl_rpti;
	u16 pr_reg_tpgt;
	int pr_reg_all_tg_pt; /* Reservation effects all target ports */
	int pr_reg_aptpl; /* Activate Persistence across Target Power Loss */
	int pr_res_holder;
	int pr_res_type;
	int pr_res_scope;
	u32 pr_reg_flags;
	u32 pr_res_mapped_lun;
	u32 pr_aptpl_target_lun;
	u32 pr_res_generation;
	u64 pr_reg_bin_isid;
	u64 pr_res_key;
	atomic_t pr_res_holders;
	struct se_node_acl_s *pr_reg_nacl;
	struct se_dev_entry_s *pr_reg_deve;
	struct se_lun_s *pr_reg_tg_pt_lun;
	struct list_head pr_reg_list;
	struct list_head pr_reg_abort_list;
	struct list_head pr_reg_aptpl_list;
	struct list_head pr_reg_atp_list;
	struct list_head pr_reg_atp_mem_list;
} ____cacheline_aligned t10_pr_registration_t;

typedef struct t10_reservation_template_s {
	/* Reservation effects all target ports */
	int pr_all_tg_pt;
	/* Activate Persistence across Target Power Loss enabled for SCSI device */
	int pr_aptpl_active;
	u32 pr_aptpl_buf_len;
	u32 pr_generation;
	t10_reservations_index_t res_type;
	spinlock_t registration_lock;
	spinlock_t aptpl_reg_lock;
	/* Reservation holder when pr_all_tg_pt=1 */
	struct se_node_acl_s *pr_res_holder;
	struct list_head registration_list;
	struct list_head aptpl_reg_list;
	int (*t10_reservation_check)(struct se_cmd_s *, u32 *);
	int (*t10_seq_non_holder)(struct se_cmd_s *, unsigned char *, u32);
	int (*t10_pr_register)(struct se_cmd_s *);
	int (*t10_pr_clear)(struct se_cmd_s *);
} ____cacheline_aligned t10_reservation_template_t;

typedef struct se_queue_req_s {
	int			state;
	void			*queue_se_obj_ptr;
	void			*cmd;
	struct se_obj_lun_type_s *queue_se_obj_api;
	struct list_head	qr_list;
} ____cacheline_aligned se_queue_req_t;

typedef struct se_queue_obj_s {
	atomic_t		queue_cnt;
	spinlock_t		cmd_queue_lock;
	struct list_head	qobj_list;
	wait_queue_head_t	thread_wq;
	struct completion	thread_create_comp;
	struct completion	thread_done_comp;
} ____cacheline_aligned se_queue_obj_t;

typedef struct se_transport_task_s {
	unsigned char		t_task_cdb[SCSI_CDB_SIZE];
	unsigned long long	t_task_lba;
	int			t_tasks_failed;
	u32			t_task_cdbs;
	u32			t_task_check;
	u32			t_task_no;
	u32			t_task_sectors;
	u32			t_task_se_num;
	atomic_t		t_fe_count;
	atomic_t		t_se_count;
	atomic_t		t_task_cdbs_left;
	atomic_t		t_task_cdbs_ex_left;
	atomic_t		t_task_cdbs_timeout_left;
	atomic_t		t_task_cdbs_sent;
	atomic_t		t_transport_aborted;
	atomic_t		t_transport_active;
	atomic_t		t_transport_complete;
	atomic_t		t_transport_queue_active;
	atomic_t		t_transport_sent;
	atomic_t		t_transport_stop;
	atomic_t		t_transport_timeout;
	atomic_t		transport_dev_active;
	atomic_t		transport_lun_active;
	atomic_t		transport_lun_fe_stop;
	atomic_t		transport_lun_stop;
	spinlock_t		t_state_lock;
	struct semaphore	t_transport_stop_sem;
	struct semaphore	t_transport_passthrough_sem;
	struct semaphore	t_transport_passthrough_wsem;
	struct semaphore	transport_lun_fe_stop_sem;
	struct semaphore	transport_lun_stop_sem;
	void			*t_task_buf;
	void			*t_task_pt_buf;
	struct list_head	t_task_list;
	struct list_head	*t_mem_list;
} ____cacheline_aligned se_transport_task_t;

typedef struct se_task_s {
	unsigned char	task_sense;
	struct scatterlist *task_sg;
	void		*transport_req;
	u8		task_scsi_status;
	u8		task_flags;
	int		task_error_status;
	int		task_state_flags;
	unsigned long long	task_lba;
	u32		task_no;
	u32		task_sectors;
	u32		task_size;
	u32		task_sg_num;
	u32		task_sg_offset;
	struct se_cmd_s *task_se_cmd;
	struct se_device_s	*se_dev;
	struct semaphore	task_stop_sem;
	atomic_t	task_active;
	atomic_t	task_execute_queue;
	atomic_t	task_timeout;
	atomic_t	task_sent;
	atomic_t	task_stop;
	atomic_t	task_state_active;
	struct timer_list	task_timer;
	int (*transport_map_task)(struct se_task_s *, u32);
	void *se_obj_ptr;
	struct se_obj_lun_type_s *se_obj_api;
	struct list_head t_list;
	struct list_head t_execute_list;
	struct list_head t_state_list;
} ____cacheline_aligned se_task_t;

#define TASK_CMD(task)	((struct se_cmd_s *)task->task_se_cmd)
#define TASK_DEV(task)	((struct se_device_s *)task->se_dev)

typedef struct se_transform_info_s {
	int		ti_set_counts;
	u32		ti_data_length;
	unsigned long long	ti_lba;
	struct se_cmd_s *ti_se_cmd;
	struct se_device_s *ti_dev;
	void *se_obj_ptr;
	void *ti_obj_ptr;
	struct se_obj_lun_type_s *se_obj_api;
	struct se_obj_lun_type_s *ti_obj_api;
} ____cacheline_aligned se_transform_info_t;

typedef struct se_offset_map_s {
	int                     map_reset;
	u32                     iovec_length;
	u32                     iscsi_offset;
	u32                     current_offset;
	u32                     orig_offset;
	u32                     sg_count;
	u32                     sg_current;
	u32                     sg_length;
	struct page		*sg_page;
	struct se_mem_s		*map_se_mem;
	struct se_mem_s		*map_orig_se_mem;
	void			*iovec_base;
} ____cacheline_aligned se_offset_map_t;

typedef struct se_map_sg_s {
	int			map_flags;
	u32			data_length;
	u32			data_offset;
	void			*fabric_cmd;
	struct se_cmd_s		*se_cmd;
	struct iovec		*iov;
} ____cacheline_aligned se_map_sg_t;

typedef struct se_unmap_sg_s {
	u32			data_length;
	u32			sg_count;
	u32			sg_offset;
	u32			padding;
	u32			t_offset;
	void			*fabric_cmd;
	struct se_cmd_s		*se_cmd;
	se_offset_map_t		lmap;
	struct se_mem_s		*cur_se_mem;
} ____cacheline_aligned se_unmap_sg_t;

typedef struct se_cmd_s {
	/* SAM response code being sent to initiator */
	u8			scsi_status;
	u8			scsi_asc;
	u8			scsi_ascq;
	u8			scsi_sense_reason;
	u16			scsi_sense_length;
	/* Delay for ALUA Active/NonOptimized state access in milliseconds */
	int			alua_nonop_delay;
	int			data_direction;
	/* For SAM Task Attribute */
	int			sam_task_attr;
	/* Transport protocol dependent state */
	int			t_state;
	/* Transport protocol dependent state for out of order CmdSNs */
	int			deferred_t_state;
	/* Transport specific error status */
	int			transport_error_status;
	u32			se_cmd_flags;
	u32			se_ordered_id;
	/* Total size in bytes associated with command */
	u32			data_length;
	/* SCSI Presented Data Transfer Length */
	u32			cmd_spdtl;
	u32			residual_count;
	u32			orig_fe_lun;
	/* Number of iovecs iovecs used for IP stack calls */
	u32			iov_data_count;
	/* Number of iovecs allocated for iscsi_cmd_t->iov_data */
	u32			orig_iov_data_count;
	/* Persistent Reservation key */
	u64			pr_res_key;
	atomic_t                transport_sent;
	/* Used for sense data */
	void			*sense_buffer;
	/* Used with sockets based fabric plugins */
	struct iovec		*iov_data;
	struct list_head	se_delayed_list;
	struct list_head	se_ordered_list;
	struct list_head	se_lun_list;
	struct se_device_s      *se_dev;
	struct se_dev_entry_s   *se_deve;
	struct se_lun_s		*se_lun;
	struct se_obj_lun_type_s *se_obj_api;
	void			*se_obj_ptr;
	struct se_obj_lun_type_s *se_orig_obj_api;
	void			*se_orig_obj_ptr;
	void			*se_fabric_cmd_ptr;
	struct se_session_s	*se_sess;
	struct se_tmr_req_s	*se_tmr_req;
	struct se_transport_task_s *t_task;
	struct target_core_fabric_ops *se_tfo;
	int (*transport_add_cmd_to_queue)(struct se_cmd_s *, u8);
	int (*transport_allocate_iovecs)(struct se_cmd_s *);
	int (*transport_allocate_resources)(struct se_cmd_s *, u32, u32);
	int (*transport_cdb_transform)(struct se_cmd_s *,
					struct se_transform_info_s *);
	int (*transport_do_transform)(struct se_cmd_s *,
					struct se_transform_info_s *);
	int (*transport_emulate_cdb)(struct se_cmd_s *);
	void (*transport_free_resources)(struct se_cmd_s *);
	u32 (*transport_get_lba)(unsigned char *);
	unsigned long long (*transport_get_long_lba)(unsigned char *);
	struct se_task_s *(*transport_get_task)(struct se_transform_info_s *,
					struct se_cmd_s *, void *,
					struct se_obj_lun_type_s *);
	int (*transport_map_buffers_to_tasks)(struct se_cmd_s *);
	void (*transport_map_SG_segments)(struct se_unmap_sg_s *);
	void (*transport_passthrough_done)(struct se_cmd_s *);
	void (*transport_unmap_SG_segments)(struct se_unmap_sg_s *);
	int (*transport_set_iovec_ptrs)(struct se_map_sg_s *,
					struct se_unmap_sg_s *);
	void (*transport_split_cdb)(unsigned long long, u32 *, unsigned char *);
	void (*transport_wait_for_tasks)(struct se_cmd_s *, int, int);
	void (*callback)(struct se_cmd_s *cmd, void *callback_arg,
			int complete_status);
	void *callback_arg;
} ____cacheline_aligned se_cmd_t;

#define T_TASK(cmd)     ((se_transport_task_t *)(cmd->t_task))
#define CMD_OBJ_API(cmd) ((struct se_obj_lun_type_s *)(cmd->se_obj_api))
#define CMD_ORIG_OBJ_API(cmd) ((struct se_obj_lun_type_s *)	\
				(cmd->se_orig_obj_api))
#define CMD_TFO(cmd) ((struct target_core_fabric_ops *)cmd->se_tfo)

typedef struct se_tmr_req_s {
	/* Task Management function to be preformed */
	u8			function;
	/* Task Management response to send */
	u8			response;
	int			call_transport;
	/* Reference to ITT that Task Mgmt should be preformed */
	u32			ref_task_tag;
	/* 64-bit encoded SAM LUN from $FABRIC_MOD TMR header */
	u64			ref_task_lun;
	void 			*fabric_tmr_ptr;
	se_cmd_t		*task_cmd;
	se_cmd_t		*ref_cmd;
	struct se_device_s	*tmr_dev;
	struct se_lun_s		*tmr_lun;
	struct list_head	tmr_list;
} ____cacheline_aligned se_tmr_req_t;

typedef struct se_ua_s {
	u8			ua_asc;
	u8			ua_ascq;
	struct se_node_acl_s	*ua_nacl;
	struct list_head	ua_dev_list;
	struct list_head	ua_nacl_list;
} ____cacheline_aligned se_ua_t;

typedef struct se_node_acl_s {
	char			initiatorname[TRANSPORT_IQN_LEN];
	int			nodeacl_flags;
	u32			queue_depth;
#ifdef SNMP_SUPPORT
	u32			acl_index;
	u64			num_cmds;
	u64			read_bytes;
	u64			write_bytes;
	spinlock_t		stats_lock;
#endif /* SNMP_SUPPORT */
	/* Used for PR SPEC_I_PT=1 and REGISTER_AND_MOVE */
	atomic_t		acl_pr_ref_count;
	struct se_dev_entry_s	*device_list;
	struct se_session_s	*nacl_sess;
	struct se_portal_group_s *se_tpg;
	spinlock_t		device_list_lock;
	spinlock_t		nacl_sess_lock;
	struct config_group	acl_group;
	struct config_group	acl_param_group;
	struct list_head	acl_list;
	struct list_head	acl_sess_list;
} ____cacheline_aligned se_node_acl_t;

typedef struct se_session_s {
	u64			sess_bin_isid;
	struct se_node_acl_s	*se_node_acl;
	struct se_portal_group_s *se_tpg;
	void			*fabric_sess_ptr;
	struct list_head	sess_list;
	struct list_head	sess_acl_list;
} ____cacheline_aligned se_session_t;

#define SE_SESS(cmd)		((struct se_session_s *)(cmd)->se_sess)
#define SE_NODE_ACL(sess)	((struct se_node_acl_s *)(sess)->se_node_acl)

struct se_device_s;
struct se_transform_info_s;
struct se_obj_lun_type_s;
struct scatterlist;

typedef struct se_lun_acl_s {
	char			initiatorname[TRANSPORT_IQN_LEN];
	u32			mapped_lun;
	struct se_node_acl_s	*se_lun_nacl;
	struct se_lun_s		*se_lun;
	struct list_head	lacl_list;
	struct config_group	se_lun_group;
}  ____cacheline_aligned se_lun_acl_t;

typedef struct se_dev_entry_s {
	u32			lun_flags;
	u32			deve_cmds;
	u32			deve_flags;
	u32			mapped_lun;
	u32			average_bytes;
	u32			last_byte_count;
	u32			total_cmds;
	u32			total_bytes;
	u64			pr_res_key;
#ifdef SNMP_SUPPORT
	u64			creation_time;
	u32			attach_count;
	u64			read_bytes;
	u64			write_bytes;
#endif /* SNMP_SUPPORT */
	atomic_t		ua_count;
	/* Used for PR SPEC_I_PT=1 and REGISTER_AND_MOVE */
	atomic_t		pr_ref_count;
	se_lun_acl_t		*se_lun_acl;
	spinlock_t		ua_lock;
	struct se_lun_s		*se_lun;
	struct list_head	alua_port_list;
	struct list_head	ua_list;
}  ____cacheline_aligned se_dev_entry_t;

typedef struct se_dev_attrib_s {
	int		emulate_ua_intlck_ctrl;
	int		emulate_tas;
	int		emulate_reservations;
	int		emulate_alua;
	int		enforce_pr_isids;
	u32		hw_block_size;
	u32		block_size;
	u32		hw_max_sectors;
	u32		max_sectors;
	u32		hw_queue_depth;
	u32		queue_depth;
	u32		task_timeout;
	struct se_subsystem_dev_s *da_sub_dev;
	struct config_group da_group;
} ____cacheline_aligned se_dev_attrib_t;

typedef struct se_dev_snap_attrib_s {
	unsigned char	contact[SNAP_CONTACT_LEN];
	unsigned char	lv_group[SNAP_GROUP_LEN];
	unsigned char	lvc_size[SNAP_LVC_LEN]; /* in lvcreate --size shorthand */
	pid_t		pid;
	int		enabled;	
	int		permissions;
	int		max_snapshots;
	int		max_warn;
	int		check_interval;
	int		create_interval;
	int		usage;
	int		usage_warn;
	int		vgs_usage_warn;
} se_dev_snap_attrib_t;

typedef struct se_subsystem_dev_s {
	unsigned char	se_dev_alias[SE_DEV_ALIAS_LEN];
	unsigned char	se_dev_udev_path[SE_UDEV_PATH_LEN];
	u32		su_dev_flags;
	struct se_hba_s *se_dev_hba;
	struct se_device_s *se_dev_ptr;
	se_dev_attrib_t se_dev_attrib;
	se_dev_snap_attrib_t se_snap_attrib;
	/* T10 Asymmetric Logical Unit Assignment for Target Ports */
	t10_alua_t	t10_alua;
	/* T10 Inquiry and VPD WWN Information */
	t10_wwn_t	t10_wwn;
	/* T10 SPC-2 + SPC-3 Reservations */
	t10_reservation_template_t t10_reservation;
	spinlock_t      se_dev_lock;
	void            *se_dev_su_ptr;
	struct list_head g_se_dev_list;
	struct config_group se_dev_group;
	/* For T10 Reservations */
	struct config_group se_dev_pr_group;
	/* For userspace lvm utils */
	struct config_group se_dev_snap_group;
} ____cacheline_aligned se_subsystem_dev_t;

#define SE_DEV_SNAP(su_dev)	(&(su_dev)->se_snap_attrib)
#define T10_ALUA(su_dev)	(&(su_dev)->t10_alua)
#define T10_RES(su_dev)		(&(su_dev)->t10_reservation)

typedef struct se_device_s {
	/* Type of disk transport used for device */
	u8			type;
	/* Set to 1 if thread is NOT sleeping on thread_sem */
	u8			thread_active;
	u8			dev_status_timer_flags;
	/* RELATIVE TARGET PORT IDENTIFER Counter */
	u16			dev_rpti_counter;
	/* Used for SAM Task Attribute ordering */
	u32			dev_cur_ordered_id;
	u32			dev_flags;
	u32			dev_port_count;
	u32			dev_status;
	u32			dev_tcq_window_closed;
	/* Physical device queue depth */
	u32			queue_depth;
	/* Used for SPC-2 reservations enforce of ISIDs */
	u64			dev_res_bin_isid;
	t10_task_attr_index_t	dev_task_attr_type;
	unsigned long long	dev_sectors_total;
	/* Pointer to transport specific device structure */
	void 			*dev_ptr;
#ifdef SNMP_SUPPORT
	u32			dev_index;
	u64			creation_time;
	u32			num_resets;
	u64			num_cmds;
	u64			read_bytes;
	u64			write_bytes;
	spinlock_t		stats_lock;
#endif /* SNMP_SUPPORT */
	/* Active commands on this virtual SE device */
	atomic_t		active_cmds;
	atomic_t		simple_cmds;
	atomic_t		depth_left;
	atomic_t		dev_ordered_id;
	atomic_t		dev_tur_active;
	atomic_t		execute_tasks;
	atomic_t		dev_status_thr_count;
	atomic_t		dev_hoq_count;
	atomic_t		dev_ordered_sync;
	struct se_obj_s		dev_obj;
	struct se_obj_s		dev_access_obj;
	struct se_obj_s		dev_export_obj;
	struct se_obj_s		dev_feature_obj;
	se_queue_obj_t		*dev_queue_obj;
	se_queue_obj_t		*dev_status_queue_obj;
	spinlock_t		delayed_cmd_lock;
	spinlock_t		ordered_cmd_lock;
	spinlock_t		execute_task_lock;
	spinlock_t		state_task_lock;
	spinlock_t		dev_alua_lock;
	spinlock_t		dev_reservation_lock;
	spinlock_t		dev_state_lock;
	spinlock_t		dev_status_lock;
	spinlock_t		dev_status_thr_lock;
	spinlock_t		se_port_lock;
	spinlock_t		se_tmr_lock;
	/* Used for legacy SPC-2 reservationsa */
	struct se_node_acl_s	*dev_reserved_node_acl;
	/* Used for ALUA Logical Unit Group membership */
	struct t10_alua_lu_gp_member_s *dev_alua_lu_gp_mem;
	/* Used for SPC-3 Persistent Reservations */
	struct t10_pr_registration_s *dev_pr_res_holder;
	struct list_head	dev_sep_list;
	struct list_head	dev_tmr_list;
	struct timer_list	dev_status_timer;
	/* Pointer to descriptor for processing thread */
	struct task_struct	*process_thread;
	pid_t			process_thread_pid;
	struct task_struct		*dev_mgmt_thread;
	int (*write_pending)(struct se_task_s *);
	void (*dev_generate_cdb)(unsigned long long, u32 *,
					unsigned char *, int);
	struct se_obj_lun_type_s *dev_obj_api;
	struct list_head	delayed_cmd_list;
	struct list_head	ordered_cmd_list;
	struct list_head	execute_task_list;
	struct list_head	state_task_list;
	/* Pointer to associated SE HBA */
	struct se_hba_s		*se_hba;
	struct se_subsystem_dev_s *se_sub_dev;
	/* Pointer to template of function pointers for transport */
	struct se_subsystem_api_s *transport;
	/* Linked list for se_hba_t se_device_t list */
	struct list_head	dev_list;
	/* Linked list for se_global_t->g_se_dev_list */
	struct list_head	g_se_dev_list;
}  ____cacheline_aligned se_device_t;

#define SE_DEV(cmd)		((se_device_t *)(cmd)->se_lun->se_dev)
#define SU_DEV(dev)		((se_subsystem_dev_t *)(dev)->se_sub_dev)
#define ISCSI_DEV(cmd)		SE_DEV(cmd)
#define DEV_ATTRIB(dev)		(&(dev)->se_sub_dev->se_dev_attrib)
#define DEV_T10_WWN(dev)	(&(dev)->se_sub_dev->t10_wwn)
#define DEV_OBJ_API(dev)	((struct se_obj_lun_type_s *)(dev)->dev_obj_api)

typedef struct se_hba_s {
	/* Type of disk transport used for HBA. */
	u8			type;
	u16			hba_tpgt;
	u32			hba_status;
	u32			hba_id;
	u32			hba_flags;
	/* Virtual iSCSI devices attached. */
	u32			dev_count;
#ifdef SNMP_SUPPORT
	u32			hba_index;
#endif
	atomic_t		dev_mib_access_count;
	atomic_t		load_balance_queue;
	atomic_t		left_queue_depth;
	/* Maximum queue depth the HBA can handle. */
	atomic_t		max_queue_depth;
	/* Pointer to transport specific host structure. */
	void			*hba_ptr;
	/* Linked list for se_device_t */
	struct list_head	hba_dev_list;
	struct list_head	hba_list;
	spinlock_t		device_lock;
	spinlock_t		hba_queue_lock;
	struct config_group	hba_group;
	struct semaphore	hba_access_sem;
	struct se_subsystem_api_s *transport;
}  ____cacheline_aligned se_hba_t;

#define ISCSI_HBA(d)		((se_hba_t *)(d)->se_hba)
/* Using SE_HBA() for new code */
#define SE_HBA(d)		((se_hba_t *)(d)->se_hba)

typedef struct se_lun_s {
	int			lun_type;
	int			lun_status;
	u32			lun_access;
	u32			lun_flags;
	u32			unpacked_lun;
	atomic_t		lun_acl_count;
	spinlock_t		lun_acl_lock;
	spinlock_t		lun_cmd_lock;
	spinlock_t		lun_sep_lock;
	struct completion	lun_shutdown_comp;
	struct list_head	lun_cmd_list;
	struct list_head	lun_acl_list;
	se_device_t		*se_dev;
	void			*lun_type_ptr;
	struct config_group	lun_group;
	struct se_obj_lun_type_s *lun_obj_api;
	struct se_port_s	*lun_sep;
} ____cacheline_aligned se_lun_t;

#define SE_LUN(c)		((se_lun_t *)(c)->se_lun)
#define ISCSI_LUN(c)		SE_LUN(c)
#define LUN_OBJ_API(lun)	((struct se_obj_lun_type_s *)(lun)->lun_obj_api)

typedef struct se_port_s {
	/* RELATIVE TARGET PORT IDENTIFER */
	u16		sep_rtpi;
	int		sep_tg_pt_secondary_stat;
	int		sep_tg_pt_secondary_write_md;
#ifdef SNMP_SUPPORT
	u32		sep_index;
	scsi_port_stats_t sep_stats;
#endif
	/* Used for ALUA Target Port Groups membership */
	atomic_t	sep_tg_pt_gp_active;
	atomic_t	sep_tg_pt_secondary_offline;
	/* Used for PR ALL_TG_PT=1 */
	atomic_t	sep_tg_pt_ref_cnt;
	spinlock_t	sep_alua_lock;
	struct mutex	sep_tg_pt_md_mutex;
	struct t10_alua_tg_pt_gp_member_s *sep_alua_tg_pt_gp_mem;
	struct se_lun_s *sep_lun;
	struct se_portal_group_s *sep_tpg;
	struct list_head sep_alua_list;
	struct list_head sep_list;
} ____cacheline_aligned se_port_t;

typedef struct se_portal_group_s {
	/* Type of target portal group */
	int			se_tpg_type;
	/* Number of ACLed Initiator Nodes for this TPG */
	u32			num_node_acls;
	/* Used for PR SPEC_I_PT=1 and REGISTER_AND_MOVE */
	atomic_t		tpg_pr_ref_count;
	/* Spinlock for adding/removing ACLed Nodes */
	spinlock_t		acl_node_lock;
	/* Spinlock for adding/removing sessions */
	spinlock_t		session_lock;
	spinlock_t		tpg_lun_lock;
	/* Pointer to $FABRIC_MOD portal group */
	void			*se_tpg_fabric_ptr;
	struct list_head	se_tpg_list;
	/* linked list for initiator ACL list */
	struct list_head	acl_node_list;
	struct se_lun_s		*tpg_lun_list;
	struct se_lun_s		tpg_virt_lun0;
	/* List of TCM sessions assoicated wth this TPG */
	struct list_head	tpg_sess_list;
	/* Pointer to $FABRIC_MOD dependent code */
	struct target_core_fabric_ops *se_tpg_tfo;
	struct config_group	tpg_group;
} ____cacheline_aligned se_portal_group_t;

#define TPG_TFO(se_tpg)	((struct target_core_fabric_ops *)(se_tpg)->se_tpg_tfo)

typedef struct se_global_s {
	u16			alua_lu_gps_counter;
	u32			in_shutdown;
	u32			alua_lu_gps_count;
	u32			g_hba_id_counter;
	struct config_group	target_core_hbagroup;
	struct config_group	alua_group;
	struct config_group	alua_lu_gps_group;
	struct list_head	g_lu_gps_list;
	struct list_head	g_se_tpg_list;
	struct list_head	g_hba_list;
	struct list_head	g_se_dev_list;
	struct se_hba_s		*g_lun0_hba;
	struct se_subsystem_dev_s *g_lun0_su_dev;
	struct se_device_s	*g_lun0_dev;
	struct se_plugin_class_s *plugin_class_list;
	t10_alua_lu_gp_t	*default_lu_gp;
	spinlock_t		g_device_lock;
	spinlock_t		hba_lock;
	spinlock_t		se_tpg_lock;
	spinlock_t		lu_gps_lock;
	spinlock_t		plugin_class_lock;
#ifdef DEBUG_DEV
	spinlock_t		debug_dev_lock;
#endif
} ____cacheline_aligned se_global_t;

#endif /* TARGET_CORE_BASE_H */
