/*******************************************************************************
 * Filename:  target_core_alua.c
 *
 * This file contains SPC-3 compliant asymmetric logical unit assigntment (ALUA)
 *
 * Copyright (c) 2009 Rising Tide, Inc.
 * Copyright (c) 2009 Linux-iSCSI.org
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
 ******************************************************************************/

#define TARGET_CORE_ALUA_C

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/configfs.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <scsi/scsi.h>
#include <scsi/scsi_cmnd.h>

#include <../lio-core/iscsi_linux_defs.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_transport.h>
#include <target/target_core_alua.h>
#include <target/target_core_transport_plugin.h>
#include <target/target_core_ua.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>

#undef TARGET_CORE_ALUA_C

/*
 * REPORT_TARGET_PORT_GROUPS
 *
 * See spc4r17 section 6.27
 */
int core_scsi3_emulate_report_target_port_groups(se_cmd_t *cmd)
{
	se_subsystem_dev_t *su_dev = SE_DEV(cmd)->se_sub_dev;
	se_port_t *port;
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	u32 rd_len = 0, off = 4;

	spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	list_for_each_entry(tg_pt_gp, &T10_ALUA(su_dev)->tg_pt_gps_list,
			tg_pt_gp_list) {
		/*
		 * PREF: Preferred target port bit, determine if this
		 * bit should be set for port group.
		 */
		if (tg_pt_gp->tg_pt_gp_pref)
			buf[off] = 0x80;
		/*
		 * Set the ASYMMETRIC ACCESS State
		 */
		buf[off++] |= (atomic_read(
			&tg_pt_gp->tg_pt_gp_alua_access_state) & 0xff);
		/*
		 * Set supported ASYMMETRIC ACCESS State bits
		 */
		buf[off] = 0x80; // T_SUP */
		buf[off] |= 0x40; /* O_SUP */
		buf[off] |= 0x8; /* U_SUP */
		buf[off] |= 0x4; /* S_SUP */
		buf[off] |= 0x2; /* AN_SUP */
		buf[off++] |= 0x1; /* AO_SUP */
		/*
		 * TARGET PORT GROUP
		 */
		buf[off++] = ((tg_pt_gp->tg_pt_gp_id >> 8) & 0xff);
		buf[off++] = (tg_pt_gp->tg_pt_gp_id & 0xff);

		off++; /* Skip over Reserved */
		/*
		 * STATUS CODE
		 */
		buf[off++] = (tg_pt_gp->tg_pt_gp_alua_access_status & 0xff);
		/*
		 * Vendor Specific field
		 */
		buf[off++] = 0x00;
		/*
		 * TARGET PORT COUNT
		 */
		buf[off++] = (tg_pt_gp->tg_pt_gp_members & 0xff);
		rd_len += 8;

		spin_lock(&tg_pt_gp->tg_pt_gp_lock);
		list_for_each_entry(tg_pt_gp_mem, &tg_pt_gp->tg_pt_gp_mem_list,
				tg_pt_gp_mem_list) {
			port = tg_pt_gp_mem->tg_pt;
			/*
			 * Start Target Port descriptor format
			 *
			 * See spc4r17 section 6.2.7 Table 247
			 */
			off += 2; /* Skip over Obsolete */
			/*
			 * Set RELATIVE TARGET PORT IDENTIFIER
			 */
			buf[off++] = ((port->sep_rtpi >> 8) & 0xff);
			buf[off++] = (port->sep_rtpi & 0xff);
			rd_len += 4;
		}
		spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
	}
	spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	/*
	 * Set the RETURN DATA LENGTH set in the header of the DataIN Payload
	 */
	buf[0] = ((rd_len >> 24) & 0xff);
	buf[1] = ((rd_len >> 16) & 0xff);
	buf[2] = ((rd_len >> 8) & 0xff);
	buf[3] = (rd_len & 0xff);

	return 0;
}

/*
 * SET_TARGET_PORT_GROUPS for explict ALUA operation.
 *
 * See spc4r17 section 6.35
 */
int core_scsi3_emulate_set_target_port_groups(se_cmd_t *cmd)
{
	se_device_t *dev = SE_DEV(cmd);
	se_subsystem_dev_t *su_dev = SE_DEV(cmd)->se_sub_dev;
	se_port_t *port, *l_port = SE_LUN(cmd)->lun_sep;
	se_node_acl_t *nacl = SE_SESS(cmd)->se_node_acl;
	t10_alua_tg_pt_gp_t *tg_pt_gp = NULL, *l_tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem, *l_tg_pt_gp_mem;
	unsigned char *buf = (unsigned char *)T_TASK(cmd)->t_task_buf;
	unsigned char *ptr = &buf[4]; /* Skip over RESERVED area in header */
	u32 len = 4; /* Skip over RESERVED area in header */
	int alua_access_state, primary = 0, ret;
	u16 tg_pt_id, rtpi;

	if (!(l_port))
		return -1;
	/*
	 * Determine if explict ALUA via SET_TARGET_PORT_GROUPS is allowed
	 * for the local tg_pt_gp.
	 */
	l_tg_pt_gp_mem = l_port->sep_alua_tg_pt_gp_mem;
	if (!(l_tg_pt_gp_mem)) {
		printk(KERN_ERR "Unable to access *l_tg_pt_gp_mem\n");
		return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
	}
	spin_lock(&l_tg_pt_gp_mem->tg_pt_gp_mem_lock);
	l_tg_pt_gp = l_tg_pt_gp_mem->tg_pt_gp;
	if (!(l_tg_pt_gp)) {
		spin_unlock(&l_tg_pt_gp_mem->tg_pt_gp_mem_lock);
		printk(KERN_ERR "Unable to access *l_l_tg_pt_gp\n");
		return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
	}
	ret = (l_tg_pt_gp->tg_pt_gp_alua_access_type & TPGS_EXPLICT_ALUA);
	spin_unlock(&l_tg_pt_gp_mem->tg_pt_gp_mem_lock);

	if (!(ret)) {
		printk(KERN_INFO "Unable to process SET_TARGET_PORT_GROUPS"
				" while TPGS_EXPLICT_ALUA is disabled\n");
		return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
	}

	while (len < cmd->data_length) {
		alua_access_state = (ptr[0] & 0x0f);
		/*
		 * Check the received ALUA access state, and determine if
		 * the state is a primary or secondary target port asymmetric
		 * access state.
		 */
		ret = core_alua_check_transition(alua_access_state, &primary);
		if (ret != 0) {
			/*
			 * If the SET TARGET PORT GROUPS attempts to establish
			 * an invalid combination of target port asymmetric
			 * access states or attempts to establish an
			 * unsupported target port asymmetric access state,
			 * then the command shall be terminated with CHECK
			 * CONDITION status, with the sense key set to ILLEGAL
			 * REQUEST, and the additional sense code set to INVALID
			 * FIELD IN PARAMETER LIST.
			 */
			return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		}
		ret = -1;
		/*
		 * If the ASYMMETRIC ACCESS STATE field (see table 267)
		 * specifies a primary target port asymmetric access state,
		 * then the TARGET PORT GROUP OR TARGET PORT field specifies
		 * a primary target port group for which the primary target
		 * port asymmetric access state shall be changed. If the
		 * ASYMMETRIC ACCESS STATE field specifies a secondary target
		 * port asymmetric access state, then the TARGET PORT GROUP OR
		 * TARGET PORT field specifies the relative target port
		 * identifier (see 3.1.120) of the target port for which the
		 * secondary target port asymmetric access state shall be
		 * changed.
		 */
		if (primary) {
			tg_pt_id = ((ptr[2] << 8) & 0xff);
			tg_pt_id |= (ptr[3] & 0xff);
			/*
			 * Locate the matching target port group ID from
			 * the global tg_pt_gp list
			 */
			spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
			list_for_each_entry(tg_pt_gp,
					&T10_ALUA(su_dev)->tg_pt_gps_list,
					tg_pt_gp_list) {
				if (!(tg_pt_gp->tg_pt_gp_valid_id))
					continue;

				if (tg_pt_id != tg_pt_gp->tg_pt_gp_id)
					continue;

				atomic_inc(&tg_pt_gp->tg_pt_gp_ref_cnt);
				smp_mb__after_atomic_inc();
				spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);

				ret = core_alua_do_port_transition(tg_pt_gp,
						dev, l_port, nacl,
						alua_access_state, 1);

				spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
				atomic_dec(&tg_pt_gp->tg_pt_gp_ref_cnt);
				smp_mb__after_atomic_dec();	
				break;
			}
			spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
			/*
			 * If not matching target port group ID can be located
			 * throw an exception with ASCQ: INVALID_PARAMETER_LIST
			 */
			if (ret != 0)
				return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		} else {
			rtpi = ((ptr[2] << 8) & 0xff);
			rtpi |= (ptr[3] & 0xff);
			/*
			 * Locate the matching relative target port identifer
			 * for the se_device_t storage object.
			 */
			spin_lock(&dev->se_port_lock);
			list_for_each_entry(port, &dev->dev_sep_list,
							sep_list) {
				if (port->sep_rtpi != rtpi)
					continue;

				tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
				spin_unlock(&dev->se_port_lock);

				ret = core_alua_set_tg_pt_secondary_state(
						tg_pt_gp_mem, port, 1, 1);

				spin_lock(&dev->se_port_lock);
				break;
			}
			spin_unlock(&dev->se_port_lock);
			/*
			 * If not matching relative target port identifier can
			 * be located, throw an exception with ASCQ:
			 * INVALID_PARAMETER_LIST
			 */
			if (ret != 0)
				return PYX_TRANSPORT_INVALID_PARAMETER_LIST;
		}

		ptr += 4;
		len += 4;
	}

	return 0;
}

static inline int core_alua_state_optimized(
	struct se_cmd_s *cmd,
	unsigned char *cdb,
	u8 *alua_ascq)
{
	/*
	 * For the Optimized ALUA access state case, we want to process the
	 * incoming fabric cmd ASAP..
	 */
	return 0;
}

static inline int core_alua_state_nonoptimized(
	struct se_cmd_s *cmd,
	unsigned char *cdb,
	int nonop_delay_msecs,
	u8 *alua_ascq)
{
	/*
	 * Set SCF_ALUA_NON_OPTIMIZED here, this value will be checked
	 * later to determine if processing of this cmd needs to be
	 * temporarily delayed for the Active/NonOptimized primary access state.
	 */
	cmd->se_cmd_flags |= SCF_ALUA_NON_OPTIMIZED;
	cmd->alua_nonop_delay = nonop_delay_msecs;
	return 0;
}

static inline int core_alua_state_standby(
	struct se_cmd_s *cmd,
	unsigned char *cdb,
	u8 *alua_ascq)
{
	/*
	 * Allowed CDBs for ALUA_ACCESS_STATE_STANDBY as defined by
	 * spc4r17 section 5.9.2.4.4
	 */
	switch (cdb[0]) {
	case INQUIRY:
	case LOG_SELECT:
	case LOG_SENSE:
	case MODE_SELECT:
	case MODE_SENSE:
	case REPORT_LUNS:
	case RECEIVE_DIAGNOSTIC:
	case SEND_DIAGNOSTIC:
	case 0xa3:
		switch (cdb[1]) {
		case MI_REPORT_TARGET_PGS:
			return 0;
		default:
			*alua_ascq = ASCQ_04H_ALUA_TG_PT_STANDBY;
			return 1;
		}
	case 0xa4:
		switch (cdb[1]) {
		case MO_SET_TARGET_PGS:
			return 0;
		default:
			*alua_ascq = ASCQ_04H_ALUA_TG_PT_STANDBY;
			return 1;
		}
	case REQUEST_SENSE:
	case PERSISTENT_RESERVE_IN:
	case PERSISTENT_RESERVE_OUT:
	case READ_BUFFER:
	case WRITE_BUFFER:
		return 0;
	default:
		*alua_ascq = ASCQ_04H_ALUA_TG_PT_STANDBY;
		return 1;
	}

	return 0;
}

static inline int core_alua_state_unavailable(
	struct se_cmd_s *cmd,
	unsigned char *cdb,
	u8 *alua_ascq)
{
	/*
	 * Allowed CDBs for ALUA_ACCESS_STATE_UNAVAILABLE as defined by
	 * spc4r17 section 5.9.2.4.5
	 */
	switch (cdb[0]) {
	case INQUIRY:
	case REPORT_LUNS:
	case 0xa3:
		switch (cdb[1]) {
		case MI_REPORT_TARGET_PGS:
			return 0;
		default:
			*alua_ascq = ASCQ_04H_ALUA_TG_PT_UNAVAILABLE;
			return 1;
		}
	case 0xa4:
		switch (cdb[1]) {
		case MO_SET_TARGET_PGS:
			return 0;
		default:
			*alua_ascq = ASCQ_04H_ALUA_TG_PT_UNAVAILABLE;
			return 1;
		}
	case REQUEST_SENSE:
	case READ_BUFFER:
	case WRITE_BUFFER:
		return 0;
	default:
		*alua_ascq = ASCQ_04H_ALUA_TG_PT_UNAVAILABLE;
		return 1;
	}
	
	return 0;
}

static inline int core_alua_state_transition(
	struct se_cmd_s *cmd,
	unsigned char *cdb,
	u8 *alua_ascq)
{
	/*
	 * Allowed CDBs for ALUA_ACCESS_STATE_TRANSITIO as defined by
	 * spc4r17 section 5.9.2.5
	 */
	switch (cdb[0]) {
	case INQUIRY:
	case REPORT_LUNS:
	case 0xa3:
		switch (cdb[1]) {
		case MI_REPORT_TARGET_PGS:
			return 0;
		default:
			*alua_ascq = ASCQ_04H_ALUA_STATE_TRANSITION;
			return 1;
		}
	case REQUEST_SENSE:
	case READ_BUFFER:
	case WRITE_BUFFER:
		return 0;
	default:
		*alua_ascq = ASCQ_04H_ALUA_STATE_TRANSITION;
		return 1;
	}

	return 0;
}

/*
 * Used for alua_type SPC_ALUA_PASSTHROUGH and SPC2_ALUA_DISABLED
 */
int core_alua_state_check_nop(
	struct se_cmd_s *cmd,
	unsigned char *cdb,
	u8 *alua_ascq)
{
	return 0;
}

/*
 * Used for alua_type SPC3_ALUA_EMULATED
 */
int core_alua_state_check(
	struct se_cmd_s *cmd,
	unsigned char *cdb,
	u8 *alua_ascq)
{
	se_lun_t *lun = SE_LUN(cmd);
	se_port_t *port = lun->lun_sep;
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	int out_alua_state, nonop_delay_msecs;

	if (!(port))
		return 0;
	/*
	 * First, check for a se_port_t specific secondary ALUA target port
	 * access state: OFFLINE
	 */
	if (atomic_read(&port->sep_tg_pt_secondary_offline)) {		
		*alua_ascq = ASCQ_04H_ALUA_OFFLINE;
		printk(KERN_INFO "ALUA: Got secondary offline status for local"
				" target port\n");
		*alua_ascq = ASCQ_04H_ALUA_OFFLINE;
		return 1;
	}
	 /*
	 * Second, obtain the t10_alua_tg_pt_gp_member_t pointer to the
	 * ALUA target port group, to obtain current ALUA access state.
	 * Otherwise look for the underlying se_device_t association with
	 * a ALUA logical unit group.
	 */
	tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	out_alua_state = atomic_read(&tg_pt_gp->tg_pt_gp_alua_access_state);
	nonop_delay_msecs = tg_pt_gp->tg_pt_gp_nonop_delay_msecs;
	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	/*
	 * Process ALUA_ACCESS_STATE_ACTIVE_OPTMIZED in a seperate conditional
	 * statement so the complier knows explictly to check this case first.
	 */
	if (out_alua_state == ALUA_ACCESS_STATE_ACTIVE_OPTMIZED)
		return core_alua_state_optimized(cmd, cdb, alua_ascq);

	switch (out_alua_state) {
	case ALUA_ACCESS_STATE_ACTIVE_NON_OPTIMIZED:
		return core_alua_state_nonoptimized(cmd, cdb,
					nonop_delay_msecs, alua_ascq);
	case ALUA_ACCESS_STATE_STANDBY:
		return core_alua_state_standby(cmd, cdb, alua_ascq);
	case ALUA_ACCESS_STATE_UNAVAILABLE:
		return core_alua_state_unavailable(cmd, cdb, alua_ascq);
	case ALUA_ACCESS_STATE_TRANSITION:
		return core_alua_state_transition(cmd, cdb, alua_ascq);
	/*
	 * OFFLINE is a secondary ALUA target port group access state, that is
	 * handled above with se_port_t->sep_tg_pt_secondary_offline=1
	 */
	case ALUA_ACCESS_STATE_OFFLINE:
	default:
		printk(KERN_ERR "Unknown ALUA access state: 0x%02x\n",
				out_alua_state);
		return -1;
	}

	return 0;
}

/*
 * Check implict and explict ALUA state change request.
 */
int core_alua_check_transition(int state, int *primary)
{
	switch (state) {
	case ALUA_ACCESS_STATE_ACTIVE_OPTMIZED:
	case ALUA_ACCESS_STATE_ACTIVE_NON_OPTIMIZED:
	case ALUA_ACCESS_STATE_STANDBY:
	case ALUA_ACCESS_STATE_UNAVAILABLE:
		/*
		 * OPTIMIZED, NON-OPTIMIZED, STANDBY and UNAVAILABLE are
		 * defined as primary target port asymmetric access states.
		 */
		*primary = 1;
		break;
	case ALUA_ACCESS_STATE_OFFLINE:
		/*
		 * OFFLINE state is defined as a secondary target port
		 * asymmetric access state.
		 */
		*primary = 0;
		break;
	default:
		printk(KERN_ERR "Unknown ALUA access state: 0x%02x\n", state);
		return -1;
	}

	return 0;
}

char *core_alua_dump_state(int state)
{
	switch (state) {
	case ALUA_ACCESS_STATE_ACTIVE_OPTMIZED:
		return "Active/Optimized";		
	case ALUA_ACCESS_STATE_ACTIVE_NON_OPTIMIZED:
		return "Active/NonOptimized";
	case ALUA_ACCESS_STATE_STANDBY:
		return "Standby";
	case ALUA_ACCESS_STATE_UNAVAILABLE:
		return "Unavailable";
	case ALUA_ACCESS_STATE_OFFLINE:
		return "Offline";
	default:
		return "Unknown";	
	}

	return NULL;
}

char *core_alua_dump_status(int status)
{
	switch (status) {
	case ALUA_STATUS_NONE:
		return "None";
	case ALUA_STATUS_ALTERED_BY_EXPLICT_STPG:
		return "Altered by Explict STPG";
	case ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA:
		return "Altered by Implict ALUA";
	default:
		return "Unknown";
	}

	return NULL;
}

/*
 * Used by fabric modules to determine when we need to delay processing
 * for the Active/NonOptimized paths..
 */
int core_alua_check_nonop_delay(
	se_cmd_t *cmd)
{
	if (!(cmd->se_cmd_flags & SCF_ALUA_NON_OPTIMIZED))
		return 0;
	if (in_interrupt())
		return 0;
	/*
	 * The ALUA Active/NonOptimized access state delay can be disabled
	 * in via configfs with a value of zero
	 */
	if (!(cmd->alua_nonop_delay))
		return 0;
	/*
	 * se_cmd_t->alua_nonop_delay gets set by a target port group
	 * defined interval in core_alua_state_nonoptimized()
	 */
	msleep_interruptible(cmd->alua_nonop_delay);
	return 0;
}
EXPORT_SYMBOL(core_alua_check_nonop_delay);

/*
 * Called with tg_pt_gp->tg_pt_gp_md_mutex or tg_pt_gp_mem->sep_tg_pt_md_mutex
 * 
 */
int core_alua_write_tpg_metadata(
	const char *path,
	unsigned char *md_buf,
	u32 md_buf_len) 
{
	mm_segment_t old_fs;
	struct file *file;
	struct iovec iov[1];
	int flags = O_RDWR | O_CREAT | O_TRUNC, ret;

	memset(iov, 0, sizeof(struct iovec));

	file = filp_open(path, flags, 0600);
	if (IS_ERR(file) || !file || !file->f_dentry) {
		printk(KERN_ERR "filp_open(%s) for ALUA metadata failed\n",
			path);
		return -1;
	}

	iov[0].iov_base = &md_buf[0];
	iov[0].iov_len = md_buf_len;

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_writev(file, &iov[0], 1, &file->f_pos);
	set_fs(old_fs);

	if (ret < 0) {
		printk("Error writing ALUA metadata file: %s\n", path);
		filp_close(file, NULL);
		return -1;
	}
	filp_close(file, NULL);

	return 0;
}

/*
 * Called with tg_pt_gp->tg_pt_gp_md_mutex held
 */
int core_alua_update_tpg_primary_metadata(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	int primary_state,
	unsigned char *md_buf)
{
	se_subsystem_dev_t *su_dev = tg_pt_gp->tg_pt_gp_su_dev;
	t10_wwn_t *wwn = &su_dev->t10_wwn;
	char path[512];
	int len;

	memset(path, 0, 512);

	len = snprintf(md_buf, tg_pt_gp->tg_pt_gp_md_buf_len,
			"tg_pt_gp_id=%hu\n"
			"alua_access_state=0x%02x\n"
			"alua_access_status=0x%02x\n",
			tg_pt_gp->tg_pt_gp_id, primary_state,
			tg_pt_gp->tg_pt_gp_alua_access_status);

	snprintf(path, 512, "/var/target/alua/tpgs_%s/%s",
		&wwn->unit_serial[0],
		config_item_name(&tg_pt_gp->tg_pt_gp_group.cg_item));

	return core_alua_write_tpg_metadata(path, md_buf, len);
}

int core_alua_do_transition_tg_pt(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	se_port_t *l_port,
	se_node_acl_t *nacl,
	unsigned char *md_buf,
	int new_state,
	int explict)
{
	se_dev_entry_t *se_deve;
	se_lun_acl_t *lacl;
	se_port_t *port;
	t10_alua_tg_pt_gp_member_t *mem;
	int old_state = 0;
	/*
	 * Save the old primary ALUA access state, and set the current state
	 * to ALUA_ACCESS_STATE_TRANSITION.
	 */
	old_state = atomic_read(&tg_pt_gp->tg_pt_gp_alua_access_state);
	atomic_set(&tg_pt_gp->tg_pt_gp_alua_access_state,
			ALUA_ACCESS_STATE_TRANSITION);
	tg_pt_gp->tg_pt_gp_alua_access_status = (explict) ?
				ALUA_STATUS_ALTERED_BY_EXPLICT_STPG :
				ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA;
	/*
	 * Check for the optional ALUA primary state transition delay
	 */
	if (tg_pt_gp->tg_pt_gp_trans_delay_msecs != 0) 
		msleep_interruptible(tg_pt_gp->tg_pt_gp_trans_delay_msecs);

	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	list_for_each_entry(mem, &tg_pt_gp->tg_pt_gp_mem_list,
				tg_pt_gp_mem_list) {
		port = mem->tg_pt;
		/*
		 * After an implicit target port asymmetric access state
		 * change, a device server shall establish a unit attention
		 * condition for the initiator port associated with every I_T
		 * nexus with the additional sense code set to ASYMMETRIC
		 * ACCESS STATE CHAGED.
		 * 
		 * After an explicit target port asymmetric access state
		 * change, a device server shall establish a unit attention
		 * condition with the additional sense code set to ASYMMETRIC
		 * ACCESS STATE CHANGED for the initiator port associated with
		 * every I_T nexus other than the I_T nexus on which the SET
		 * TARGET PORT GROUPS command
		 */
		atomic_inc(&mem->tg_pt_gp_mem_ref_cnt);
		smp_mb__after_atomic_inc();
		spin_unlock(&tg_pt_gp->tg_pt_gp_lock);

		spin_lock_bh(&port->sep_alua_lock);
		list_for_each_entry(se_deve, &port->sep_alua_list,
					alua_port_list) {
			lacl = se_deve->se_lun_acl;
			/*
			 * se_deve->se_lun_acl pointer may be NULL for a
			 * entry created without explict Node+MappedLUN ACLs
			 */
			if (!(lacl))
				continue;

			if (explict &&
			   (nacl != NULL) && (nacl == lacl->se_lun_nacl) &&
			   (l_port != NULL) && (l_port == port))
				continue;

			core_scsi3_ua_allocate(lacl->se_lun_nacl,
				se_deve->mapped_lun, 0x2A,
				ASCQ_2AH_ASYMMETRIC_ACCESS_STATE_CHANGED);
		}
		spin_unlock_bh(&port->sep_alua_lock);

		spin_lock(&tg_pt_gp->tg_pt_gp_lock);
		atomic_dec(&mem->tg_pt_gp_mem_ref_cnt);
		smp_mb__after_atomic_dec();
	}
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
	/*
	 * Update the ALUA metadata buf that has been allocated in
	 * core_alua_do_port_transition(), this metadata will be written
	 * to struct file.
	 *
	 * Note that there is the case where we do not want to update the
	 * metadata when the saved metadata is being parsed in userspace
	 * when setting the existing port access state and access status.
	 *
	 * Also note that the failure to write out the ALUA metadata to
	 * struct file does NOT affect the actual ALUA transition.
	 */
	if (tg_pt_gp->tg_pt_gp_write_metadata) {
		mutex_lock(&tg_pt_gp->tg_pt_gp_md_mutex);
		core_alua_update_tpg_primary_metadata(tg_pt_gp,
					new_state, md_buf);
		mutex_unlock(&tg_pt_gp->tg_pt_gp_md_mutex);
	}
	/*
	 * Set the current primary ALUA access state to the requested new state
	 */
	atomic_set(&tg_pt_gp->tg_pt_gp_alua_access_state, new_state);

	printk(KERN_INFO "Successful %s ALUA transition TG PT Group: %s ID: %hu"
		" from primary access state: %s to %s\n", (explict) ? "explict" :
		"implict", config_item_name(&tg_pt_gp->tg_pt_gp_group.cg_item),
		tg_pt_gp->tg_pt_gp_id, core_alua_dump_state(old_state),
		core_alua_dump_state(new_state));

	return 0;
}

int core_alua_do_port_transition(
	t10_alua_tg_pt_gp_t *l_tg_pt_gp,
	se_device_t *l_dev,
	se_port_t *l_port,
	se_node_acl_t *l_nacl,
	int new_state,
	int explict)
{
	se_device_t *dev;
	se_port_t *port;
	se_subsystem_dev_t *su_dev;
	se_node_acl_t *nacl;
	t10_alua_lu_gp_t *lu_gp;
	t10_alua_lu_gp_member_t *lu_gp_mem, *local_lu_gp_mem;
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	unsigned char *md_buf;
	int primary;

	if (core_alua_check_transition(new_state, &primary) != 0)
		return -1;

	md_buf = kzalloc(l_tg_pt_gp->tg_pt_gp_md_buf_len, GFP_KERNEL);
	if (!(md_buf)) {
		printk("Unable to allocate buf for ALUA metadata\n");
		return -1;
	}

	local_lu_gp_mem = l_dev->dev_alua_lu_gp_mem;
	spin_lock(&local_lu_gp_mem->lu_gp_mem_lock);
	lu_gp = local_lu_gp_mem->lu_gp;
	atomic_inc(&lu_gp->lu_gp_ref_cnt);
	smp_mb__after_atomic_inc();
	spin_unlock(&local_lu_gp_mem->lu_gp_mem_lock);
	/*
	 * For storage objects that are members of the 'default_lu_gp',
	 * we only do transition on the passed *l_tp_pt_gp, and not
	 * on all of the matching target port groups IDs in default_lu_gp.
	 */
	if (!(lu_gp->lu_gp_id)) {
		/*
		 * core_alua_do_transition_tg_pt() will always return
		 * success.
		 */
		core_alua_do_transition_tg_pt(l_tg_pt_gp, l_port, l_nacl,
					md_buf, new_state, explict);
		atomic_dec(&lu_gp->lu_gp_ref_cnt);
		smp_mb__after_atomic_dec();
		kfree(md_buf);
		return 0;
	}
	/*
	 * For all other LU groups aside from 'default_lu_gp', walk all of
	 * the associated storage objects looking for a matching target port
	 * group ID from the local target port group.
	 */
	spin_lock(&lu_gp->lu_gp_lock);
	list_for_each_entry(lu_gp_mem, &lu_gp->lu_gp_mem_list,
				lu_gp_mem_list) {

		dev = lu_gp_mem->lu_gp_mem_dev;
		su_dev = dev->se_sub_dev;
		atomic_inc(&lu_gp_mem->lu_gp_mem_ref_cnt);
		smp_mb__after_atomic_inc();
		spin_unlock(&lu_gp->lu_gp_lock);
		
		spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
		list_for_each_entry(tg_pt_gp,
				&T10_ALUA(su_dev)->tg_pt_gps_list,
				tg_pt_gp_list) {

			if (!(tg_pt_gp->tg_pt_gp_valid_id))
				continue;
			/*
			 * If the target behavior port asymmetric access state
			 * is changed for any target port group accessiable via
			 * a logical unit within a LU group, the target port
			 * behavior group asymmetric access states for the same
			 * target port group accessible via other logical units
			 * in that LU group will also change.
			 */
			if (l_tg_pt_gp->tg_pt_gp_id != tg_pt_gp->tg_pt_gp_id)
				continue;

			if (l_tg_pt_gp == tg_pt_gp) {
				port = l_port;
				nacl = l_nacl;
			} else {
				port = NULL;
				nacl = NULL;
			}
			atomic_inc(&tg_pt_gp->tg_pt_gp_ref_cnt);
			smp_mb__after_atomic_inc();
			spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
			/*
			 * core_alua_do_transition_tg_pt() will always return
			 * success.
			 */
			core_alua_do_transition_tg_pt(tg_pt_gp, port,
					nacl, md_buf, new_state, explict);

			spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
			atomic_dec(&tg_pt_gp->tg_pt_gp_ref_cnt);
			smp_mb__after_atomic_dec();
		}
		spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);

		spin_lock(&lu_gp->lu_gp_lock);
		atomic_dec(&lu_gp_mem->lu_gp_mem_ref_cnt);
		smp_mb__after_atomic_dec();
	}
	spin_unlock(&lu_gp->lu_gp_lock);

	printk("Successfully processed LU Group: %s all ALUA TG PT Group IDs:"
		" %hu %s transition to primary state: %s\n",
		config_item_name(&lu_gp->lu_gp_group.cg_item),
		l_tg_pt_gp->tg_pt_gp_id, (explict) ? "explict" : "implict",
		core_alua_dump_state(new_state));

	atomic_dec(&lu_gp->lu_gp_ref_cnt);
	smp_mb__after_atomic_dec();
	kfree(md_buf);
	return 0;
}

/*
 * Called with tg_pt_gp_mem->sep_tg_pt_md_mutex held
 */
int core_alua_update_tpg_secondary_metadata(
	struct t10_alua_tg_pt_gp_member_s *tg_pt_gp_mem,
	se_port_t *port,
	unsigned char *md_buf,
	u32 md_buf_len)
{
	se_portal_group_t *se_tpg = port->sep_tpg;
	char * buf;
	char * path;
	char * wwn;
	int len, ret;

	buf = kzalloc(2048, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;
	path = buf;
	wwn = path + 1024;

	len = snprintf(wwn, 512, "%s",
			TPG_TFO(se_tpg)->tpg_get_wwn(se_tpg));

	if (TPG_TFO(se_tpg)->tpg_get_tag != NULL)
		snprintf(wwn+len, 1024-len, "+%hu",
				TPG_TFO(se_tpg)->tpg_get_tag(se_tpg));

	len = snprintf(md_buf, md_buf_len, "alua_tg_pt_offline=%d\n"
			"alua_tg_pt_status=0x%02x\n",
			atomic_read(&port->sep_tg_pt_secondary_offline),
			port->sep_tg_pt_secondary_stat);

	snprintf(path, 512, "/var/target/alua/%s/%s/lun_%u",
			TPG_TFO(se_tpg)->get_fabric_name(), wwn,
			port->sep_lun->unpacked_lun);

	ret = core_alua_write_tpg_metadata(path, md_buf, len);
	kfree(buf);
	return ret;
}

int core_alua_set_tg_pt_secondary_state(
	struct t10_alua_tg_pt_gp_member_s *tg_pt_gp_mem,
	se_port_t *port,
	int explict,
	int offline)
{
	struct t10_alua_tg_pt_gp_s *tg_pt_gp;
	unsigned char *md_buf;
	u32 md_buf_len;
	int trans_delay_msecs;

	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	if (!(tg_pt_gp)) {
		spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
		printk(KERN_ERR "Unable to complete secondary state"
				" transition\n");
		return -1;
	}
	trans_delay_msecs = tg_pt_gp->tg_pt_gp_trans_delay_msecs;
	/*
	 * Set the secondary ALUA target port access state to OFFLINE
	 * or release the previously secondary state for se_port_t
	 */
	if (offline)
		atomic_set(&port->sep_tg_pt_secondary_offline, 1);
	else
		atomic_set(&port->sep_tg_pt_secondary_offline, 0);

	md_buf_len = tg_pt_gp->tg_pt_gp_md_buf_len;
	port->sep_tg_pt_secondary_stat = (explict) ?
			ALUA_STATUS_ALTERED_BY_EXPLICT_STPG :
			ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA;

	printk(KERN_INFO "Successful %s ALUA transition TG PT Group: %s ID: %hu"
		" to secondary access state: %s\n", (explict) ? "explict" :
		"implict", config_item_name(&tg_pt_gp->tg_pt_gp_group.cg_item),
		tg_pt_gp->tg_pt_gp_id, (offline) ? "OFFLINE" : "ONLINE");

	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	/*
	 * Do the optional transition delay after we set the secondary
	 * ALUA access state.
	 */
	if (trans_delay_msecs != 0)
		msleep_interruptible(trans_delay_msecs);	
	/*
	 * See if we need to update the ALUA fabric port metadata for
	 * secondary state and status
	 */
	if (port->sep_tg_pt_secondary_write_md) {
		md_buf = kzalloc(md_buf_len, GFP_KERNEL);
		if (!(md_buf)) {
			printk(KERN_ERR "Unable to allocate md_buf for"
				" secondary ALUA access metadata\n");
			return -1;
		}
		mutex_lock(&port->sep_tg_pt_md_mutex);
		core_alua_update_tpg_secondary_metadata(tg_pt_gp_mem, port,
				md_buf, md_buf_len);
		mutex_unlock(&port->sep_tg_pt_md_mutex);

		kfree(md_buf);
	}

	return 0;
}

t10_alua_lu_gp_t *core_alua_allocate_lu_gp(const char *name, int def_group)
{
	t10_alua_lu_gp_t *lu_gp;

	lu_gp = kmem_cache_zalloc(t10_alua_lu_gp_cache, GFP_KERNEL);
	if (!(lu_gp)) {
		printk(KERN_ERR "Unable to allocate t10_alua_lu_gp_t\n");
		return NULL;
	}
	INIT_LIST_HEAD(&lu_gp->lu_gp_list);
	INIT_LIST_HEAD(&lu_gp->lu_gp_mem_list);
	spin_lock_init(&lu_gp->lu_gp_lock);
	atomic_set(&lu_gp->lu_gp_ref_cnt, 0);

	if (def_group) {
		lu_gp->lu_gp_id = se_global->alua_lu_gps_counter++;;
		lu_gp->lu_gp_valid_id = 1;
		se_global->alua_lu_gps_count++;
	}

	return lu_gp;
}

int core_alua_set_lu_gp_id(t10_alua_lu_gp_t *lu_gp, u16 lu_gp_id)
{
	t10_alua_lu_gp_t *lu_gp_tmp;
	u16 lu_gp_id_tmp;
	/*
	 * The lu_gp->lu_gp_id may only be set once..
	 */
	if (lu_gp->lu_gp_valid_id) {
		printk(KERN_ERR "ALUA LU Group already has a valid ID,"
			" ignoring request\n");
		return -1;
	}

	spin_lock(&se_global->lu_gps_lock);
	if (se_global->alua_lu_gps_count == 0x0000ffff) {
		printk(KERN_ERR "Maximum ALUA se_global->alua_lu_gps_count:"
				" 0x0000ffff reached\n");
		spin_unlock(&se_global->lu_gps_lock);
		kmem_cache_free(t10_alua_lu_gp_cache, lu_gp);
		return -1;
	}
again:
	lu_gp_id_tmp = (lu_gp_id != 0) ? lu_gp_id :
				se_global->alua_lu_gps_counter++;

	list_for_each_entry(lu_gp_tmp, &se_global->g_lu_gps_list, lu_gp_list) {
		if (lu_gp_tmp->lu_gp_id == lu_gp_id_tmp) {
			if (!(lu_gp_id))
				goto again;

			printk(KERN_ERR "ALUA Logical Unit Group ID: %hu already"
				" exists, ignoring request\n", lu_gp_id);
			spin_unlock(&se_global->lu_gps_lock);
			return -1;
		}
	}

	lu_gp->lu_gp_id = lu_gp_id_tmp;
	lu_gp->lu_gp_valid_id = 1;
	list_add_tail(&lu_gp->lu_gp_list, &se_global->g_lu_gps_list);
	se_global->alua_lu_gps_count++;
	spin_unlock(&se_global->lu_gps_lock);

	return 0;
}

t10_alua_lu_gp_member_t *core_alua_allocate_lu_gp_mem(
	se_device_t *dev)
{
	t10_alua_lu_gp_member_t *lu_gp_mem;

	lu_gp_mem = kmem_cache_zalloc(t10_alua_lu_gp_mem_cache, GFP_KERNEL);
	if (!(lu_gp_mem)) {
		printk(KERN_ERR "Unable to allocate t10_alua_lu_gp_member_t\n");
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&lu_gp_mem->lu_gp_mem_list);
	spin_lock_init(&lu_gp_mem->lu_gp_mem_lock);
	atomic_set(&lu_gp_mem->lu_gp_mem_ref_cnt, 0);

	lu_gp_mem->lu_gp_mem_dev = dev;
	dev->dev_alua_lu_gp_mem = lu_gp_mem;

	return lu_gp_mem;
}

void core_alua_free_lu_gp(t10_alua_lu_gp_t *lu_gp)
{
	t10_alua_lu_gp_member_t *lu_gp_mem, *lu_gp_mem_tmp;
	/*
	 * Once we have reached this point, config_item_put() has
	 * already been called from target_core_alua_drop_lu_gp().
	 *
	 * Here, we remove the *lu_gp from the global list so that
	 * no associations can be made while we are releasing
	 * t10_alua_lu_gp_t.
	 */
	spin_lock(&se_global->lu_gps_lock);
	atomic_set(&lu_gp->lu_gp_shutdown, 1);
	list_del(&lu_gp->lu_gp_list);
	se_global->alua_lu_gps_count--;
	spin_unlock(&se_global->lu_gps_lock);
	/*
	 * Allow t10_alua_lu_gp_t * referenced by core_alua_get_lu_gp_by_name()
	 * in target_core_configfs.c:target_core_store_alua_lu_gp() to be
	 * released with core_alua_put_lu_gp_from_name()
	 */
	while (atomic_read(&lu_gp->lu_gp_ref_cnt))
		msleep(10);
	/*
	 * Release reference to t10_alua_lu_gp_t * from all associated
	 * se_device_t.
	 */
	spin_lock(&lu_gp->lu_gp_lock);
	list_for_each_entry_safe(lu_gp_mem, lu_gp_mem_tmp,
				&lu_gp->lu_gp_mem_list, lu_gp_mem_list) {
		if (lu_gp_mem->lu_gp_assoc) {
			list_del(&lu_gp_mem->lu_gp_mem_list);
			lu_gp->lu_gp_members--;
			lu_gp_mem->lu_gp_assoc = 0;
		}
		spin_unlock(&lu_gp->lu_gp_lock);
		/*
		 *
		 * lu_gp_mem is assoicated with a single
		 * se_device_t->dev_alua_lu_gp_mem, and is released when
		 * se_device_t is released via core_alua_free_lu_gp_mem().
		 *
		 * If the passed lu_gp does NOT match the default_lu_gp, assume
		 * we want to re-assocate a given lu_gp_mem with default_lu_gp.
		 */
		spin_lock(&lu_gp_mem->lu_gp_mem_lock);
		if (lu_gp != se_global->default_lu_gp)
			__core_alua_attach_lu_gp_mem(lu_gp_mem,
					se_global->default_lu_gp);
		else
			lu_gp_mem->lu_gp = NULL;
		spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

		spin_lock(&lu_gp->lu_gp_lock);
	}
	spin_unlock(&lu_gp->lu_gp_lock);

	kmem_cache_free(t10_alua_lu_gp_cache, lu_gp);
}

void core_alua_free_lu_gp_mem(se_device_t *dev)
{
	se_subsystem_dev_t *su_dev = dev->se_sub_dev;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_lu_gp_t *lu_gp;
	t10_alua_lu_gp_member_t *lu_gp_mem;

	if (alua->alua_type != SPC3_ALUA_EMULATED)
		return;

	lu_gp_mem = dev->dev_alua_lu_gp_mem;
	if (!(lu_gp_mem))
		return;

	while (atomic_read(&lu_gp_mem->lu_gp_mem_ref_cnt))
		msleep(10);

	spin_lock(&lu_gp_mem->lu_gp_mem_lock);
	lu_gp = lu_gp_mem->lu_gp;
	if ((lu_gp)) {
		spin_lock(&lu_gp->lu_gp_lock);
		if (lu_gp_mem->lu_gp_assoc) {
			list_del(&lu_gp_mem->lu_gp_mem_list);
			lu_gp->lu_gp_members--;
			lu_gp_mem->lu_gp_assoc = 0;
		}
		spin_unlock(&lu_gp->lu_gp_lock);
		lu_gp_mem->lu_gp = NULL;
	}
	spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

	kmem_cache_free(t10_alua_lu_gp_mem_cache, lu_gp_mem);
}

t10_alua_lu_gp_t *core_alua_get_lu_gp_by_name(const char *name)
{
	t10_alua_lu_gp_t *lu_gp;
	struct config_item *ci;

	spin_lock(&se_global->lu_gps_lock);
	list_for_each_entry(lu_gp, &se_global->g_lu_gps_list, lu_gp_list) {
		if (!(lu_gp->lu_gp_valid_id))
			continue;
		ci = &lu_gp->lu_gp_group.cg_item;
		if (!(strcmp(config_item_name(ci), name))) {
			atomic_inc(&lu_gp->lu_gp_ref_cnt);
			spin_unlock(&se_global->lu_gps_lock);
			return lu_gp;
		}
	}
	spin_unlock(&se_global->lu_gps_lock);

	return NULL;
}

void core_alua_put_lu_gp_from_name(t10_alua_lu_gp_t *lu_gp)
{
	spin_lock(&se_global->lu_gps_lock);
	atomic_dec(&lu_gp->lu_gp_ref_cnt);
	spin_unlock(&se_global->lu_gps_lock);
}

/*
 * Called with t10_alua_lu_gp_member_t->lu_gp_mem_lock
 */
void __core_alua_attach_lu_gp_mem(
	t10_alua_lu_gp_member_t *lu_gp_mem,
	t10_alua_lu_gp_t *lu_gp)
{
	spin_lock(&lu_gp->lu_gp_lock);
	lu_gp_mem->lu_gp = lu_gp;
	lu_gp_mem->lu_gp_assoc = 1;
	list_add_tail(&lu_gp_mem->lu_gp_mem_list, &lu_gp->lu_gp_mem_list);
	lu_gp->lu_gp_members++;
	spin_unlock(&lu_gp->lu_gp_lock);
}

/*
 * Called with t10_alua_lu_gp_member_t->lu_gp_mem_lock
 */
void __core_alua_drop_lu_gp_mem(
	t10_alua_lu_gp_member_t *lu_gp_mem,
	t10_alua_lu_gp_t *lu_gp)
{
	spin_lock(&lu_gp->lu_gp_lock);
	list_del(&lu_gp_mem->lu_gp_mem_list);
	lu_gp_mem->lu_gp = NULL;
	lu_gp_mem->lu_gp_assoc = 0;
	lu_gp->lu_gp_members--;
	spin_unlock(&lu_gp->lu_gp_lock);
}

t10_alua_tg_pt_gp_t *core_alua_allocate_tg_pt_gp(
	se_subsystem_dev_t *su_dev,
	const char *name,
	int def_group)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;

	tg_pt_gp = kmem_cache_zalloc(t10_alua_tg_pt_gp_cache, GFP_KERNEL);
	if (!(tg_pt_gp)) {
		printk(KERN_ERR "Unable to allocate t10_alua_tg_pt_gp_t\n");
		return NULL;
	}
	INIT_LIST_HEAD(&tg_pt_gp->tg_pt_gp_list);
	INIT_LIST_HEAD(&tg_pt_gp->tg_pt_gp_mem_list);
	mutex_init(&tg_pt_gp->tg_pt_gp_md_mutex);
	spin_lock_init(&tg_pt_gp->tg_pt_gp_lock);
	atomic_set(&tg_pt_gp->tg_pt_gp_ref_cnt, 0);
	tg_pt_gp->tg_pt_gp_su_dev = su_dev;
	tg_pt_gp->tg_pt_gp_md_buf_len = ALUA_MD_BUF_LEN;
	atomic_set(&tg_pt_gp->tg_pt_gp_alua_access_state,
		ALUA_ACCESS_STATE_ACTIVE_OPTMIZED);
	/*
	 * Enable both explict and implict ALUA support by default
	 */
	tg_pt_gp->tg_pt_gp_alua_access_type =
			TPGS_EXPLICT_ALUA | TPGS_IMPLICT_ALUA;
	/*
	 * Set the default Active/NonOptimized Delay in milliseconds
	 */
	tg_pt_gp->tg_pt_gp_nonop_delay_msecs = ALUA_DEFAULT_NONOP_DELAY_MSECS;
	tg_pt_gp->tg_pt_gp_trans_delay_msecs = ALUA_DEFAULT_TRANS_DELAY_MSECS;

	if (def_group) {
		spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
		tg_pt_gp->tg_pt_gp_id =
				T10_ALUA(su_dev)->alua_tg_pt_gps_counter++;
		tg_pt_gp->tg_pt_gp_valid_id = 1;
		T10_ALUA(su_dev)->alua_tg_pt_gps_count++;
		list_add_tail(&tg_pt_gp->tg_pt_gp_list,
			      &T10_ALUA(su_dev)->tg_pt_gps_list);
		spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	}

	return tg_pt_gp;
}

int core_alua_set_tg_pt_gp_id(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	u16 tg_pt_gp_id)
{
	se_subsystem_dev_t *su_dev = tg_pt_gp->tg_pt_gp_su_dev;
	t10_alua_tg_pt_gp_t *tg_pt_gp_tmp;
	u16 tg_pt_gp_id_tmp;
	/*
	 * The tg_pt_gp->tg_pt_gp_id may only be set once..
	 */
	if (tg_pt_gp->tg_pt_gp_valid_id) {
		printk(KERN_ERR "ALUA TG PT Group already has a valid ID,"
			" ignoring request\n");
		return -1;
	}

	spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	if (T10_ALUA(su_dev)->alua_tg_pt_gps_count == 0x0000ffff) {
		printk(KERN_ERR "Maximum ALUA alua_tg_pt_gps_count:"
			" 0x0000ffff reached\n");
		spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
		kmem_cache_free(t10_alua_tg_pt_gp_cache, tg_pt_gp);
		return -1;
	}
again:
	tg_pt_gp_id_tmp = (tg_pt_gp_id != 0) ? tg_pt_gp_id :
			T10_ALUA(su_dev)->alua_tg_pt_gps_counter++;

	list_for_each_entry(tg_pt_gp_tmp, &T10_ALUA(su_dev)->tg_pt_gps_list,
			tg_pt_gp_list) {
		if (tg_pt_gp_tmp->tg_pt_gp_id == tg_pt_gp_id_tmp) {
			if (!(tg_pt_gp_id))
				goto again;

			printk(KERN_ERR "ALUA Target Port Group ID: %hu already"
				" exists, ignoring request\n", tg_pt_gp_id);
			spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
			return -1;
		}
	}

	tg_pt_gp->tg_pt_gp_id = tg_pt_gp_id_tmp;
	tg_pt_gp->tg_pt_gp_valid_id = 1;
	list_add_tail(&tg_pt_gp->tg_pt_gp_list,
			&T10_ALUA(su_dev)->tg_pt_gps_list);
	T10_ALUA(su_dev)->alua_tg_pt_gps_count++;
	spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);

	return 0;
}

t10_alua_tg_pt_gp_member_t *core_alua_allocate_tg_pt_gp_mem(
	se_port_t *port)
{
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;

	tg_pt_gp_mem = kmem_cache_zalloc(t10_alua_tg_pt_gp_mem_cache,
				GFP_KERNEL);
	if (!(tg_pt_gp_mem)) {
		printk(KERN_ERR "Unable to allocate t10_alua_tg_pt_gp_member_t\n");
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&tg_pt_gp_mem->tg_pt_gp_mem_list);
	spin_lock_init(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	atomic_set(&tg_pt_gp_mem->tg_pt_gp_mem_ref_cnt, 0);

	tg_pt_gp_mem->tg_pt = port;
	port->sep_alua_tg_pt_gp_mem = tg_pt_gp_mem;
	atomic_set(&port->sep_tg_pt_gp_active, 1);

	return tg_pt_gp_mem;
}

void core_alua_free_tg_pt_gp(
	t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	se_subsystem_dev_t *su_dev = tg_pt_gp->tg_pt_gp_su_dev;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem, *tg_pt_gp_mem_tmp;
	/*
	 * Once we have reached this point, config_item_put() has already
	 * been called from target_core_alua_drop_tg_pt_gp().
	 *
	 * Here we remove *tg_pt_gp from the global list so that
	 * no assications *OR* explict ALUA via SET_TARGET_PORT_GROUPS
	 * can be made while we are releasing t10_alua_tg_pt_gp_t.
	 */
	spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	list_del(&tg_pt_gp->tg_pt_gp_list);
	T10_ALUA(su_dev)->alua_tg_pt_gps_counter--;
	spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	/*
	 * Allow a t10_alua_tg_pt_gp_member_t * referenced by
	 * core_alua_get_tg_pt_gp_by_name() in
	 * target_core_configfs.c:target_core_store_alua_tg_pt_gp()
	 * to be released with core_alua_put_tg_pt_gp_from_name().
	 */
	while (atomic_read(&tg_pt_gp->tg_pt_gp_ref_cnt))
		msleep(10);
	/*
	 * Release reference to t10_alua_tg_pt_gp_t from all associated
	 * se_port_t.
	 */
	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	list_for_each_entry_safe(tg_pt_gp_mem, tg_pt_gp_mem_tmp,
			&tg_pt_gp->tg_pt_gp_mem_list, tg_pt_gp_mem_list) {
		if (tg_pt_gp_mem->tg_pt_gp_assoc) {
			list_del(&tg_pt_gp_mem->tg_pt_gp_mem_list);
			tg_pt_gp->tg_pt_gp_members--;
			tg_pt_gp_mem->tg_pt_gp_assoc = 0;
		}
		spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
		/*
		 * tg_pt_gp_mem is assoicated with a single
		 * se_port->sep_alua_tg_pt_gp_mem, and is released via
		 * core_alua_free_tg_pt_gp_mem().
		 *
		 * If the passed tg_pt_gp does NOT match the default_tg_pt_gp,
		 * assume we want to re-assocate a given tg_pt_gp_mem with
		 * default_tg_pt_gp.
		 */
		spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
		if (tg_pt_gp != T10_ALUA(su_dev)->default_tg_pt_gp) {
			__core_alua_attach_tg_pt_gp_mem(tg_pt_gp_mem,
					T10_ALUA(su_dev)->default_tg_pt_gp);
		} else
			tg_pt_gp_mem->tg_pt_gp = NULL;
		spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

		spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	}
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);

	kmem_cache_free(t10_alua_tg_pt_gp_cache, tg_pt_gp);
}

void core_alua_free_tg_pt_gp_mem(se_port_t *port)
{
	se_subsystem_dev_t *su_dev = port->sep_lun->se_dev->se_sub_dev;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;

	if (alua->alua_type != SPC3_ALUA_EMULATED)
		return;

	tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
	if (!(tg_pt_gp_mem))
		return;

	while (atomic_read(&tg_pt_gp_mem->tg_pt_gp_mem_ref_cnt))
		msleep(10);

	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	if ((tg_pt_gp)) {
		spin_lock(&tg_pt_gp->tg_pt_gp_lock);
		if (tg_pt_gp_mem->tg_pt_gp_assoc) {
			list_del(&tg_pt_gp_mem->tg_pt_gp_mem_list);
			tg_pt_gp->tg_pt_gp_members--;
			tg_pt_gp_mem->tg_pt_gp_assoc = 0;
		}
		spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
		tg_pt_gp_mem->tg_pt_gp = NULL;
	}
	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

	kmem_cache_free(t10_alua_tg_pt_gp_mem_cache, tg_pt_gp_mem);
}

t10_alua_tg_pt_gp_t *core_alua_get_tg_pt_gp_by_name(
	se_subsystem_dev_t *su_dev,
	const char *name)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	struct config_item *ci;

	spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	list_for_each_entry(tg_pt_gp, &T10_ALUA(su_dev)->tg_pt_gps_list,
			tg_pt_gp_list) {
		if (!(tg_pt_gp->tg_pt_gp_valid_id))
			continue;
		ci = &tg_pt_gp->tg_pt_gp_group.cg_item;
		if (!(strcmp(config_item_name(ci), name))) {
			atomic_inc(&tg_pt_gp->tg_pt_gp_ref_cnt);
			spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
			return tg_pt_gp;
		}
	}
	spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);

	return NULL;
}

void core_alua_put_tg_pt_gp_from_name(
	t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	se_subsystem_dev_t *su_dev = tg_pt_gp->tg_pt_gp_su_dev;

	spin_lock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
	atomic_dec(&tg_pt_gp->tg_pt_gp_ref_cnt);
	spin_unlock(&T10_ALUA(su_dev)->tg_pt_gps_lock);
}

/*
 * Called with t10_alua_tg_pt_gp_member_t->tg_pt_gp_mem_lock held
 */
void __core_alua_attach_tg_pt_gp_mem(
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem,
	t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	tg_pt_gp_mem->tg_pt_gp = tg_pt_gp;
	tg_pt_gp_mem->tg_pt_gp_assoc = 1;
	list_add_tail(&tg_pt_gp_mem->tg_pt_gp_mem_list,
			&tg_pt_gp->tg_pt_gp_mem_list);
	tg_pt_gp->tg_pt_gp_members++;
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
}

/*
 * Called with t10_alua_tg_pt_gp_member_t->tg_pt_gp_mem_lock held
 */
void __core_alua_drop_tg_pt_gp_mem(
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem,
	t10_alua_tg_pt_gp_t *tg_pt_gp)
{
	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	list_del(&tg_pt_gp_mem->tg_pt_gp_mem_list);
	tg_pt_gp_mem->tg_pt_gp = NULL;
	tg_pt_gp_mem->tg_pt_gp_assoc = 0;
	tg_pt_gp->tg_pt_gp_members--;
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);
}

ssize_t core_alua_show_tg_pt_gp_info(se_port_t *port, char *page)
{
	se_subsystem_dev_t *su_dev = port->sep_lun->se_dev->se_sub_dev;
	struct config_item *tg_pt_ci;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	ssize_t len = 0;

	if (alua->alua_type != SPC3_ALUA_EMULATED)
		return len;

	tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
	if (!(tg_pt_gp_mem))
		return len;

	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	if ((tg_pt_gp)) {
		tg_pt_ci = &tg_pt_gp->tg_pt_gp_group.cg_item;
		len += sprintf(page, "TG Port Alias: %s\nTG Port Group ID:"
			" %hu\nTG Port Primary Access State: %s\nTG Port "
			"Primary Access Status: %s\nTG Port Secondary Access"
			" State: %s\nTG Port Secondary Access Status: %s\n",
			config_item_name(tg_pt_ci), tg_pt_gp->tg_pt_gp_id,
			core_alua_dump_state(atomic_read(
					&tg_pt_gp->tg_pt_gp_alua_access_state)),
			core_alua_dump_status(tg_pt_gp->tg_pt_gp_alua_access_status),
			(atomic_read(&port->sep_tg_pt_secondary_offline)) ?
			"Offline" : "None",
			core_alua_dump_status(port->sep_tg_pt_secondary_stat));
	}
	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

	return len;
}
EXPORT_SYMBOL(core_alua_show_tg_pt_gp_info);

ssize_t core_alua_store_tg_pt_gp_info(
	se_port_t *port,
	const char *page,
	size_t count)
{
	se_portal_group_t *tpg;
	se_lun_t *lun;
	se_subsystem_dev_t *su_dev = port->sep_lun->se_dev->se_sub_dev;
	t10_alua_tg_pt_gp_t *tg_pt_gp = NULL, *tg_pt_gp_new = NULL;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	unsigned char buf[TG_PT_GROUP_NAME_BUF];
	int move = 0;

	tpg = port->sep_tpg;
	lun = port->sep_lun;

	if (T10_ALUA(su_dev)->alua_type != SPC3_ALUA_EMULATED) {
		printk(KERN_WARNING "SPC3_ALUA_EMULATED not enabled for"
			" %s/tpgt_%hu/%s\n", TPG_TFO(tpg)->tpg_get_wwn(tpg),
			TPG_TFO(tpg)->tpg_get_tag(tpg),
			config_item_name(&lun->lun_group.cg_item));
		return -EINVAL;
	}

	if (count > TG_PT_GROUP_NAME_BUF) {
		printk(KERN_ERR "ALUA Target Port Group alias too large!\n");
		return -EINVAL;
	}
	memset(buf, 0, TG_PT_GROUP_NAME_BUF);
	memcpy(buf, page, count);
	/*
	 * Any ALUA target port group alias besides "NULL" means we will be
	 * making a new group association.
	 */
	if (strcmp(strstrip(buf), "NULL")) {
		/*
		 * core_alua_get_tg_pt_gp_by_name() will increment reference to
		 * t10_alua_tg_pt_gp_t.  This reference is released with
		 * core_alua_put_tg_pt_gp_from_name() below.
		 */
		tg_pt_gp_new = core_alua_get_tg_pt_gp_by_name(su_dev,
					strstrip(buf));
		if (!(tg_pt_gp_new))
			return -ENODEV;
	}
	tg_pt_gp_mem = port->sep_alua_tg_pt_gp_mem;
	if (!(tg_pt_gp_mem)) {
		if (tg_pt_gp_new)
			core_alua_put_tg_pt_gp_from_name(tg_pt_gp_new);
		printk(KERN_ERR "NULL se_port_t->sep_alua_tg_pt_gp_mem pointer\n");
		return -EINVAL;
	}

	spin_lock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	tg_pt_gp = tg_pt_gp_mem->tg_pt_gp;
	if ((tg_pt_gp)) {
		/*
		 * Clearing an existing tg_pt_gp association, and replacing
		 * with the default_tg_pt_gp.
		 */
		if (!(tg_pt_gp_new)) {
			printk(KERN_INFO "Target_Core_ConfigFS: Moving"
				" %s/tpgt_%hu/%s from ALUA Target Port Group:"
				" alua/%s, ID: %hu back to"
				" default_tg_pt_gp\n",
				TPG_TFO(tpg)->tpg_get_wwn(tpg),
				TPG_TFO(tpg)->tpg_get_tag(tpg),
				config_item_name(&lun->lun_group.cg_item),
				config_item_name(
					&tg_pt_gp->tg_pt_gp_group.cg_item),
				tg_pt_gp->tg_pt_gp_id);

			__core_alua_drop_tg_pt_gp_mem(tg_pt_gp_mem, tg_pt_gp);
			__core_alua_attach_tg_pt_gp_mem(tg_pt_gp_mem,
					T10_ALUA(su_dev)->default_tg_pt_gp);
			spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);

			return count;
		}
		/*
		 * Removing existing association of tg_pt_gp_mem with tg_pt_gp
		 */
		__core_alua_drop_tg_pt_gp_mem(tg_pt_gp_mem, tg_pt_gp);
		move = 1;
	}
	/*
	 * Associate tg_pt_gp_mem with tg_pt_gp_new.
	 */
	__core_alua_attach_tg_pt_gp_mem(tg_pt_gp_mem, tg_pt_gp_new);
	spin_unlock(&tg_pt_gp_mem->tg_pt_gp_mem_lock);
	printk("Target_Core_ConfigFS: %s %s/tpgt_%hu/%s to ALUA Target Port"
		" Group: alua/%s, ID: %hu\n", (move) ?
		"Moving" : "Adding", TPG_TFO(tpg)->tpg_get_wwn(tpg),
		TPG_TFO(tpg)->tpg_get_tag(tpg),
		config_item_name(&lun->lun_group.cg_item),
		config_item_name(&tg_pt_gp_new->tg_pt_gp_group.cg_item),
		tg_pt_gp_new->tg_pt_gp_id);

	core_alua_put_tg_pt_gp_from_name(tg_pt_gp_new);
	return count;
}
EXPORT_SYMBOL(core_alua_store_tg_pt_gp_info);

ssize_t core_alua_show_access_type(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	char *page)
{
	if ((tg_pt_gp->tg_pt_gp_alua_access_type & TPGS_EXPLICT_ALUA) &&
	    (tg_pt_gp->tg_pt_gp_alua_access_type & TPGS_IMPLICT_ALUA))
		return sprintf(page, "Implict and Explict\n");
	else if (tg_pt_gp->tg_pt_gp_alua_access_type & TPGS_IMPLICT_ALUA)	
		return sprintf(page, "Implict\n");
	else if (tg_pt_gp->tg_pt_gp_alua_access_type & TPGS_EXPLICT_ALUA)
		return sprintf(page, "Explict\n");
	else
		return sprintf(page, "None\n");
}

ssize_t core_alua_store_access_type(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int ret;

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract alua_access_type\n");
		return -EINVAL;
	}
	if ((tmp != 0) && (tmp != 1) && (tmp != 2) && (tmp != 3)) {
		printk(KERN_ERR "Illegal value for alua_access_type:"
				" %lu\n", tmp);
		return -EINVAL;
	}
	if (tmp == 3)
		tg_pt_gp->tg_pt_gp_alua_access_type =
			TPGS_IMPLICT_ALUA | TPGS_EXPLICT_ALUA;
	else if (tmp == 2)	
		tg_pt_gp->tg_pt_gp_alua_access_type = TPGS_EXPLICT_ALUA;
	else if (tmp == 1)
		tg_pt_gp->tg_pt_gp_alua_access_type = TPGS_IMPLICT_ALUA;
	else
		tg_pt_gp->tg_pt_gp_alua_access_type = 0;
	
	return count;
}

ssize_t core_alua_show_nonop_delay_msecs(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	char *page)
{
	return sprintf(page, "%d\n", tg_pt_gp->tg_pt_gp_nonop_delay_msecs);
}

ssize_t core_alua_store_nonop_delay_msecs(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int ret;

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract nonop_delay_msecs\n");
		return -EINVAL;
	}
	if (tmp > ALUA_MAX_NONOP_DELAY_MSECS) {
		printk(KERN_ERR "Passed nonop_delay_msecs: %lu, exceeds"
			" ALUA_MAX_NONOP_DELAY_MSECS: %d\n", tmp,
			ALUA_MAX_NONOP_DELAY_MSECS);
		return -EINVAL;
	}
	tg_pt_gp->tg_pt_gp_nonop_delay_msecs = (int)tmp;

	return count;
}

ssize_t core_alua_show_trans_delay_msecs(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	char *page)
{
	return sprintf(page, "%d\n", tg_pt_gp->tg_pt_gp_trans_delay_msecs);
}

ssize_t core_alua_store_trans_delay_msecs(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int ret;

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract trans_delay_msecs\n");
		return -EINVAL;
	}
	if (tmp > ALUA_MAX_TRANS_DELAY_MSECS) {
		printk(KERN_ERR "Passed trans_delay_msecs: %lu, exceeds"
			" ALUA_MAX_TRANS_DELAY_MSECS: %d\n", tmp,
			ALUA_MAX_TRANS_DELAY_MSECS);
		return -EINVAL;
	}
	tg_pt_gp->tg_pt_gp_trans_delay_msecs = (int)tmp;

	return count;
}

ssize_t core_alua_show_preferred_bit(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	char *page)
{
	return sprintf(page, "%d\n", tg_pt_gp->tg_pt_gp_pref);
}

ssize_t core_alua_store_preferred_bit(
	t10_alua_tg_pt_gp_t *tg_pt_gp,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int ret;	

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract preferred ALUA value\n");
		return -EINVAL;
	}
	if ((tmp != 0) && (tmp != 1)) {
		printk(KERN_ERR "Illegal value for preferred ALUA: %lu\n", tmp);
		return -EINVAL;
	}
	tg_pt_gp->tg_pt_gp_pref = (int)tmp;

	return count;
}

ssize_t core_alua_show_offline_bit(se_lun_t *lun, char *page)
{
	if (!(lun->lun_sep))
		return -ENODEV;

	return sprintf(page, "%d\n",
		atomic_read(&lun->lun_sep->sep_tg_pt_secondary_offline));
}
EXPORT_SYMBOL(core_alua_show_offline_bit);

ssize_t core_alua_store_offline_bit(se_lun_t *lun, const char *page, size_t count)
{
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	unsigned long tmp;
	int ret;

	if (!(lun->lun_sep))
		return -ENODEV;

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract alua_tg_pt_offline value\n");
		return -EINVAL;
	}
	if ((tmp != 0) && (tmp != 1)) {
		printk(KERN_ERR "Illegal value for alua_tg_pt_offline: %lu\n", tmp);
		return -EINVAL;
	}
	tg_pt_gp_mem = lun->lun_sep->sep_alua_tg_pt_gp_mem;
	if (!(tg_pt_gp_mem)) {
		printk(KERN_ERR "Unable to locate *tg_pt_gp_mem\n");
		return -EINVAL;
	}
	
	ret = core_alua_set_tg_pt_secondary_state(tg_pt_gp_mem,
			lun->lun_sep, 0, (int)tmp);
	if (ret < 0)
		return -EINVAL;

	return count;
}
EXPORT_SYMBOL(core_alua_store_offline_bit);

ssize_t core_alua_show_secondary_status(
	se_lun_t *lun,
	char *page)
{
	return sprintf(page, "%d\n", lun->lun_sep->sep_tg_pt_secondary_stat);
}
EXPORT_SYMBOL(core_alua_show_secondary_status);

ssize_t core_alua_store_secondary_status(
	se_lun_t *lun,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int ret;

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract alua_tg_pt_status\n");
		return -EINVAL;
	}
	if ((tmp != ALUA_STATUS_NONE) &&
	    (tmp != ALUA_STATUS_ALTERED_BY_EXPLICT_STPG) &&
	    (tmp != ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA)) {
		printk(KERN_ERR "Illegal value for alua_tg_pt_status: %lu\n",
				tmp);
		return -EINVAL;
	}
	lun->lun_sep->sep_tg_pt_secondary_stat = (int)tmp;

	return count;
}
EXPORT_SYMBOL(core_alua_store_secondary_status);

ssize_t core_alua_show_secondary_write_metadata(
	se_lun_t *lun,
	char *page)
{
	return sprintf(page, "%d\n",
			lun->lun_sep->sep_tg_pt_secondary_write_md);
}
EXPORT_SYMBOL(core_alua_show_secondary_write_metadata);

ssize_t core_alua_store_secondary_write_metadata(
	se_lun_t *lun,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int ret;

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract alua_tg_pt_write_md\n");
		return -EINVAL;
	}
	if ((tmp != 0) && (tmp != 1)) {
		printk(KERN_ERR "Illegal value for alua_tg_pt_write_md:"
				" %lu\n", tmp);
		return -EINVAL;
	}
	lun->lun_sep->sep_tg_pt_secondary_write_md = (int)tmp;

	return count;
}
EXPORT_SYMBOL(core_alua_store_secondary_write_metadata);

int core_setup_alua(se_device_t *dev, int force_pt)
{
	se_subsystem_dev_t *su_dev = dev->se_sub_dev;
	t10_alua_t *alua = T10_ALUA(su_dev);
	t10_alua_lu_gp_member_t *lu_gp_mem;
	/*
	 * If this device is from Target_Core_Mod/pSCSI, use the ALUA logic
	 * of the Underlying SCSI hardware.  In Linux/SCSI terms, this can
	 * cause a problem because libata and some SATA RAID HBAs appear
	 * under Linux/SCSI, but emulate SCSI logic themselves.
	 */
	if (((TRANSPORT(dev)->transport_type == TRANSPORT_PLUGIN_PHBA_PDEV) &&
	    !(DEV_ATTRIB(dev)->emulate_alua)) || force_pt) {
		alua->alua_type = SPC_ALUA_PASSTHROUGH;
		alua->alua_state_check = &core_alua_state_check_nop;
		printk(KERN_INFO "%s: Using SPC_ALUA_PASSTHROUGH, no ALUA"
			" emulation\n", TRANSPORT(dev)->name);
		return 0;
	}
	/*
	 * If SPC-3 or above is reported by real or emulated se_device_t,
	 * use emulated ALUA.
	 */
	if (TRANSPORT(dev)->get_device_rev(dev) >= SCSI_3) {
		printk(KERN_INFO "%s: Enabling ALUA Emulation for SPC-3"
			" device\n", TRANSPORT(dev)->name);
		/*
		 * Assoicate this se_device_t with the default ALUA
		 * LUN Group.
		 */
		lu_gp_mem = core_alua_allocate_lu_gp_mem(dev);
		if (IS_ERR(lu_gp_mem) || !lu_gp_mem)
			return -1;

		alua->alua_type = SPC3_ALUA_EMULATED;
		alua->alua_state_check = &core_alua_state_check;
		spin_lock(&lu_gp_mem->lu_gp_mem_lock);
		__core_alua_attach_lu_gp_mem(lu_gp_mem,
				se_global->default_lu_gp);
		spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

		printk(KERN_INFO "%s: Adding to default ALUA LU Group:"
			" core/alua/lu_gps/default_lu_gp\n",
			TRANSPORT(dev)->name);
	} else {
		alua->alua_type = SPC2_ALUA_DISABLED;
		alua->alua_state_check = &core_alua_state_check_nop;
		printk("%s: Disabling ALUA Emulation for SPC-2 device\n",
				TRANSPORT(dev)->name);
	}

	return 0;
}
