/*******************************************************************************
 * Filename:  target_core_stgt.h
 *
 * This file contains the generic target mode <-> Linux STGT subsystem plugin.
 * specific definitions and prototypes.
 *
 * Copyright (c) 2009 Rising Tide Systems, Inc.
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


#ifndef TARGET_CORE_STGT_H
#define TARGET_CORE_STGT_H

#define STGT_VERSION		"v1.0"
#define STGT_NAME		"stgt_tcm"

/* used in pscsi_add_device_to_list() */
#define STGT_DEFAULT_QUEUEDEPTH	1

#define PS_RETRY		5
#define PS_TIMEOUT_DISK		(15*HZ)
#define PS_TIMEOUT_OTHER	(500*HZ)

extern se_global_t *se_global;
extern struct block_device *linux_blockdevice_claim(int, int, void *);
extern int linux_blockdevice_release(int, int, struct block_device *);
extern int linux_blockdevice_check(int, int);

extern int stgt_CDB_inquiry(se_task_t *, u32);
extern int stgt_CDB_none(se_task_t *, u32);
extern int stgt_CDB_read_non_SG(se_task_t *, u32);
extern int stgt_CDB_read_SG(se_task_t *, u32);
extern int stgt_CDB_write_non_SG(se_task_t *, u32);
extern int stgt_CDB_write_SG(se_task_t *, u32);

#ifndef STGT_INCLUDE_STRUCTS
extern int stgt_plugin_init(void);
extern void stgt_plugin_free(void);
extern int stgt_attach_hba(se_hba_t *, u32);
extern int stgt_detach_hba(se_hba_t *);
#if 0
extern int pscsi_claim_phydevice(se_hba_t *, se_device_t *);
extern int pscsi_release_phydevice(se_device_t *);
#endif
extern void *stgt_allocate_virtdevice(se_hba_t *, const char *);
extern se_device_t *stgt_create_virtdevice(se_hba_t *, se_subsystem_dev_t *,
					void *);
extern int stgt_activate_device(se_device_t *);
extern void stgt_deactivate_device(se_device_t *);
extern void stgt_free_device(void *);
extern int stgt_transport_complete(se_task_t *);
extern void *stgt_allocate_request(se_task_t *, se_device_t *);
extern int stgt_do_task(se_task_t *);
extern void stgt_free_task(se_task_t *);
extern ssize_t stgt_set_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						const char *, ssize_t);
extern ssize_t stgt_check_configfs_dev_params(se_hba_t *,
						se_subsystem_dev_t *);
extern ssize_t stgt_show_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						char *);
#if 0
extern se_device_t *scsi_create_virtdevice_from_fd(se_subsystem_dev_t *,
						const char *);
#endif
extern void stgt_get_plugin_info(void *, char *, int *);
extern void stgt_get_hba_info(se_hba_t *, char *, int *);
extern void stgt_get_dev_info(se_device_t *, char *, int *);
extern int stgt_check_lba(unsigned long long, se_device_t *);
extern int stgt_check_for_SG(se_task_t *);
extern unsigned char *stgt_get_cdb(se_task_t *);
extern unsigned char *stgt_get_sense_buffer(se_task_t *);
extern u32 stgt_get_blocksize(se_device_t *);
extern u32 stgt_get_device_rev(se_device_t *);
extern u32 stgt_get_device_type(se_device_t *);
extern u32 stgt_get_dma_length(u32, se_device_t *);
extern u32 stgt_get_max_sectors(se_device_t *);
extern u32 stgt_get_queue_depth(se_device_t *);
extern void stgt_shutdown_hba(struct se_hba_s *);
extern void stgt_req_done(struct request *, int);
extern int stgt_transfer_response(struct scsi_cmnd *,
				  void (*done)(struct scsi_cmnd *));
#endif

#include <linux/device.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_device.h>
#include <linux/kref.h>
#include <linux/kobject.h>

typedef struct stgt_plugin_task_s {
	unsigned char stgt_cdb[SCSI_CDB_SIZE];
	unsigned char stgt_sense[SCSI_SENSE_BUFFERSIZE];
	int	stgt_direction;
	int	stgt_result;
	u32	stgt_resid;
	struct scsi_cmnd *stgt_cmd;
} stgt_plugin_task_t;

#define PDF_HAS_CHANNEL_ID	0x01
#define PDF_HAS_TARGET_ID	0x02
#define PDF_HAS_LUN_ID		0x04
#define PDF_HAS_VPD_UNIT_SERIAL 0x08
#define PDF_HAS_VPD_DEV_IDENT	0x10

typedef struct stgt_dev_virt_s {
	int	sdv_flags;
	int	sdv_legacy; /* Use scsi_execute_async() from HTCL */
	int	sdv_channel_id;
	int	sdv_target_id;
	int	sdv_lun_id;
	struct block_device *sdv_bd; /* Temporary for v2.6.28 */
	struct scsi_device *sdv_sd;
	struct se_hba_s *sdv_se_hba;
} stgt_dev_virt_t;

typedef struct stgt_hba_s {
	struct device dev;
	struct se_hba_s *se_hba;
	struct Scsi_Host *scsi_host;
} stgt_hba_t;

extern void __stgt_get_dev_info(stgt_dev_virt_t *, char *, int *);

/*
 * We use the generic command sequencer, so we must setup
 * se_subsystem_spc_t.
 */
#ifndef STGT_INCLUDE_STRUCTS

se_subsystem_spc_t stgt_template_spc = {
	.inquiry		= stgt_CDB_inquiry,
	.none			= stgt_CDB_none,
	.read_non_SG		= stgt_CDB_read_non_SG,
	.read_SG		= stgt_CDB_read_SG,
	.write_non_SG		= stgt_CDB_write_non_SG,
	.write_SG		= stgt_CDB_write_SG,
};

se_subsystem_api_t stgt_template = {
	.name			= "stgt",			\
	.type			= STGT,				\
	.transport_type		= TRANSPORT_PLUGIN_VHBA_PDEV,	\
	.attach_hba		= stgt_attach_hba,		\
	.detach_hba		= stgt_detach_hba,		\
	.activate_device	= stgt_activate_device,		\
	.deactivate_device	= stgt_deactivate_device,	\
	.claim_phydevice	= NULL,				\
	.allocate_virtdevice	= stgt_allocate_virtdevice,	\
	.create_virtdevice	= stgt_create_virtdevice,	\
	.free_device		= stgt_free_device,		\
	.release_phydevice	= NULL,				\
	.transport_complete	= stgt_transport_complete,	\
	.allocate_request	= stgt_allocate_request,	\
	.do_task		= stgt_do_task,			\
	.free_task		= stgt_free_task,		\
	.check_configfs_dev_params = stgt_check_configfs_dev_params, \
	.set_configfs_dev_params = stgt_set_configfs_dev_params, \
	.show_configfs_dev_params = stgt_show_configfs_dev_params, \
	.create_virtdevice_from_fd = NULL,			\
	.plugin_init		= stgt_plugin_init,		\
	.plugin_free		= stgt_plugin_free,		\
	.get_plugin_info	= stgt_get_plugin_info,		\
	.get_hba_info		= stgt_get_hba_info,		\
	.get_dev_info		= stgt_get_dev_info,		\
	.check_lba		= stgt_check_lba,		\
	.check_for_SG		= stgt_check_for_SG,		\
	.get_cdb		= stgt_get_cdb,			\
	.get_sense_buffer	= stgt_get_sense_buffer,	\
	.get_blocksize		= stgt_get_blocksize,		\
	.get_device_rev		= stgt_get_device_rev,		\
	.get_device_type	= stgt_get_device_type,		\
	.get_dma_length		= stgt_get_dma_length,		\
	.get_max_sectors	= stgt_get_max_sectors,		\
	.get_queue_depth	= stgt_get_queue_depth,		\
	.shutdown_hba		= stgt_shutdown_hba,		\
	.write_pending		= NULL,				\
	.spc			= &stgt_template_spc,		\
};

#endif

#endif   /*** TARGET_CORE_STGT_H ***/
