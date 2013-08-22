/*******************************************************************************
 * Filename:  target_core_rd.h
 *
 * This file contains the Storage Engine <-> Ramdisk transport specific
 * definitions and prototypes.
 *
 * Copyright (c) 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2009 Rising Tide Software, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
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


#ifndef TARGET_CORE_RD_H
#define TARGET_CORE_RD_H

#define RD_HBA_VERSION		"v3.5"
#define RD_DR_VERSION		"3.5"
#define RD_MCP_VERSION		"3.5"

/* Largest piece of memory kmalloc can allocate */
#define RD_MAX_ALLOCATION_SIZE	65536
/* Maximum queuedepth for the Ramdisk HBA */
#define RD_HBA_QUEUE_DEPTH	256
#define RD_DEVICE_QUEUE_DEPTH	32
#define RD_MAX_DEVICE_QUEUE_DEPTH 128
#define RD_BLOCKSIZE		512
#define RD_MAX_SECTORS		1024

#define RD_DATA_READ		1
#define RD_DATA_WRITE		2
#define RD_DATA_NONE		3

extern se_global_t *se_global;

#ifndef RD_INCLUDE_STRUCTS
extern int rd_CDB_inquiry(se_task_t *, u32);
extern int rd_CDB_none(se_task_t *, u32);
extern int rd_CDB_read_non_SG(se_task_t *, u32);
extern int rd_CDB_read_SG(se_task_t *, u32);
extern int rd_CDB_write_non_SG(se_task_t *, u32);
extern int rd_CDB_write_SG(se_task_t *, u32);

extern int rd_attach_hba(se_hba_t *, u32);
extern int rd_detach_hba(se_hba_t *);
extern void *rd_DIRECT_allocate_virtdevice(se_hba_t *, const char *);
extern void *rd_MEMCPY_allocate_virtdevice(se_hba_t *, const char *);
extern se_device_t *rd_DIRECT_create_virtdevice(se_hba_t *,
				se_subsystem_dev_t *, void *);
extern se_device_t *rd_MEMCPY_create_virtdevice(se_hba_t *,
				se_subsystem_dev_t *, void *);
extern int rd_activate_device(se_device_t *);
extern void rd_deactivate_device(se_device_t *);
extern void rd_free_device(void *);
extern int rd_transport_complete(se_task_t *);
extern void *rd_allocate_request(se_task_t *, se_device_t *);
extern int rd_DIRECT_do_task(se_task_t *);
extern int rd_MEMCPY_do_task(se_task_t *);
extern int rd_DIRECT_allocate_DMA(se_cmd_t *, u32, u32);
extern int rd_DIRECT_do_se_mem_map(struct se_task_s *, struct list_head *,
				void *, struct se_mem_s *, struct se_mem_s **,
				u32 *, u32 *);
extern void rd_DIRECT_free_DMA(se_cmd_t *);
extern void rd_free_task(se_task_t *);
extern ssize_t rd_set_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						const char *, ssize_t);
extern ssize_t rd_check_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *);
extern ssize_t rd_show_configfs_dev_params(se_hba_t *, se_subsystem_dev_t *,
						char *);
extern void rd_dr_get_plugin_info(void *, char *, int *);
extern void rd_mcp_get_plugin_info(void *, char *, int *);
extern void rd_get_hba_info(se_hba_t *, char *, int *);
extern void rd_get_dev_info(se_device_t *, char *, int *);
extern int rd_DIRECT_check_lba(unsigned long long, se_device_t *);
extern int rd_MEMCPY_check_lba(unsigned long long, se_device_t *);
extern int rd_check_for_SG(se_task_t *);
extern unsigned char *rd_get_cdb(se_task_t *);
extern u32 rd_get_blocksize(se_device_t *);
extern u32 rd_get_device_rev(se_device_t *);
extern u32 rd_get_device_type(se_device_t *);
extern u32 rd_get_dma_length(u32, se_device_t *);
extern u32 rd_get_max_sectors(se_device_t *);
extern u32 rd_get_queue_depth(se_device_t *);
extern u32 rd_get_max_queue_depth(se_device_t *);
#endif /* ! RD_INCLUDE_STRUCTS */

#define RRF_EMULATE_CDB		0x01
#define RRF_GOT_LBA		0x02

typedef struct rd_request_s {
	/* SCSI CDB from iSCSI Command PDU */
	unsigned char	rd_scsi_cdb[SCSI_CDB_SIZE];
	/* Data Direction */
	u8		rd_data_direction;
	/* Total length of request */
	u32		rd_bufflen;
	/* RD request flags */
	u32		rd_req_flags;
	/* Offset from start of page */
	u32		rd_offset;
	/* Starting page in Ramdisk for request */
	u32		rd_page;
	/* Total number of pages needed for request */
	u32		rd_page_count;
	/* Scatterlist count */
	u32		rd_sg_count;
	u32		rd_size;
	/* Logical Block Address */
	unsigned long long	rd_lba;
	 /* Data buffer containing scatterlists(s) or
	  * contiguous memory segments */
	void		*rd_buf;
	/* Ramdisk device */
	struct rd_dev_s	*rd_dev;
} ____cacheline_aligned rd_request_t;

typedef struct rd_dev_sg_table_s {
	u32		page_start_offset;
	u32		page_end_offset;
	u32		rd_sg_count;
	struct scatterlist *sg_table;
} ____cacheline_aligned rd_dev_sg_table_t;

#define RDF_HAS_PAGE_COUNT	0x01

typedef struct rd_dev_s {
	int		rd_direct;
	u32		rd_flags;
	/* Unique Ramdisk Device ID in Ramdisk HBA */
	u32		rd_dev_id;
	/* Total page count for ramdisk device */
	u32		rd_page_count;
	/* Number of SG tables in sg_table_array */
	u32		sg_table_count;
	u32		rd_queue_depth;
	/* Array of rd_dev_sg_table_t containing scatterlists */
	rd_dev_sg_table_t *sg_table_array;
	/* Ramdisk HBA device is connected to */
	struct rd_host_s *rd_host;
	/* Next RD Device entry in list */
	struct rd_dev_s *next;
} ____cacheline_aligned rd_dev_t;

extern void __rd_get_dev_info(rd_dev_t *, char *, int *);

typedef struct rd_host_s {
	u32		rd_host_dev_id_count;
	u32		rd_host_id;		/* Unique Ramdisk Host ID */
} ____cacheline_aligned rd_host_t;

#ifndef RD_INCLUDE_STRUCTS
/*
 * We use the generic command sequencer, so we must setup
 * se_subsystem_spc_t.
 */
se_subsystem_spc_t rd_template_spc = {
	.inquiry		= rd_CDB_inquiry,
	.none			= rd_CDB_none,
	.read_non_SG		= rd_CDB_read_non_SG,
	.read_SG		= rd_CDB_read_SG,
	.write_non_SG		= rd_CDB_write_non_SG,
	.write_SG		= rd_CDB_write_SG,
};

se_subsystem_api_t rd_dr_template = {
	.name			= "rd_dr",
	.type			= RAMDISK_DR,
	.transport_type		= TRANSPORT_PLUGIN_VHBA_VDEV,
	.attach_hba		= rd_attach_hba,
	.detach_hba		= rd_detach_hba,
	.allocate_virtdevice	= rd_DIRECT_allocate_virtdevice,
	.create_virtdevice	= rd_DIRECT_create_virtdevice,
	.activate_device	= rd_activate_device,
	.deactivate_device	= rd_deactivate_device,
	.free_device		= rd_free_device,
	.transport_complete	= rd_transport_complete,
	.allocate_DMA		= rd_DIRECT_allocate_DMA,
	.free_DMA		= rd_DIRECT_free_DMA,
	.allocate_request	= rd_allocate_request,
	.do_task		= rd_DIRECT_do_task,
	.free_task		= rd_free_task,
	.check_configfs_dev_params = rd_check_configfs_dev_params,
	.set_configfs_dev_params = rd_set_configfs_dev_params,
	.show_configfs_dev_params = rd_show_configfs_dev_params,
	.get_plugin_info	= rd_dr_get_plugin_info,
	.get_hba_info		= rd_get_hba_info,
	.get_dev_info		= rd_get_dev_info,
	.check_lba		= rd_DIRECT_check_lba,
	.check_for_SG		= rd_check_for_SG,
	.get_cdb		= rd_get_cdb,
	.get_blocksize		= rd_get_blocksize,
	.get_device_rev		= rd_get_device_rev,
	.get_device_type	= rd_get_device_type,
	.get_dma_length		= rd_get_dma_length,
	.get_max_sectors	= rd_get_max_sectors,
	.get_queue_depth	= rd_get_queue_depth,
	.get_max_queue_depth	= rd_get_max_queue_depth,
	.do_se_mem_map		= rd_DIRECT_do_se_mem_map,
	.write_pending		= NULL,
	.spc			= &rd_template_spc,
};

se_subsystem_api_t rd_mcp_template = {
	.name			= "rd_mcp",
	.type			= RAMDISK_MCP,
	.transport_type		= TRANSPORT_PLUGIN_VHBA_VDEV,
	.attach_hba		= rd_attach_hba,
	.detach_hba		= rd_detach_hba,
	.allocate_virtdevice	= rd_MEMCPY_allocate_virtdevice,
	.create_virtdevice	= rd_MEMCPY_create_virtdevice,
	.activate_device	= rd_activate_device,
	.deactivate_device	= rd_deactivate_device,
	.free_device		= rd_free_device,
	.transport_complete	= rd_transport_complete,
	.allocate_request	= rd_allocate_request,
	.do_task		= rd_MEMCPY_do_task,
	.free_task		= rd_free_task,
	.check_configfs_dev_params = rd_check_configfs_dev_params,
	.set_configfs_dev_params = rd_set_configfs_dev_params,
	.show_configfs_dev_params = rd_show_configfs_dev_params,
	.get_plugin_info	= rd_mcp_get_plugin_info,
	.get_hba_info		= rd_get_hba_info,
	.get_dev_info		= rd_get_dev_info,
	.check_lba		= rd_MEMCPY_check_lba,
	.check_for_SG		= rd_check_for_SG,
	.get_cdb		= rd_get_cdb,
	.get_blocksize		= rd_get_blocksize,
	.get_device_rev		= rd_get_device_rev,
	.get_device_type	= rd_get_device_type,
	.get_dma_length		= rd_get_dma_length,
	.get_max_sectors	= rd_get_max_sectors,
	.get_queue_depth	= rd_get_queue_depth,
	.get_max_queue_depth	= rd_get_max_queue_depth,
	.write_pending		= NULL,
	.spc			= &rd_template_spc,
};

#endif /* ! RD_INCLUDE_STRUCTS */

#endif /* TARGET_CORE_RD_H */
