/*******************************************************************************
 * Filename:  target_core_stgt.c
 *
 * This file contains the generic target mode <-> Linux SCSI subsystem plugin.
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


#define TARGET_CORE_STGT_C

#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/genhd.h>
#include <linux/cdrom.h>
#include <linux/file.h>
#include <scsi/scsi.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_tgt.h>
#include <sd.h>
#include <sr.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_transport.h>
#include <target/target_core_stgt.h>
#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>
#include <target/target_core_transport_plugin.h>

#undef TARGET_CORE_STGT_C

#define to_stgt_hba(d)	container_of(d, struct stgt_hba_s, dev)

static int stgt_host_no_cnt;

#define ISPRINT(a)  ((a >= ' ') && (a <= '~'))

static int pseudo_lld_bus_match(struct device *dev,
				struct device_driver *dev_driver)
{
	return 1;
}

static int stgt_lld_probe(struct device *);
static int stgt_lld_remove(struct device *);

static struct bus_type stgt_lld_bus = {
	.name		= "stgt_bus",
	.match		= pseudo_lld_bus_match,
	.probe		= stgt_lld_probe,
	.remove		= stgt_lld_remove,
};

static struct device_driver stgt_driverfs_driver = {
	.name		= STGT_NAME,
	.bus		= &stgt_lld_bus,
};

static void stgt_primary_release(struct device *dev)
{
	return;
}

static struct device stgt_primary = {
	.init_name	= "stgt_primary_0",
	.release	= stgt_primary_release,
};

static struct scsi_host_template stgt_driver_template = {
	.name		= STGT_NAME,
	.module		= THIS_MODULE,
	.can_queue	= 1,
	.sg_tablesize	= SG_ALL,
	.use_clustering	= DISABLE_CLUSTERING,
	.max_sectors	= SCSI_DEFAULT_MAX_SECTORS,
	.transfer_response = stgt_transfer_response,
	.eh_abort_handler = NULL,
	.shost_attrs	= NULL,
	.proc_name	= STGT_NAME,
	.supported_mode	= MODE_TARGET,
};

static void stgt_release_adapter(struct device *dev)
{
	stgt_hba_t *stgt_hba;

	stgt_hba = to_stgt_hba(dev);
	kfree(stgt_hba);
}

int stgt_plugin_init(void)
{
	int ret;

	ret = device_register(&stgt_primary);
	if (ret) {
		printk(KERN_ERR "device_register() failed for stgt_primary\n");
		return ret;
	}

	ret = bus_register(&stgt_lld_bus);
	if (ret) {
		printk(KERN_ERR "bus_register() failed for stgt_ldd_bus\n");
		goto dev_unreg;
	}

	ret = driver_register(&stgt_driverfs_driver);
	if (ret) {
		printk(KERN_ERR "driver_register() failed for"
			" stgt_driverfs_driver\n");
		goto bus_unreg;
	}
	stgt_host_no_cnt = 0;

	printk(KERN_INFO "CORE_STGT[0]: Bus Initalization complete\n");
	return 0;

bus_unreg:
	bus_unregister(&stgt_lld_bus);
dev_unreg:
	device_unregister(&stgt_primary);
	return ret;
}

void stgt_plugin_free(void)
{
	driver_unregister(&stgt_driverfs_driver);
	bus_unregister(&stgt_lld_bus);
	device_unregister(&stgt_primary);

	printk(KERN_INFO "CORE_STGT[0]: Bus release complete\n");
}

/*	stgt_attach_hba():
 *
 */
int stgt_attach_hba(se_hba_t *hba, u32 host_id)
{
	stgt_hba_t *stgt_hba;
	int err;

	stgt_hba = kzalloc(sizeof(stgt_hba_t), GFP_KERNEL);
	if (!(stgt_hba)) {
		printk(KERN_ERR "Unable to allocate stgt_hba_t\n");
		return -ENOMEM;
	}
	stgt_hba->se_hba = hba;

	stgt_hba->dev.bus = &stgt_lld_bus;
	stgt_hba->dev.parent = &stgt_primary;
	stgt_hba->dev.release = &stgt_release_adapter;
	dev_set_name(&stgt_hba->dev, "stgt_adapter%d", stgt_host_no_cnt);

	err = device_register(&stgt_hba->dev);
	if (err) {
		printk(KERN_ERR "device_register() for stgt_hba failed:"
				" %d\n", err);
		return err;
	}
	stgt_host_no_cnt++;

	return 0;
}


static int stgt_lld_probe(struct device *dev)
{
	se_hba_t *hba;
	stgt_hba_t *stgt_hba;
	struct Scsi_Host *sh;
	int hba_depth, max_sectors, err;

	stgt_hba = to_stgt_hba(dev);

	sh = scsi_host_alloc(&stgt_driver_template, sizeof(stgt_hba));
	if (!(sh)) {
		printk(KERN_ERR "scsi_host_alloc() failed\n");
		return -ENOMEM;
	}
	hba = stgt_hba->se_hba;
	stgt_hba->scsi_host = sh;

	sh->max_id = 10;
	sh->max_lun = 10;

	/*
	 * Assign the stgt_hba_t pointer to struct Scsi_Host->hostdata..
	 */
	*(stgt_hba_t **)&sh->hostdata = stgt_hba;

	err = scsi_add_host(sh, &stgt_hba->dev);
	if (err) {
		printk(KERN_ERR "scsi_add_host() failed with err: %d\n", err);
		return err;
	}

	max_sectors = sh->max_sectors;
	/*
	 * Usually the SCSI LLD will use the hostt->can_queue value to define
	 * its HBA TCQ depth.  Some other drivers (like 2.6 megaraid) don't set
	 * this at all and set sh->can_queue at runtime.
	 */
	hba_depth = (sh->hostt->can_queue > sh->can_queue) ?
		sh->hostt->can_queue : sh->can_queue;
	atomic_set(&hba->left_queue_depth, hba_depth);
	atomic_set(&hba->max_queue_depth, hba_depth);

	hba->hba_ptr = (void *) sh;
	hba->transport = &stgt_template;

	printk(KERN_INFO "CORE_HBA[%d] - %s STGT HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		PYX_ISCSI_VENDOR, STGT_VERSION, TARGET_CORE_MOD_VERSION);
	printk(KERN_INFO "CORE_HBA[%d] - %s\n", hba->hba_id, (sh->hostt->name) ?
			(sh->hostt->name) : "Unknown");
	printk(KERN_INFO "CORE_HBA[%d] - Attached STGT HBA to Generic"
		" Target Core with TCQ Depth: %d MaxSectors: %hu\n",
		hba->hba_id, atomic_read(&hba->max_queue_depth), max_sectors);

	return 0;
}

static int stgt_lld_remove(struct device *dev)
{
	stgt_hba_t *stgt_hba;
	struct Scsi_Host *sh;

	stgt_hba = to_stgt_hba(dev);
	sh = stgt_hba->scsi_host;

	scsi_remove_host(sh);
	scsi_host_put(sh);

	return 0;
}

/*	stgt_detach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
int stgt_detach_hba(se_hba_t *hba)
{
	struct Scsi_Host *scsi_host = (struct Scsi_Host *) hba->hba_ptr;
	stgt_hba_t *stgt_hba = *(stgt_hba_t **)shost_priv(scsi_host);

	printk(KERN_INFO "CORE_HBA[%d] - Detached STGT HBA: %s from"
		" Generic Target Core\n", hba->hba_id,
		(scsi_host->hostt->name) ? (scsi_host->hostt->name) :
		"Unknown");

	device_unregister(&stgt_hba->dev);
	hba->hba_ptr = NULL;

	return 0;
}

void *stgt_allocate_virtdevice(se_hba_t *hba, const char *name)
{
	stgt_dev_virt_t *sdv;

	sdv = kzalloc(sizeof(stgt_dev_virt_t), GFP_KERNEL);
	if (!(sdv)) {
		printk(KERN_ERR "Unable to allocate memory for stgt_dev_virt_t\n");
		return NULL;
	}
	sdv->sdv_se_hba = hba;

	printk(KERN_INFO "STGT: Allocated sdv: %p for %s\n", sdv, name);
	return (void *)sdv;
}

#warning FIXME: implement stgt_create_virtdevice()
se_device_t *stgt_create_virtdevice(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	void *p)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *)p;
	struct Scsi_Host *sh = (struct Scsi_Host *) hba->hba_ptr;

	if (!(sdv)) {
		printk(KERN_ERR "Unable to locate stgt_dev_virt_t"
				" parameter\n");
		return NULL;
	}

	printk(KERN_ERR "Unable to locate %d:%d:%d:%d\n", sh->host_no,
		sdv->sdv_channel_id,  sdv->sdv_target_id, sdv->sdv_lun_id);

	return NULL;
}

/*	stgt_activate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
int stgt_activate_device(se_device_t *dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;
	struct Scsi_Host *sh = sd->host;

	printk(KERN_INFO "CORE_STGT[%d] - Activating %s Device with TCQ: %d at"
		" SCSI Location (Channel/Target/LUN) %d/%d/%d\n", sh->host_no,
		(sdv->sdv_legacy) ? "Legacy" : "REQ",  sd->queue_depth,
		sd->channel, sd->id, sd->lun);

	return 0;
}

/*	stgt_deactivate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
void stgt_deactivate_device(se_device_t *dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;
	struct Scsi_Host *sh = sd->host;

	printk(KERN_INFO "CORE_STGT[%d] - Deactivating %s Device with TCQ: %d"
		" at SCSI Location (Channel/Target/LUN) %d/%d/%d\n",
		sh->host_no, (sdv->sdv_legacy) ? "Legacy" : "REQ",
		sd->queue_depth, sd->channel, sd->id, sd->lun);
}

/*	stgt_free_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
void stgt_free_device(void *p)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) p;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;

	if (sdv->sdv_bd)
		sdv->sdv_bd = NULL;

	if (sd) {
		if ((sd->type == TYPE_DISK) || (sd->type == TYPE_ROM))
			scsi_device_put(sd);

		sdv->sdv_sd = NULL;
	}

	kfree(sdv);
}

/*	pscsi_transport_complete():
 *
 *
 */
int stgt_transport_complete(se_task_t *task)
{
	stgt_plugin_task_t *st = (stgt_plugin_task_t *) task->transport_req;
	int result;

	result = st->stgt_result;
	if (status_byte(result) & CHECK_CONDITION)
		return 1;

	return 0;
}

/*	stgt_allocate_request(): (Part of se_subsystem_api_t template)
 *
 *
 */
void *stgt_allocate_request(
	se_task_t *task,
	se_device_t *dev)
{
	stgt_plugin_task_t *st;

	st = kzalloc(sizeof(stgt_plugin_task_t), GFP_KERNEL);
	if (!(st)) {
		printk(KERN_ERR "Unable to allocate stgt_plugin_task_t\n");
		return NULL;
	}

	return st;
}

/*      stgt_do_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
int stgt_do_task(se_task_t *task)
{
	stgt_plugin_task_t *st = (stgt_plugin_task_t *) task->transport_req;
	struct Scsi_Host *sh = task->se_dev->se_hba->hba_ptr;
	struct scsi_cmnd *sc;
	int tag = MSG_SIMPLE_TAG;

	sc = scsi_host_get_command(sh, st->stgt_direction, GFP_KERNEL);
	if (!sc) {
		printk(KERN_ERR "Unable to allocate memory for struct"
			" scsi_cmnd\n");
		return PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE;
	}

	memcpy(sc->cmnd, st->stgt_cdb, MAX_COMMAND_SIZE);
	sc->sdb.length = task->task_size;
	sc->sdb.table.sgl = task->task_sg;
	sc->tag = tag;

	BUG();
#warning FIXME: Get struct scsi_lun for scsi_tgt_queue_command()
#if 0
	err = scsi_tgt_queue_command(sc, itn_id, (struct scsi_lun *)&cmd->lun,
			cmd->tag);
	if (err) {
		printk(KERN_INFO "scsi_tgt_queue_command() failed for sc:"
			" %p\n", sc);
		scsi_host_put_command(sh, sc);
	}
#endif
	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

/*	stgt_free_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
void stgt_free_task(se_task_t *task)
{
	stgt_plugin_task_t *st = (stgt_plugin_task_t *)task->transport_req;

	kfree(st);
}

ssize_t stgt_set_configfs_dev_params(se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	const char *page,
	ssize_t count)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) se_dev->se_dev_su_ptr;
	struct Scsi_Host *sh = (struct Scsi_Host *) hba->hba_ptr;
	char *buf, *cur, *ptr, *ptr2;
	unsigned long scsi_channel_id, scsi_target_id, scsi_lun_id;
	int params = 0, ret;
	/*
	 * Make sure we take into account the NULL terminator when copying
	 * the const buffer here..
	 */
	buf = kzalloc(count + 1, GFP_KERNEL);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate memory for temporary"
				" buffer\n");
		return -ENOMEM;
	}
	memcpy(buf, page, count);
	cur = buf;

	while (cur) {
		ptr = strstr(cur, "=");
		if (!(ptr))
			goto out;

		*ptr = '\0';
		ptr++;

		ptr2 = strstr(cur, "scsi_channel_id");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &scsi_channel_id);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" scsi_channel_id=\n");
				break;
			}
			sdv->sdv_channel_id = (int)scsi_channel_id;
			printk(KERN_INFO "STGT[%d]: Referencing SCSI Channel"
				" ID: %d\n",  sh->host_no, sdv->sdv_channel_id);
			sdv->sdv_flags |= PDF_HAS_CHANNEL_ID;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "scsi_target_id");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &scsi_target_id);
			if (ret < 0) {
				printk("tcm_strict_strtoul() failed for"
					" tcm_strict_strtoul()\n");
				break;
			}
			sdv->sdv_target_id = (int)scsi_target_id;
			printk(KERN_INFO "STGT[%d]: Referencing SCSI Target"
				" ID: %d\n", sh->host_no, sdv->sdv_target_id);
			sdv->sdv_flags |= PDF_HAS_TARGET_ID;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "scsi_lun_id");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &scsi_lun_id);
			if (ret < 0) {
				printk("tcm_strict_strtoul() failed for"
					" scsi_lun_id=\n");
				break;
			}
			sdv->sdv_lun_id = (int)scsi_lun_id;
			printk(KERN_INFO "STGT[%d]: Referencing SCSI LUN ID:"
				" %d\n", sh->host_no, sdv->sdv_lun_id);
			sdv->sdv_flags |= PDF_HAS_LUN_ID;
			params++;
		} else
			cur = NULL;
	}

out:
	kfree(buf);
	return (params) ? count : -EINVAL;
}

ssize_t stgt_check_configfs_dev_params(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) se_dev->se_dev_su_ptr;

	if (!(sdv->sdv_flags & PDF_HAS_CHANNEL_ID) ||
	    !(sdv->sdv_flags & PDF_HAS_TARGET_ID) ||
	    !(sdv->sdv_flags & PDF_HAS_TARGET_ID)) {
		printk(KERN_ERR "Missing scsi_channel_id=, scsi_target_id= and"
			" scsi_lun_id= parameters\n");
		return -1;
	}

	return 0;
}

ssize_t stgt_show_configfs_dev_params(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	char *page)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) se_dev->se_dev_su_ptr;
	int bl = 0;

	__stgt_get_dev_info(sdv, page, &bl);
	return (ssize_t)bl;
}

void stgt_get_plugin_info(void *p, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "%s STGT <-> Target_Core_Mod Plugin %s\n",
		PYX_ISCSI_VENDOR, STGT_VERSION);
}

void stgt_get_hba_info(se_hba_t *hba, char *b, int *bl)
{
	struct Scsi_Host *sh = (struct Scsi_Host *) hba->hba_ptr;

	*bl += sprintf(b + *bl, "Core Host ID: %u  SCSI Host ID: %u\n",
			 hba->hba_id, sh->host_no);
	*bl += sprintf(b + *bl, "        SCSI HBA: %s  <local>\n",
		(sh->hostt->name) ? (sh->hostt->name) : "Unknown");
}

void stgt_get_dev_info(se_device_t *dev, char *b, int *bl)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;

	__stgt_get_dev_info(sdv, b, bl);
}

void __stgt_get_dev_info(stgt_dev_virt_t *sdv, char *b, int *bl)
{
	int i;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;

	*bl += sprintf(b + *bl, "STGT SCSI Device Bus Location:"
		" Channel ID: %d Target ID: %d LUN: %d\n",
		sdv->sdv_channel_id, sdv->sdv_target_id, sdv->sdv_lun_id);

	if (sd) {
		*bl += sprintf(b + *bl, "        ");
		*bl += sprintf(b + *bl, "Vendor: ");
		for (i = 0; i < 8; i++) {
			if (ISPRINT(sd->vendor[i]))   /* printable character? */
				*bl += sprintf(b + *bl, "%c", sd->vendor[i]);
			else
				*bl += sprintf(b + *bl, " ");
		}
		*bl += sprintf(b + *bl, " Model: ");
		for (i = 0; i < 16; i++) {
			if (ISPRINT(sd->model[i]))   /* printable character ? */
				*bl += sprintf(b + *bl, "%c", sd->model[i]);
			else
				*bl += sprintf(b + *bl, " ");
		}
		*bl += sprintf(b + *bl, " Rev: ");
		for (i = 0; i < 4; i++) {
			if (ISPRINT(sd->rev[i]))   /* printable character ? */
				*bl += sprintf(b + *bl, "%c", sd->rev[i]);
			else
				*bl += sprintf(b + *bl, " ");
		}

		if (sd->type == TYPE_DISK) {
			struct scsi_disk *sdisk =
					dev_get_drvdata(&sd->sdev_gendev);
			struct gendisk *disk = (struct gendisk *) sdisk->disk;
			struct block_device *bdev = bdget(MKDEV(disk->major,
						disk->first_minor));

			bdev->bd_disk = disk;
			*bl += sprintf(b + *bl, "   %s\n", (!bdev->bd_holder) ?
					"" : (bdev->bd_holder ==
					(struct scsi_device *)sd) ?
					"CLAIMED: PSCSI" : "CLAIMED: OS");
		} else
			*bl += sprintf(b + *bl, "\n");
	}

	return;
}

/*      stgt_map_task_SG():
 *
 *
 */
int stgt_map_task_SG(se_task_t *task)
{
	return 0;
}

/*	stgt_map_task_non_SG():
 *
 *
 */
int stgt_map_task_non_SG(se_task_t *task)
{
	return 0;
}

/*	stgt_CDB_inquiry():
 *
 *
 */
int stgt_CDB_inquiry(se_task_t *task, u32 size)
{
	stgt_plugin_task_t *st = (stgt_plugin_task_t *) task->transport_req;

	st->stgt_direction = DMA_FROM_DEVICE;
	return stgt_map_task_non_SG(task);
}

int stgt_CDB_none(se_task_t *task, u32 size)
{
	stgt_plugin_task_t *st = (stgt_plugin_task_t *) task->transport_req;

	st->stgt_direction = DMA_NONE;
	return 0;
}

/*	stgt_CDB_read_non_SG():
 *
 *
 */
int stgt_CDB_read_non_SG(se_task_t *task, u32 size)
{
	stgt_plugin_task_t *pt = (stgt_plugin_task_t *) task->transport_req;

	pt->stgt_direction = DMA_FROM_DEVICE;
	return stgt_map_task_non_SG(task);
}

/*	stgt_CDB_read_SG():
 *
 *
 */
int stgt_CDB_read_SG(se_task_t *task, u32 size)
{
	stgt_plugin_task_t *pt = (stgt_plugin_task_t *) task->transport_req;

	pt->stgt_direction = DMA_FROM_DEVICE;

	if (stgt_map_task_SG(task) < 0)
		return PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	return task->task_sg_num;
}

/*	stgt_CDB_write_non_SG():
 *
 *
 */
int stgt_CDB_write_non_SG(se_task_t *task, u32 size)
{
	stgt_plugin_task_t *pt = (stgt_plugin_task_t *) task->transport_req;

	pt->stgt_direction = DMA_TO_DEVICE;
	return stgt_map_task_non_SG(task);
}

/*	stgt_CDB_write_SG():
 *
 *
 */
int stgt_CDB_write_SG(se_task_t *task, u32 size)
{
	stgt_plugin_task_t *st = (stgt_plugin_task_t *) task->transport_req;

	st->stgt_direction = DMA_TO_DEVICE;

	if (stgt_map_task_SG(task) < 0)
		return PYX_TRANSPORT_LOGICAL_UNIT_COMMUNICATION_FAILURE;

	return task->task_sg_num;
}

/*	stgt_check_lba():
 *
 *
 */
int stgt_check_lba(unsigned long long lba, se_device_t *dev)
{
	return 0;
}

/*	stgt_check_for_SG():
 *
 *
 */
int stgt_check_for_SG(se_task_t *task)
{
	return task->task_sg_num;
}

/*	stgt_get_cdb():
 *
 *
 */
unsigned char *stgt_get_cdb(se_task_t *task)
{
	stgt_plugin_task_t *pt = (stgt_plugin_task_t *) task->transport_req;

	return pt->stgt_cdb;
}

/*	stgt_get_sense_buffer():
 *
 *
 */
unsigned char *stgt_get_sense_buffer(se_task_t *task)
{
	stgt_plugin_task_t *pt = (stgt_plugin_task_t *) task->transport_req;

	return (unsigned char *)&pt->stgt_sense[0];
}

/*	stgt_get_blocksize():
 *
 *
 */
u32 stgt_get_blocksize(se_device_t *dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;

	return sd->sector_size;
}

/*	stgt_get_device_rev():
 *
 *
 */
u32 stgt_get_device_rev(se_device_t *dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;

	return (sd->scsi_level - 1) ? sd->scsi_level - 1 : 1;
}

/*	stgt_get_device_type():
 *
 *
 */
u32 stgt_get_device_type(se_device_t *dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;

	return sd->type;
}

/*	stgt_get_dma_length():
 *
 *
 */
u32 stgt_get_dma_length(u32 task_size, se_device_t *dev)
{
	return PAGE_SIZE;
}

/*	stgt_get_max_sectors():
 *
 *
 */
u32 stgt_get_max_sectors(se_device_t *dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;
	return (sd->host->max_sectors > sd->request_queue->max_sectors) ?
		sd->request_queue->max_sectors : sd->host->max_sectors;
}

/*	stgt_get_queue_depth():
 *
 *
 */
u32 stgt_get_queue_depth(se_device_t *dev)
{
	stgt_dev_virt_t *sdv = (stgt_dev_virt_t *) dev->dev_ptr;
	struct scsi_device *sd = (struct scsi_device *) sdv->sdv_sd;

	return sd->queue_depth;
}

void stgt_shutdown_hba(se_hba_t *hba)
{
	return;
}

/*	stgt_handle_SAM_STATUS_failures():
 *
 *
 */
static inline void stgt_process_SAM_status(
	se_task_t *task,
	stgt_plugin_task_t *st)
{
	task->task_scsi_status = status_byte(st->stgt_result);
	if ((task->task_scsi_status)) {
		task->task_scsi_status <<= 1;
		printk(KERN_INFO "PSCSI Status Byte exception at task: %p CDB:"
			" 0x%02x Result: 0x%08x\n", task, st->stgt_cdb[0],
			st->stgt_result);
	}

	switch (host_byte(st->stgt_result)) {
	case DID_OK:
		transport_complete_task(task, (!task->task_scsi_status));
		break;
	default:
		printk(KERN_INFO "PSCSI Host Byte exception at task: %p CDB:"
			" 0x%02x Result: 0x%08x\n", task, st->stgt_cdb[0],
			st->stgt_result);
		task->task_scsi_status = SAM_STAT_CHECK_CONDITION;
		task->task_error_status = PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		TASK_CMD(task)->transport_error_status =
					PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		transport_complete_task(task, 0);
		break;
	}

	return;
}

/*
 * Use for struct scsi_host_template->transfer_response() function pointer
 * that is called from STGT in drivers/scsi/scsi_tgt_lib.c:
 * scsi_tgt_transfer_response()
 */
int stgt_transfer_response(struct scsi_cmnd *sc,
			   void (*done)(struct scsi_cmnd *))
{
	se_task_t *task = (se_task_t *)sc->SCp.ptr;
	stgt_plugin_task_t *st;

	if (!task) {
		printk(KERN_ERR "se_task_t is NULL!\n");
		BUG();
	}
	st = (stgt_plugin_task_t *)task->transport_req;
	if (!st) {
		printk(KERN_ERR "stgt_plugin_task_t is NULL!\n");
		BUG();
	}
	st->stgt_result = sc->request->errors;
	st->stgt_resid = sc->request->data_len;

#warning FIXME: Sense for STGT struct scsi_cmnd usage..
#if 0
	memcpy(st->stgt_sense, sense, SCSI_SENSE_BUFFERSIZE);
#endif
	stgt_process_SAM_status(task, st);
	done(sc);
	return 0;
}
