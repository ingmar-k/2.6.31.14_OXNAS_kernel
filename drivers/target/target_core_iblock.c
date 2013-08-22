/*******************************************************************************
 * Filename:  target_core_iblock.c
 *
 * This file contains the Storage Engine  <-> Linux BlockIO transport
 * specific functions.
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

#define TARGET_CORE_IBLOCK_C
#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/bio.h>
#include <linux/genhd.h>
#include <linux/file.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>

#include <../lio-core/iscsi_linux_defs.h>
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26)
#include <linux/math64.h>
#else
#include <target/math64.h>
#endif

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_transport.h>
#include <target/target_core_iblock.h>

#undef TARGET_CORE_IBLOCK_C

#if 0
#define DEBUG_IBLOCK(x...) printk(x)
#else
#define DEBUG_IBLOCK(x...)
#endif

/*	iblock_attach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
int iblock_attach_hba(se_hba_t *hba, u32 host_id)
{
	iblock_hba_t *ib_host;

	ib_host = kzalloc(sizeof(iblock_hba_t), GFP_KERNEL);
	if (!(ib_host)) {
		printk(KERN_ERR "Unable to allocate memory for iblock_hba_t\n");
		return -ENOMEM;
	}

	ib_host->iblock_host_id = host_id;

	atomic_set(&hba->left_queue_depth, IBLOCK_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, IBLOCK_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) ib_host;
	hba->transport = &iblock_template;

	printk(KERN_INFO "CORE_HBA[%d] - %s iBlock HBA Driver %s on"
		" Generic Target Core Stack %s\n", hba->hba_id,
		PYX_ISCSI_VENDOR, IBLOCK_VERSION, TARGET_CORE_MOD_VERSION);

	printk(KERN_INFO "CORE_HBA[%d] - Attached iBlock HBA: %u to Generic"
		" Target Core TCQ Depth: %d\n", hba->hba_id,
		ib_host->iblock_host_id, atomic_read(&hba->max_queue_depth));

	return 0;
}

/*	iblock_detach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
int iblock_detach_hba(se_hba_t *hba)
{
	iblock_hba_t *ib_host;

	if (!hba->hba_ptr) {
		printk(KERN_ERR "hba->hba_ptr is NULL!\n");
		return -1;
	}
	ib_host = (iblock_hba_t *) hba->hba_ptr;

	printk(KERN_INFO "CORE_HBA[%d] - Detached iBlock HBA: %u from Generic"
		" Target Core\n", hba->hba_id, ib_host->iblock_host_id);

	kfree(ib_host);
	hba->hba_ptr = NULL;

	return 0;
}

int iblock_claim_phydevice(se_hba_t *hba, se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *)dev->dev_ptr;
	struct block_device *bd;

	if (dev->dev_flags & DF_READ_ONLY) {
		printk(KERN_INFO "IBLOCK: Using previously claimed %p Major:"
			"Minor" " - %d:%d\n", ib_dev->ibd_bd, ib_dev->ibd_major,
			ib_dev->ibd_minor);
	} else {
		printk(KERN_INFO "IBLOCK: Claiming %p Major:Minor - %d:%d\n",
			ib_dev, ib_dev->ibd_major, ib_dev->ibd_minor);

		bd = linux_blockdevice_claim(ib_dev->ibd_major,
			ib_dev->ibd_minor, (void *)ib_dev);
		if (!(bd))
			return -1;

		ib_dev->ibd_bd = bd;
	}

	return 0;
}

static int __iblock_release_phydevice(iblock_dev_t *ib_dev, int ro)
{
	if (!ib_dev->ibd_bd)
		return 0;

	if (ro == 1) {
		printk(KERN_INFO "IBLOCK: Calling blkdev_put() for Major:Minor"
			" - %d:%d\n", ib_dev->ibd_major, ib_dev->ibd_minor);
		BLKDEV_PUT((struct block_device *)ib_dev->ibd_bd, FMODE_READ);
	} else {
		printk(KERN_INFO "IBLOCK: Releasing Major:Minor - %d:%d\n",
			ib_dev->ibd_major, ib_dev->ibd_minor);
		linux_blockdevice_release(ib_dev->ibd_major, ib_dev->ibd_minor,
			(struct block_device *)ib_dev->ibd_bd);
	}

	ib_dev->ibd_bd = NULL;

	return 0;
}

int iblock_release_phydevice(se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *)dev->dev_ptr;

	if (!ib_dev->ibd_bd)
		return 0;

	return __iblock_release_phydevice(ib_dev,
			(dev->dev_flags & DF_READ_ONLY) ? 1 : 0);
}

void *iblock_allocate_virtdevice(se_hba_t *hba, const char *name)
{
	iblock_dev_t *ib_dev = NULL;
	iblock_hba_t *ib_host = (iblock_hba_t *) hba->hba_ptr;

	ib_dev = kzalloc(sizeof(iblock_dev_t), GFP_KERNEL);
	if (!(ib_dev)) {
		printk(KERN_ERR "Unable to allocate iblock_dev_t\n");
		return NULL;
	}
	ib_dev->ibd_host = ib_host;

	printk(KERN_INFO  "IBLOCK: Allocated ib_dev for %s\n", name);

	return ib_dev;
}

se_device_t *iblock_create_virtdevice(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	void *p)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) p;
	se_device_t *dev;
	struct block_device *bd = NULL;
	u32 dev_flags = 0;
	int ret = 0;

	if (!(ib_dev)) {
		printk(KERN_ERR "Unable to locate iblock_dev_t parameter\n");
		return 0;
	}
	/*
	 * Check if we have an open file descritpor passed through configfs
	 * $TARGET/iblock_0/some_bd/fd pointing to an underlying.
	 * struct block_device.  If so, claim it with the pointer from
	 * iblock_create_virtdevice_from_fd()
	 *
	 * Otherwise, assume that parameters through 'control' attribute
	 * have set ib_dev->ibd_[major,minor]
	 */
	if (ib_dev->ibd_bd) {
		printk(KERN_INFO  "IBLOCK: Claiming struct block_device: %p\n",
			 ib_dev->ibd_bd);

		ib_dev->ibd_major = MAJOR(ib_dev->ibd_bd->bd_dev);
		ib_dev->ibd_minor = MINOR(ib_dev->ibd_bd->bd_dev);

		bd = linux_blockdevice_claim(ib_dev->ibd_major,
				ib_dev->ibd_minor, ib_dev);
		if (!(bd)) {
			printk(KERN_INFO "IBLOCK: Unable to claim"
					" struct block_device\n");
			goto failed;
		}
		dev_flags = DF_CLAIMED_BLOCKDEV;
	} else {
		printk(KERN_INFO  "IBLOCK: Claiming %p Major:Minor - %d:%d\n",
			ib_dev, ib_dev->ibd_major, ib_dev->ibd_minor);

		bd = __linux_blockdevice_claim(ib_dev->ibd_major,
				ib_dev->ibd_minor, ib_dev, &ret);
		if ((bd)) {
			if (ret == 1)
				dev_flags = DF_CLAIMED_BLOCKDEV;
			else if (ib_dev->ibd_force) {
				dev_flags = DF_READ_ONLY;
				printk(KERN_INFO "IBLOCK: DF_READ_ONLY for"
					" Major:Minor - %d:%d\n",
					ib_dev->ibd_major, ib_dev->ibd_minor);
			} else {
				printk(KERN_INFO "WARNING: Unable to claim"
					" block device. Only use force=1 for"
					" READ-ONLY access.\n");
				goto failed;
			}
			ib_dev->ibd_bd = bd;
		} else
			goto failed;
	}
	/*
	 * These settings need to be made tunable..
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,21)
	ib_dev->ibd_bio_set = bioset_create(32, 64);
#else
	ib_dev->ibd_bio_set = bioset_create(32, 64, 8);
#endif
	if (!(ib_dev->ibd_bio_set)) {
		printk(KERN_ERR "IBLOCK: Unable to create bioset()\n");
		__iblock_release_phydevice(ib_dev,
				(dev_flags == DF_READ_ONLY ? 1 : 0));
		goto failed;
	}
	printk(KERN_INFO "IBLOCK: Created bio_set() for major/minor: %d:%d\n",
		ib_dev->ibd_major, ib_dev->ibd_minor);
	/*
	 * Pass dev_flags for linux_blockdevice_claim() or
	 * linux_blockdevice_claim() from the usage above.
	 *
	 * Note that transport_add_device_to_core_hba() will call
	 * linux_blockdevice_release() internally on failure to
	 * call bd_release() on the referenced struct block_device.
	 */
	dev = transport_add_device_to_core_hba(hba,
			&iblock_template, se_dev, dev_flags, (void *)ib_dev);
	if (!(dev))
		goto failed;

	ib_dev->ibd_depth = dev->queue_depth;

	return dev;

failed:
	if (ib_dev->ibd_bio_set) {
		bioset_free(ib_dev->ibd_bio_set);
		ib_dev->ibd_bio_set = NULL;
	}
	ib_dev->ibd_bd = NULL;
	ib_dev->ibd_major = 0;
	ib_dev->ibd_minor = 0;
	return NULL;
}

/*	iblock_activate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
int iblock_activate_device(se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) dev->dev_ptr;
	iblock_hba_t *ib_hba = ib_dev->ibd_host;

	printk(KERN_INFO "CORE_iBLOCK[%u] - Activating Device with TCQ: %d at"
		" Major: %d Minor %d\n", ib_hba->iblock_host_id,
		ib_dev->ibd_depth, ib_dev->ibd_major, ib_dev->ibd_minor);

	return 0;
}

/*	iblock_deactivate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
void iblock_deactivate_device(se_device_t *dev)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) dev->dev_ptr;
	iblock_hba_t *ib_hba = ib_dev->ibd_host;

	printk(KERN_INFO "CORE_iBLOCK[%u] - Deactivating Device with TCQ: %d"
		" at Major: %d Minor %d\n", ib_hba->iblock_host_id,
		ib_dev->ibd_depth, ib_dev->ibd_major, ib_dev->ibd_minor);
}

void iblock_free_device(void *p)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) p;

	if (ib_dev->ibd_bio_set) {
		DEBUG_IBLOCK("Calling bioset_free ib_dev->ibd_bio_set: %p\n",
				ib_dev->ibd_bio_set);
		bioset_free(ib_dev->ibd_bio_set);
	}

	kfree(ib_dev);
}

int iblock_transport_complete(se_task_t *task)
{
	return 0;
}

/*	iblock_allocate_request(): (Part of se_subsystem_api_t template)
 *
 *
 */
void *iblock_allocate_request(
	se_task_t *task,
	se_device_t *dev)
{
	iblock_req_t *ib_req;

	ib_req = kzalloc(sizeof(iblock_req_t), GFP_KERNEL);
	if (!(ib_req)) {
		printk(KERN_ERR "Unable to allocate memory for iblock_req_t\n");
		return NULL;
	}

	ib_req->ib_dev = (iblock_dev_t *) dev->dev_ptr;
	atomic_set(&ib_req->ib_bio_cnt, 0);
	return ib_req;
}

static int iblock_emulate_inquiry(se_task_t *task)
{
	unsigned char prod[64], se_location[128];
	se_cmd_t *cmd = TASK_CMD(task);
	iblock_dev_t *ibd = (iblock_dev_t *) task->se_dev->dev_ptr;
	se_hba_t *hba = task->se_dev->se_hba;

	memset(prod, 0, 64);
	memset(se_location, 0, 128);

	sprintf(prod, "IBLOCK");
	sprintf(se_location, "%u_%u_%u", hba->hba_id, ibd->ibd_major,
		ibd->ibd_minor);

	return transport_generic_emulate_inquiry(cmd, TYPE_DISK, prod,
		IBLOCK_VERSION, se_location);
}

static unsigned long long iblock_emulate_read_cap_with_block_size(
	se_device_t *dev,
	struct block_device *bd,
	struct request_queue *q)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	unsigned long long blocks_long = (div_u64(i_size_read(bd->bd_inode),
					bdev_logical_block_size(bd)) - 1);
	u32 block_size = queue_logical_block_size(bdev_get_queue(bd));
#else
	unsigned long long blocks_long = (div_u64(i_size_read(bd->bd_inode),
					q->hardsect_size) - 1);
	u32 block_size = q->hardsect_size;
#endif

	if (block_size == DEV_ATTRIB(dev)->block_size)
		return blocks_long;

	switch (block_size) {
	case 4096:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 2048:
			blocks_long <<= 1;
			break;
		case 1024:
			blocks_long <<= 2;
			break;
		case 512:
			blocks_long <<= 3;
		default:
			break;
		}
		break;
	case 2048:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 4096:
			blocks_long >>= 1;
			break;
		case 1024:
			blocks_long <<= 1;
			break;
		case 512:
			blocks_long <<= 2;
			break;
		default:
			break;
		}
		break;
	case 1024:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 4096:
			blocks_long >>= 2;
			break;
		case 2048:
			blocks_long >>= 1;
			break;
		case 512:
			blocks_long <<= 1;
			break;
		default:
			break;
		}
		break;
	case 512:
		switch (DEV_ATTRIB(dev)->block_size) {
		case 4096:
			blocks_long >>= 3;
			break;
		case 2048:
			blocks_long >>= 2;
			break;
		case 1024:
			blocks_long >>= 1;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return blocks_long;
}

static int iblock_emulate_read_cap(se_task_t *task)
{
	iblock_dev_t *ibd = (iblock_dev_t *) task->se_dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	struct request_queue *q = bdev_get_queue(bd);
	unsigned long long blocks_long = 0;
	u32 blocks = 0;

	blocks_long = iblock_emulate_read_cap_with_block_size(
				task->se_dev, bd, q);
	if (blocks_long >= 0x00000000ffffffff)
		blocks = 0xffffffff;
	else
		blocks = (u32)blocks_long;

	return transport_generic_emulate_readcapacity(TASK_CMD(task), blocks);
}

static int iblock_emulate_read_cap16(se_task_t *task)
{
	iblock_dev_t *ibd = (iblock_dev_t *) task->se_dev->dev_ptr;
	struct block_device *bd = ibd->ibd_bd;
	struct request_queue *q = bdev_get_queue(bd);
	unsigned long long blocks_long;

	blocks_long = iblock_emulate_read_cap_with_block_size(
				task->se_dev, bd, q);
	return transport_generic_emulate_readcapacity_16(
				TASK_CMD(task), blocks_long);
}

static int iblock_emulate_scsi_cdb(se_task_t *task)
{
	int ret;
	se_cmd_t *cmd = TASK_CMD(task);

	switch (T_TASK(cmd)->t_task_cdb[0]) {
	case INQUIRY:
		if (iblock_emulate_inquiry(task) < 0)
			return PYX_TRANSPORT_INVALID_CDB_FIELD;
		break;
	case READ_CAPACITY:
		ret = iblock_emulate_read_cap(task);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				T_TASK(cmd)->t_task_cdb,
				T_TASK(cmd)->t_task_buf, 0, TYPE_DISK);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE_10:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				T_TASK(cmd)->t_task_cdb,
			T_TASK(cmd)->t_task_buf, 1, TYPE_DISK);
		if (ret < 0)
			return ret;
		break;
	case SERVICE_ACTION_IN:
		if ((T_TASK(cmd)->t_task_cdb[1] & 0x1f) !=
		     SAI_READ_CAPACITY_16) {
			printk(KERN_ERR "Unsupported SA: 0x%02x\n",
				T_TASK(cmd)->t_task_cdb[1] & 0x1f);
			return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
		}
		ret = iblock_emulate_read_cap16(task);
		if (ret < 0)
			return ret;
		break;
	case REQUEST_SENSE:
		ret = transport_generic_emulate_request_sense(cmd,
				T_TASK(cmd)->t_task_cdb);
		if (ret < 0)
			return ret;
		break;
	case ALLOW_MEDIUM_REMOVAL:
	case ERASE:
	case REZERO_UNIT:
	case SEEK_10:
	case SPACE:
	case START_STOP:
	case SYNCHRONIZE_CACHE:
	case TEST_UNIT_READY:
	case VERIFY:
	case WRITE_FILEMARKS:
	case RESERVE:
	case RESERVE_10:
	case RELEASE:
	case RELEASE_10:
		break;
	default:
		printk(KERN_ERR "Unsupported SCSI Opcode: 0x%02x for iBlock\n",
				T_TASK(cmd)->t_task_cdb[0]);
		return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

int iblock_do_task(se_task_t *task)
{
	iblock_req_t *req = (iblock_req_t *)task->transport_req;
	iblock_dev_t *ibd = (iblock_dev_t *)req->ib_dev;
	struct request_queue *q = bdev_get_queue(ibd->ibd_bd);
	struct bio *bio = req->ib_bio, *nbio = NULL;

	if (!(TASK_CMD(task)->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB))
		return iblock_emulate_scsi_cdb(task);

	while (bio) {
		nbio = bio->bi_next;
		bio->bi_next = NULL;
		DEBUG_IBLOCK("Calling submit_bio() task: %p bio: %p"
			" bio->bi_sector: %llu\n", task, bio, bio->bi_sector);

		submit_bio(
			(TASK_CMD(task)->data_direction == SE_DIRECTION_WRITE),
			bio);

		bio = nbio;
	}

	if (q->unplug_fn)
		q->unplug_fn(q);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

void iblock_free_task(se_task_t *task)
{
	iblock_req_t *req = (iblock_req_t *) task->transport_req;
	struct bio *bio, *hbio = req->ib_bio;
	/*
	 * We only release the bio(s) here if iblock_bio_done() has not called
	 * bio_put() -> iblock_bio_destructor().
	 */
	while (hbio != NULL) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		bio_put(bio);
	}

	kfree(req);
	task->transport_req = NULL;
}

ssize_t iblock_set_configfs_dev_params(se_hba_t *hba,
					       se_subsystem_dev_t *se_dev,
					       const char *page, ssize_t count)
{
	iblock_dev_t *ib_dev = (iblock_dev_t *) se_dev->se_dev_su_ptr;
	char *buf, *cur, *ptr, *ptr2;
	unsigned long major, minor, force;
	int params = 0, ret = 0;
	/*
	 * Make sure we take into account the NULL terminator when copying
	 * the const buffer here..
	 */
	buf = kzalloc(count + 1, GFP_KERNEL);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate memory for temporary"
			" buffer\n");
		return 0;
	}
	memcpy(buf, page, count);
	cur = buf;

	while (cur) {
		ptr = strstr(cur, "=");
		if (!(ptr))
			goto out;

		*ptr = '\0';
		ptr++;

		ptr2 = strstr(cur, "udev_path");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ptr = strstrip(ptr);
			ret = snprintf(ib_dev->ibd_udev_path, SE_UDEV_PATH_LEN,
				"%s", ptr);
			printk(KERN_INFO "IBLOCK: Referencing UDEV path: %s\n",
					ib_dev->ibd_udev_path);
			ib_dev->ibd_flags |= IBDF_HAS_UDEV_PATH;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "major");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &major);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed"
					" for major=\n");
				break;
			}
			ib_dev->ibd_major = (int)major;
			printk(KERN_INFO "IBLOCK: Referencing Major: %d\n",
					ib_dev->ibd_major);
			ib_dev->ibd_flags |= IBDF_HAS_MAJOR;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "minor");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &minor);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed"
					" for minor=\n");
				break;
			}
			ib_dev->ibd_minor = (int)minor;
			printk(KERN_INFO "IBLOCK: Referencing Minor: %d\n",
					ib_dev->ibd_minor);
			ib_dev->ibd_flags |= IBDF_HAS_MINOR;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "force");
		if ((ptr2)) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &force);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed"
					" for force=\n");
				break;
			}
			ib_dev->ibd_force = (int)force;
			printk(KERN_INFO "IBLOCK: Set force=%d\n",
				ib_dev->ibd_force);
			params++;
		} else
			cur = NULL;
	}

out:
	kfree(buf);
	return (params) ? count : -EINVAL;
}

ssize_t iblock_check_configfs_dev_params(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev)
{
	iblock_dev_t *ibd = (iblock_dev_t *) se_dev->se_dev_su_ptr;

	if (!(ibd->ibd_flags & IBDF_HAS_MAJOR) ||
	    !(ibd->ibd_flags & IBDF_HAS_MINOR)) {
		printk(KERN_ERR "Missing iblock_major= and iblock_minor="
			" parameters\n");
		return -1;
	}

	return 0;
}

ssize_t iblock_show_configfs_dev_params(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	char *page)
{
	iblock_dev_t *ibd = (iblock_dev_t *) se_dev->se_dev_su_ptr;
	int bl = 0;

	__iblock_get_dev_info(ibd, page, &bl);
	return (ssize_t)bl;
}

se_device_t *iblock_create_virtdevice_from_fd(
	se_subsystem_dev_t *se_dev,
	const char *page)
{
	iblock_dev_t *ibd = (iblock_dev_t *) se_dev->se_dev_su_ptr;
	se_device_t *dev = NULL;
	struct file *filp;
	struct inode *inode;
	char *p = (char *)page;
	unsigned long long fd;
	int ret;

	ret = tcm_strict_strtoull(p, 0, (unsigned long long *)&fd);
	if (ret < 0) {
		printk(KERN_ERR "tcm_strict_strtol() failed for fd\n");
		return ERR_PTR(-EINVAL);
	}
	if ((fd < 3 || fd > 7)) {
		printk(KERN_ERR "IBLOCK: Illegal value of file descriptor:"
				" %llu\n", fd);
		return ERR_PTR(-EINVAL);
	}
	filp = fget(fd);
	if (!(filp)) {
		printk(KERN_ERR "IBLOCK: Unable to fget() fd: %llu\n", fd);
		return ERR_PTR(-EBADF);
	}
	inode = igrab(filp->f_mapping->host);
	if (!(inode)) {
		printk(KERN_ERR "IBLOCK: Unable to locate struct inode for"
			" struct block_device fd\n");
		fput(filp);
		return ERR_PTR(-EINVAL);
	}
	if (!(S_ISBLK(inode->i_mode))) {
		printk(KERN_ERR "IBLOCK: S_ISBLK(inode->i_mode) failed for file"
				" descriptor: %llu\n", fd);
		iput(inode);
		fput(filp);
		return ERR_PTR(-ENODEV);
	}
	ibd->ibd_bd = I_BDEV(filp->f_mapping->host);
	if (!(ibd->ibd_bd)) {
		printk(KERN_ERR "IBLOCK: Unable to locate struct block_device"
				" from I_BDEV()\n");
		iput(inode);
		fput(filp);
		return ERR_PTR(-EINVAL);
	}
	/*
	 * iblock_create_virtdevice() will call linux_blockdevice_claim()
	 * to claim struct block_device.
	 */
	dev = iblock_create_virtdevice(se_dev->se_dev_hba, se_dev, (void *)ibd);

	iput(inode);
	fput(filp);
	return dev;
}

void iblock_get_plugin_info(void *p, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "%s iBlock Plugin %s\n", PYX_ISCSI_VENDOR,
			IBLOCK_VERSION);
}

void iblock_get_hba_info(se_hba_t *hba, char *b, int *bl)
{
	iblock_hba_t *ib_host = (iblock_hba_t *)hba->hba_ptr;

	*bl += sprintf(b + *bl, "SE Host ID: %u  iBlock Host ID: %u\n",
		hba->hba_id, ib_host->iblock_host_id);
	*bl += sprintf(b + *bl, "        LIO iBlock HBA\n");
}

void iblock_get_dev_info(se_device_t *dev, char *b, int *bl)
{
	iblock_dev_t *ibd = (iblock_dev_t *) dev->dev_ptr;

	__iblock_get_dev_info(ibd, b, bl);
}

void __iblock_get_dev_info(iblock_dev_t *ibd, char *b, int *bl)
{
	char buf[BDEVNAME_SIZE];
	struct block_device *bd = ibd->ibd_bd;

	if (bd)
		*bl += sprintf(b + *bl, "iBlock device: %s",
				bdevname(bd, buf));
	if (ibd->ibd_flags & IBDF_HAS_UDEV_PATH) {
		*bl += sprintf(b + *bl, "  UDEV PATH: %s\n",
				ibd->ibd_udev_path);
	} else
		*bl += sprintf(b + *bl, "\n");

	*bl += sprintf(b + *bl, "        ");
	if (bd) {
		*bl += sprintf(b + *bl, "Major: %d Minor: %d  %s\n",
			ibd->ibd_major, ibd->ibd_minor, (!bd->bd_contains) ?
			"" : (bd->bd_holder == (iblock_dev_t *)ibd) ?
			"CLAIMED: IBLOCK" : "CLAIMED: OS");
	} else {
		*bl += sprintf(b + *bl, "Major: %d Minor: %d\n",
			ibd->ibd_major, ibd->ibd_minor);
	}
}

static void iblock_bio_destructor(struct bio *bio)
{
	se_task_t *task = (se_task_t *)bio->bi_private;
	iblock_dev_t *ib_dev = (iblock_dev_t *) task->se_dev->dev_ptr;

	bio_free(bio, ib_dev->ibd_bio_set);
}

static struct bio *iblock_get_bio(se_task_t *task,
	iblock_req_t *ib_req,
	iblock_dev_t *ib_dev,
	int *ret,
	sector_t lba,
	u32 sg_num)
{
	struct bio *bio;

	bio = bio_alloc_bioset(GFP_NOIO, sg_num, ib_dev->ibd_bio_set);
	if (!(bio)) {
		printk(KERN_ERR "Unable to allocate memory for bio\n");
		*ret = PYX_TRANSPORT_OUT_OF_MEMORY_RESOURCES;
		return NULL;
	}

	DEBUG_IBLOCK("Allocated bio: %p task_sg_num: %u using ibd_bio_set:"
		" %p\n", bio, task->task_sg_num, ib_dev->ibd_bio_set);
	DEBUG_IBLOCK("Allocated bio: %p task_size: %u\n", bio, task->task_size);

	bio->bi_bdev = ib_dev->ibd_bd;
	bio->bi_private = (void *) task;
	bio->bi_destructor = iblock_bio_destructor;
	bio->bi_end_io = &iblock_bio_done;
	bio->bi_sector = lba;
	atomic_inc(&ib_req->ib_bio_cnt);

	DEBUG_IBLOCK("Set bio->bi_sector: %llu\n", bio->bi_sector);
	DEBUG_IBLOCK("Set ib_req->ib_bio_cnt: %d\n",
			atomic_read(&ib_req->ib_bio_cnt));
	return bio;
}

int iblock_map_task_SG(se_task_t *task)
{
	se_cmd_t *cmd = task->task_se_cmd;
	se_device_t *dev = SE_DEV(cmd);
	iblock_dev_t *ib_dev = (iblock_dev_t *) task->se_dev->dev_ptr;
	iblock_req_t *ib_req = (iblock_req_t *) task->transport_req;
	struct bio *bio = NULL, *hbio = NULL, *tbio = NULL;
	struct scatterlist *sg;
	int ret = 0;
	u32 i, sg_num = task->task_sg_num;
	sector_t block_lba;
	/*
	 * Do starting conversion up from non 512-byte blocksize with
	 * struct se_task SCSI blocksize into Linux/Block 512 units for BIO.
	 */
	if (DEV_ATTRIB(dev)->block_size == 4096)
		block_lba = (task->task_lba << 3);
	else if (DEV_ATTRIB(dev)->block_size == 2048)
		block_lba = (task->task_lba << 2);
	else if (DEV_ATTRIB(dev)->block_size == 1024)
		block_lba = (task->task_lba << 1);
	else if (DEV_ATTRIB(dev)->block_size == 512)
		block_lba = task->task_lba;
	else {
		printk(KERN_ERR "Unsupported SCSI -> BLOCK LBA conversion:"
				" %u\n", DEV_ATTRIB(dev)->block_size);
		return PYX_TRANSPORT_LU_COMM_FAILURE;
	}

	atomic_set(&ib_req->ib_bio_cnt, 0);

	bio = iblock_get_bio(task, ib_req, ib_dev, &ret, block_lba, sg_num);
	if (!(bio))
		return ret;

	ib_req->ib_bio = bio;
	hbio = tbio = bio;
	/*
	 * Use fs/bio.c:bio_add_pages() to setup the bio_vec maplist
	 * from LIO-SE se_mem_t -> task->task_sg -> struct scatterlist memory.
	 */
	for_each_sg(task->task_sg, sg, task->task_sg_num, i) {
		DEBUG_IBLOCK("task: %p bio: %p Calling bio_add_page(): page:"
			" %p len: %u offset: %u\n", task, bio, GET_PAGE_SG(sg),
				sg->length, sg->offset);
again:
		ret = bio_add_page(bio, GET_PAGE_SG(sg), sg->length,
				sg->offset);
		if (ret != sg->length) {

			DEBUG_IBLOCK("*** Set bio->bi_sector: %llu\n",
					bio->bi_sector);
			DEBUG_IBLOCK("** task->task_size: %u\n",
					task->task_size);
			DEBUG_IBLOCK("*** bio->bi_max_vecs: %u\n",
					bio->bi_max_vecs);
			DEBUG_IBLOCK("*** bio->bi_vcnt: %u\n",
					bio->bi_vcnt);

			bio = iblock_get_bio(task, ib_req, ib_dev, &ret,
						block_lba, sg_num);
			if (!(bio))
				goto fail;

			tbio = tbio->bi_next = bio;
			DEBUG_IBLOCK("-----------------> Added +1 bio: %p to"
				" list, Going to again\n", bio);
			goto again;
		}
		/* Always in 512 byte units for Linux/Block */
		block_lba += sg->length >> IBLOCK_LBA_SHIFT;
		sg_num--;
		DEBUG_IBLOCK("task: %p bio-add_page() passed!, decremented"
			" sg_num to %u\n", task, sg_num);
		DEBUG_IBLOCK("task: %p bio_add_page() passed!, increased lba"
				" to %llu\n", task, block_lba);
		DEBUG_IBLOCK("task: %p bio_add_page() passed!, bio->bi_vcnt:"
				" %u\n", task, bio->bi_vcnt);
	}

	return task->task_sg_num;
fail:
	while (hbio) {
		bio = hbio;
		hbio = hbio->bi_next;
		bio->bi_next = NULL;
		bio_put(bio);
	}
	return ret;
}

int iblock_CDB_inquiry(se_task_t *task, u32 size)
{
	return 0;
}

int iblock_CDB_none(se_task_t *task, u32 size)
{
	return 0;
}

int iblock_CDB_read_non_SG(se_task_t *task, u32 size)
{
	return 0;
}

int iblock_CDB_read_SG(se_task_t *task, u32 size)
{
	return iblock_map_task_SG(task);
}

int iblock_CDB_write_non_SG(se_task_t *task, u32 size)
{
	return 0;
}

int iblock_CDB_write_SG(se_task_t *task, u32 size)
{
	return iblock_map_task_SG(task);
}

int iblock_check_lba(unsigned long long lba, se_device_t *dev)
{
	return 0;
}

int iblock_check_for_SG(se_task_t *task)
{
	return task->task_sg_num;
}

unsigned char *iblock_get_cdb(se_task_t *task)
{
	iblock_req_t *req = (iblock_req_t *) task->transport_req;

	return req->ib_scsi_cdb;
}

u32 iblock_get_blocksize(se_device_t *dev)
{
	iblock_dev_t *ibd = (iblock_dev_t *) dev->dev_ptr;
	struct request_queue *q = bdev_get_queue(ibd->ibd_bd);
	/*
	 * Set via blk_queue_hardsect_size() in
	 * drivers/scsi/sd.c:sd_read_capacity()
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	return queue_logical_block_size(q);
#else
	return q->hardsect_size;
#endif
}

u32 iblock_get_device_rev(se_device_t *dev)
{
	return SCSI_SPC_2; /* Returns SPC-3 in Initiator Data */
}

u32 iblock_get_device_type(se_device_t *dev)
{
	return TYPE_DISK;
}

u32 iblock_get_dma_length(u32 task_size, se_device_t *dev)
{
	return PAGE_SIZE;
}

u32 iblock_get_max_sectors(se_device_t *dev)
{
	iblock_dev_t *ibd = (iblock_dev_t *) dev->dev_ptr;
	struct request_queue *q = bdev_get_queue(ibd->ibd_bd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
	return q->limits.max_sectors;
#else
	return (q->max_sectors < IBLOCK_MAX_SECTORS) ?
		q->max_sectors : IBLOCK_MAX_SECTORS;
#endif
}

u32 iblock_get_queue_depth(se_device_t *dev)
{
	return IBLOCK_DEVICE_QUEUE_DEPTH;
}

u32 iblock_get_max_queue_depth(se_device_t *dev)
{
	return IBLOCK_MAX_DEVICE_QUEUE_DEPTH;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
void iblock_bio_done(struct bio *bio, int err)
#else
extern int iblock_bio_done(struct bio *bio, unsigned int bytes_done, int err)
#endif
{
	se_task_t *task = bio->bi_private;
	iblock_req_t *ibr = task->transport_req;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	int ret = 0;
        if (bio->bi_size) {
                printk(KERN_ERR "bio: %p task_lba: %llu bio_lba: %llu err=%d,"
                        " returned with bio->bi_size: %u\n", bio, task->task_lba,
                                (unsigned long long)bio->bi_sector, err, bio->bi_size);
                transport_complete_task(task, 0);
                ret = 1;
                goto out;
        }
#endif
	/*
	 * Set -EIO if !BIO_UPTODATE and the passed is still err=0
	 */
	if (!(test_bit(BIO_UPTODATE, &bio->bi_flags)) && !(err))
		err = -EIO;

	if (err != 0) {
		printk(KERN_ERR "test_bit(BIO_UPTODATE) failed for bio: %p,"
			" err: %d\n", bio, err);
		/*
		 * Bump the ib_bio_err_cnt and release bio.
		 */
		atomic_inc(&ibr->ib_bio_err_cnt);
		smp_mb__after_atomic_inc();
		bio_put(bio);
		/*
		 * Wait to complete the task until the last bio as completed.
		 */
		if (!(atomic_dec_and_test(&ibr->ib_bio_cnt)))
			goto out;

		ibr->ib_bio = NULL;
		transport_complete_task(task, 0);
		goto out;
	}
	DEBUG_IBLOCK("done[%p] bio: %p task_lba: %llu bio_lba: %llu err=%d\n",
		task, bio, task->task_lba, bio->bi_sector, err);
	/*
	 * bio_put() will call iblock_bio_destructor() to release the bio back
	 * to ibr->ib_bio_set.
	 */
	bio_put(bio);

	/*
	 * Wait to complete the task until the last bio as completed.
	 */
	if (!(atomic_dec_and_test(&ibr->ib_bio_cnt)))
		goto out;

	ibr->ib_bio = NULL;
	transport_complete_task(task, (!atomic_read(&ibr->ib_bio_err_cnt)));
out:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
        return;
#else
        return ret;
#endif
}
