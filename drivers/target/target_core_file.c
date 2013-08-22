/*******************************************************************************
 * Filename:  target_core_file.c
 *
 * This file contains the Storage Engine <-> FILEIO transport specific functions
 *
 * Copyright (c) 2005 PyX Technologies, Inc.
 * Copyright (c) 2005-2006 SBE, Inc.  All Rights Reserved.
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


#define TARGET_CORE_FILE_C

#include <linux/version.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/blkdev.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
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
#include <target/target_core_file.h>

#undef TARGET_CORE_FILE_C

/*	fd_attach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
int fd_attach_hba(se_hba_t *hba, u32 host_id)
{
	fd_host_t *fd_host;

	fd_host = kzalloc(sizeof(fd_host_t), GFP_KERNEL);
	if (!(fd_host)) {
		printk(KERN_ERR "Unable to allocate memory for fd_host_t\n");
		return -1;
	}

	fd_host->fd_host_id = host_id;

	atomic_set(&hba->left_queue_depth, FD_HBA_QUEUE_DEPTH);
	atomic_set(&hba->max_queue_depth, FD_HBA_QUEUE_DEPTH);
	hba->hba_ptr = (void *) fd_host;
	hba->transport = &fileio_template;

	printk(KERN_INFO "CORE_HBA[%d] - %s FILEIO HBA Driver %s on Generic"
		" Target Core Stack %s\n", hba->hba_id,
		PYX_ISCSI_VENDOR, FD_VERSION, TARGET_CORE_MOD_VERSION);
	printk(KERN_INFO "CORE_HBA[%d] - Attached FILEIO HBA: %u to Generic"
		" Target Core with TCQ Depth: %d MaxSectors: %u\n",
		hba->hba_id, fd_host->fd_host_id,
		atomic_read(&hba->max_queue_depth), FD_MAX_SECTORS);

	return 0;
}

/*	fd_detach_hba(): (Part of se_subsystem_api_t template)
 *
 *
 */
int fd_detach_hba(se_hba_t *hba)
{
	fd_host_t *fd_host;

	if (!hba->hba_ptr) {
		printk(KERN_ERR "hba->hba_ptr is NULL!\n");
		return -1;
	}
	fd_host = (fd_host_t *) hba->hba_ptr;

	printk(KERN_INFO "CORE_HBA[%d] - Detached FILEIO HBA: %u from Generic"
		" Target Core\n", hba->hba_id, fd_host->fd_host_id);

	kfree(fd_host);
	hba->hba_ptr = NULL;

	return 0;
}

int fd_claim_phydevice(se_hba_t *hba, se_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *)dev->dev_ptr;
	struct block_device *bd;

	if (fd_dev->fd_bd)
		return 0;

	if (dev->dev_flags & DF_READ_ONLY) {
		printk(KERN_INFO "FILEIO: Using previously claimed %p Major"
			":Minor - %d:%d\n", fd_dev->fd_bd, fd_dev->fd_major,
			fd_dev->fd_minor);
	} else {
		printk(KERN_INFO "FILEIO: Claiming %p Major:Minor - %d:%d\n",
			fd_dev, fd_dev->fd_major, fd_dev->fd_minor);

		bd = linux_blockdevice_claim(fd_dev->fd_major,
				fd_dev->fd_minor, (void *)fd_dev);
		if (!(bd))
			return -1;

		fd_dev->fd_bd = bd;
	}

	return 0;
}

int fd_release_phydevice(se_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *)dev->dev_ptr;

	if (!fd_dev->fd_bd)
		return 0;

	if (dev->dev_flags & DF_READ_ONLY) {
		printk(KERN_INFO "FILEIO: Calling blkdev_put() for Major:Minor"
			" - %d:%d\n", fd_dev->fd_major, fd_dev->fd_minor);
		BLKDEV_PUT((struct block_device *)fd_dev->fd_bd, FMODE_READ);
	} else {
		printk(KERN_INFO "FILEIO: Releasing Major:Minor - %d:%d\n",
			fd_dev->fd_major, fd_dev->fd_minor);
		linux_blockdevice_release(fd_dev->fd_major, fd_dev->fd_minor,
			(struct block_device *)fd_dev->fd_bd);
	}
	fd_dev->fd_bd = NULL;

	return 0;
}

void *fd_allocate_virtdevice(se_hba_t *hba, const char *name)
{
	fd_dev_t *fd_dev;
	fd_host_t *fd_host = (fd_host_t *) hba->hba_ptr;

	fd_dev = kzalloc(sizeof(fd_dev_t), GFP_KERNEL);
	if (!(fd_dev)) {
		printk(KERN_ERR "Unable to allocate memory for fd_dev_t\n");
		return NULL;
	}

	fd_dev->fd_host = fd_host;

	printk(KERN_INFO "FILEIO: Allocated fd_dev for %p\n", name);

	return fd_dev;
}

/*	fd_create_virtdevice(): (Part of se_subsystem_api_t template)
 *
 *
 */
se_device_t *fd_create_virtdevice(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	void *p)
{
	char *dev_p = NULL;
	se_device_t *dev;
	fd_dev_t *fd_dev = (fd_dev_t *) p;
	fd_host_t *fd_host = (fd_host_t *) hba->hba_ptr;
	mm_segment_t old_fs;
	struct block_device *bd = NULL;
	struct file *file;
	struct inode *inode = NULL;
	struct request_queue *q;
	unsigned long long blocks_long;
	int dev_flags = 0, flags;
	u32 block_size;

	old_fs = get_fs();
	set_fs(get_ds());
	dev_p = getname(fd_dev->fd_dev_name);
	set_fs(old_fs);

	if (IS_ERR(dev_p)) {
		printk(KERN_ERR "getname(%s) failed: %lu\n",
			fd_dev->fd_dev_name, IS_ERR(dev_p));
		goto fail;
	}
#if 0
	if (di->no_create_file)
		flags = O_RDWR | O_LARGEFILE;
	else
		flags = O_RDWR | O_CREAT | O_LARGEFILE;
#else
	flags = O_RDWR | O_CREAT | O_LARGEFILE;
#endif
/*	flags |= O_DIRECT; */
	/*
	 * If fd_buffered_io=1 has not been set explictly (the default),
	 * use O_SYNC to force FILEIO writes to disk.
	 */
	if (!(fd_dev->fbd_flags & FDBD_USE_BUFFERED_IO))
		flags |= O_SYNC;

	file = filp_open(dev_p, flags, 0600);

	if (IS_ERR(file) || !file || !file->f_dentry) {
		printk(KERN_ERR "filp_open(%s) failed\n", dev_p);
		goto fail;
	}
	fd_dev->fd_file = file;
	/*
	 * If we are claiming a blockend for this struct file, we extract
	 * fd_dev->fd_size from struct block_device.
	 *
	 * Otherwise, we use the passed fd_size= from configfs
	 */
	inode = igrab(file->f_mapping->host);
	if (!(inode)) {
		printk(KERN_ERR "FILEIO: Unable to locate struct inode from"
			" struct file\n");
		goto fail;
	}
	/*
	 * If struct file is referencing a underlying struct block_device,
	 * claim it now.
	 */
	if (S_ISBLK(inode->i_mode)) {
		fd_dev->fd_bd = I_BDEV(file->f_mapping->host);
		if (!(fd_dev->fd_bd)) {
			printk(KERN_ERR "FILEIO: Unable to locate struct"
				" block_device\n");
			goto fail;
		}
		fd_dev->fd_major = MAJOR(fd_dev->fd_bd->bd_dev);
		fd_dev->fd_minor = MINOR(fd_dev->fd_bd->bd_dev);

		printk(KERN_INFO "FILEIO: Claiming %p Major:Minor - %d:%d\n",
			fd_dev, fd_dev->fd_major, fd_dev->fd_minor);

		bd = linux_blockdevice_claim(fd_dev->fd_major, fd_dev->fd_minor,
					fd_dev);
		if (!(bd)) {
			printk("FILEIO: Unable to claim struct block_device\n");
			goto fail;
		}

		dev_flags |= DF_CLAIMED_BLOCKDEV;
		/*
		 * Determine the number of bytes from i_size_read() minus
		 * one (1) logical sector from underlying struct block_device
		 */
		q = bdev_get_queue(bd);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31)
		block_size = queue_logical_block_size(q);
#else
		block_size = q->hardsect_size;
#endif
		fd_dev->fd_dev_size = (i_size_read(file->f_mapping->host) -
					block_size);
		blocks_long = div_u64(fd_dev->fd_dev_size, block_size);
		printk(KERN_INFO "FILEIO: Using size: %llu bytes from struct"
			" block_device blocks: %llu hardsect_size: %d\n",
				fd_dev->fd_dev_size, blocks_long,
				block_size);
	} else {
		if (!(fd_dev->fbd_flags & FBDF_HAS_SIZE)) {
			printk(KERN_ERR "FILEIO: Missing fd_dev_size="
				" parameter, and no backing struct"
				" block_device\n");
			goto fail;
		}
	}
	/*
	 * Pass dev_flags for linux_blockdevice_claim_bd or
	 * linux_blockdevice_claim() from the usage above.
	 *
	 * Note that transport_add_device_to_core_hba() will call
	 * linux_blockdevice_release() internally on failure to
	 * call bd_release() on the referenced struct block_device.
	 */
	dev = transport_add_device_to_core_hba(hba, &fileio_template,
				se_dev, dev_flags, (void *)fd_dev);
	if (!(dev))
		goto fail;

	fd_dev->fd_dev_id = fd_host->fd_host_dev_id_count++;
	fd_dev->fd_queue_depth = dev->queue_depth;

	printk(KERN_INFO "CORE_FILE[%u] - Added LIO FILEIO Device ID: %u at %s,"
		" %llu total bytes\n", fd_host->fd_host_id, fd_dev->fd_dev_id,
			fd_dev->fd_dev_name, fd_dev->fd_dev_size);

	iput(inode);
	putname(dev_p);
	return dev;
fail:
	if (fd_dev->fd_file) {
		filp_close(fd_dev->fd_file, NULL);
		fd_dev->fd_file = NULL;
	}
	fd_dev->fd_bd = NULL;
	fd_dev->fd_major = 0;
	fd_dev->fd_minor = 0;
	if (inode)
		iput(inode);
	putname(dev_p);
	return NULL;
}

/*	fd_activate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
int fd_activate_device(se_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *) dev->dev_ptr;
	fd_host_t *fd_host = fd_dev->fd_host;

	printk(KERN_INFO "CORE_FILE[%u] - Activating Device with TCQ: %d at"
		" FILEIO Device ID: %d\n", fd_host->fd_host_id,
		fd_dev->fd_queue_depth, fd_dev->fd_dev_id);

	return 0;
}

/*	fd_deactivate_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
void fd_deactivate_device(se_device_t *dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *) dev->dev_ptr;
	fd_host_t *fd_host = fd_dev->fd_host;

	printk(KERN_INFO "CORE_FILE[%u] - Deactivating Device with TCQ: %d at"
		" FILEIO Device ID: %d\n", fd_host->fd_host_id,
		fd_dev->fd_queue_depth, fd_dev->fd_dev_id);

	return;
}

/*	fd_free_device(): (Part of se_subsystem_api_t template)
 *
 *
 */
void fd_free_device(void *p)
{
	fd_dev_t *fd_dev = (fd_dev_t *) p;

	if (fd_dev->fd_file) {
		filp_close(fd_dev->fd_file, NULL);
		fd_dev->fd_file = NULL;
	}

	kfree(fd_dev);
}

/*	fd_transport_complete(): (Part of se_subsystem_api_t template)
 *
 *
 */
int fd_transport_complete(se_task_t *task)
{
	return 0;
}

/*	fd_allocate_request(): (Part of se_subsystem_api_t template)
 *
 *
 */
void *fd_allocate_request(
	se_task_t *task,
	se_device_t *dev)
{
	fd_request_t *fd_req;

	fd_req = kzalloc(sizeof(fd_request_t), GFP_KERNEL);
	if (!(fd_req)) {
		printk(KERN_ERR "Unable to allocate fd_request_t\n");
		return NULL;
	}

	fd_req->fd_dev = (fd_dev_t *) dev->dev_ptr;

	return (void *)fd_req;
}

/*	fd_emulate_inquiry():
 *
 *
 */
int fd_emulate_inquiry(se_task_t *task)
{
	unsigned char prod[64], se_location[128];
	se_cmd_t *cmd = TASK_CMD(task);
	fd_dev_t *fdev = (fd_dev_t *) task->se_dev->dev_ptr;
	se_hba_t *hba = task->se_dev->se_hba;

	memset(prod, 0, 64);
	memset(se_location, 0, 128);

	sprintf(prod, "FILEIO");
	sprintf(se_location, "%u_%u", hba->hba_id, fdev->fd_dev_id);

	return transport_generic_emulate_inquiry(cmd, TYPE_DISK, prod,
		FD_VERSION, se_location);
}

/*	fd_emulate_read_cap():
 *
 *
 */
static int fd_emulate_read_cap(se_task_t *task)
{
	fd_dev_t *fd_dev = (fd_dev_t *) task->se_dev->dev_ptr;
	unsigned long long blocks_long = div_u64(fd_dev->fd_dev_size,
				DEV_ATTRIB(task->se_dev)->block_size);
	u32 blocks;

	if (blocks_long >= 0x00000000ffffffff)
		blocks = 0xffffffff;
	else
		blocks = (u32)blocks_long;

	return transport_generic_emulate_readcapacity(TASK_CMD(task), blocks);
}

static int fd_emulate_read_cap16(se_task_t *task)
{
	fd_dev_t *fd_dev = (fd_dev_t *) task->se_dev->dev_ptr;
	unsigned long long blocks_long = div_u64(fd_dev->fd_dev_size,
				  DEV_ATTRIB(task->se_dev)->block_size);

	return transport_generic_emulate_readcapacity_16(TASK_CMD(task),
		blocks_long);
}

/*	fd_emulate_scsi_cdb():
 *
 *
 */
static int fd_emulate_scsi_cdb(se_task_t *task)
{
	int ret;
	se_cmd_t *cmd = TASK_CMD(task);
	fd_request_t *fd_req = (fd_request_t *) task->transport_req;

	switch (fd_req->fd_scsi_cdb[0]) {
	case INQUIRY:
		if (fd_emulate_inquiry(task) < 0)
			return PYX_TRANSPORT_INVALID_CDB_FIELD;
		break;
	case READ_CAPACITY:
		ret = fd_emulate_read_cap(task);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				fd_req->fd_scsi_cdb, fd_req->fd_buf, 0,
				TYPE_DISK);
		if (ret < 0)
			return ret;
		break;
	case MODE_SENSE_10:
		ret = transport_generic_emulate_modesense(TASK_CMD(task),
				fd_req->fd_scsi_cdb, fd_req->fd_buf, 1,
				TYPE_DISK);
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
		ret = fd_emulate_read_cap16(task);
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
		printk(KERN_ERR "Unsupported SCSI Opcode: 0x%02x for FILEIO\n",
				fd_req->fd_scsi_cdb[0]);
		return PYX_TRANSPORT_UNKNOWN_SAM_OPCODE;
	}

	task->task_scsi_status = GOOD;
	transport_complete_task(task, 1);

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

static inline int fd_iovec_alloc(fd_request_t *req)
{
	req->fd_iovs = kzalloc(sizeof(struct iovec) * req->fd_sg_count,
				GFP_KERNEL);
	if (!(req->fd_iovs)) {
		printk(KERN_ERR "Unable to allocate req->fd_iovs\n");
		return -1;
	}

	return 0;
}

static inline int fd_seek(
	struct file *fd,
	unsigned long long lba,
	u32 block_size)
{
	mm_segment_t old_fs;
	unsigned long long offset;

	old_fs = get_fs();
	set_fs(get_ds());
	if (fd->f_op->llseek)
		offset = fd->f_op->llseek(fd, lba * block_size, 0);
	else
		offset = default_llseek(fd, lba * block_size, 0);
	set_fs(old_fs);
#if 0
	printk(KERN_INFO "lba: %llu : block_size: %d\n", lba, block_size);
	printk(KERN_INFO "offset from llseek: %llu\n", offset);
	printk(KERN_INFO "(lba * block_size): %llu\n", (lba * block_size));
#endif
	if (offset != (lba * block_size)) {
		printk(KERN_ERR "offset: %llu not equal to LBA: %llu\n",
			offset, (lba * block_size));
		return -1;
	}

	return 0;
}

static int fd_do_readv(fd_request_t *req, se_task_t *task)
{
	int ret = 0;
	u32 i;
	mm_segment_t old_fs;
	struct file *fd = req->fd_dev->fd_file;
	struct scatterlist *sg = task->task_sg;
	struct iovec iov[req->fd_sg_count];

	memset(iov, 0, sizeof(struct iovec) * req->fd_sg_count);

	if (fd_seek(fd, req->fd_lba, DEV_ATTRIB(task->se_dev)->block_size) < 0)
		return -1;

	for (i = 0; i < req->fd_sg_count; i++) {
		iov[i].iov_len = sg[i].length;
		iov[i].iov_base = GET_ADDR_SG(&sg[i]);
	}

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_readv(fd, &iov[0], req->fd_sg_count, &fd->f_pos);
	set_fs(old_fs);
	/*
	 * Return zeros and GOOD status even if the READ did not return
	 * the expected virt_size for struct file w/o a backing struct
	 * block_device.
	 */
	if (S_ISBLK(fd->f_dentry->d_inode->i_mode)) {
		if (ret < 0 || ret != req->fd_size) {
			printk(KERN_ERR "vfs_readv() returned %d,"
				" expecting %d for S_ISBLK\n", ret,
				(int)req->fd_size);
			return -1;
		}
	} else {
		if (ret < 0) {
			printk(KERN_ERR "vfs_readv() returned %d for non"
				" S_ISBLK\n", ret);
			return -1;
		}
	}

	return 1;
}

#if 0

void fd_sendfile_free_DMA(se_cmd_t *cmd)
{
	printk(KERN_INFO "Release reference to pages now..\n");
}

static int fd_sendactor(
	read_descriptor_t *desc,
	struct page *page,
	unsigned long offset,
	unsigned long size)
{
	unsigned long count = desc->count;
	se_task_t *task = desc->arg.data;
	fd_request_t *req = (fd_request_t *) task->transport_req;
	struct scatterlist *sg = task->task_sg;

	printk(KERN_INFO "page: %p offset: %lu size: %lu\n", page,
			offset, size);

	__free_page(sg[req->fd_cur_offset].page);

	printk(KERN_INFO "page_address(page): %p\n", page_address(page));
	sg[req->fd_cur_offset].page = page;
	sg[req->fd_cur_offset].offset = offset;
	sg[req->fd_cur_offset].length = size;

	printk(KERN_INFO "sg[%d:%p].page %p length: %d\n", req->fd_cur_offset,
		&sg[req->fd_cur_offset], sg[req->fd_cur_offset].page,
		sg[req->fd_cur_offset].length);

	req->fd_cur_size += size;
	printk(KERN_INFO "fd_cur_size: %u\n", req->fd_cur_size);

	req->fd_cur_offset++;

	desc->count--;
	desc->written += size;
	return size;
}

static int fd_do_sendfile(fd_request_t *req, se_task_t *task)
{
	int ret = 0;
	struct file *fd = req->fd_dev->fd_file;

	if (fd_seek(fd, req->fd_lba, DEV_ATTRIB(task->se_dev)->block_size) < 0)
		return -1;

	TASK_CMD(task)->transport_free_DMA = &fd_sendfile_free_DMA;

	ret = fd->f_op->sendfile(fd, &fd->f_pos, req->fd_sg_count,
			fd_sendactor, (void *)task);

	if (ret < 0) {
		printk(KERN_ERR "fd->f_op->sendfile() returned %d\n", ret);
		return -1;
	}

	return 1;
}
#endif

static int fd_do_writev(fd_request_t *req, se_task_t *task)
{
	int ret = 0;
	u32 i;
	struct file *fd = req->fd_dev->fd_file;
	struct scatterlist *sg = task->task_sg;
	mm_segment_t old_fs;
	struct iovec iov[req->fd_sg_count];

	memset(iov, 0, sizeof(struct iovec) * req->fd_sg_count);

	if (fd_seek(fd, req->fd_lba, DEV_ATTRIB(task->se_dev)->block_size) < 0)
		return -1;

	for (i = 0; i < req->fd_sg_count; i++) {
		iov[i].iov_len = sg[i].length;
		iov[i].iov_base = GET_ADDR_SG(&sg[i]);
	}

	old_fs = get_fs();
	set_fs(get_ds());
	ret = vfs_writev(fd, &iov[0], req->fd_sg_count, &fd->f_pos);
	set_fs(old_fs);

	if (ret < 0 || ret != req->fd_size) {
		printk(KERN_ERR "vfs_writev() returned %d\n", ret);
		return -1;
	}

	return 1;
}

int fd_do_task(se_task_t *task)
{
	int ret = 0;
	fd_request_t *req = (fd_request_t *) task->transport_req;

	if (!(TASK_CMD(task)->se_cmd_flags & SCF_SCSI_DATA_SG_IO_CDB))
		return fd_emulate_scsi_cdb(task);

	req->fd_lba = task->task_lba;
	req->fd_size = task->task_size;
	/*
	 * Call vectorized fileio functions to map struct scatterlist
	 * physical memory addresses to struct iovec virtual memory.
	 */
	if (req->fd_data_direction == FD_DATA_READ)
		ret = fd_do_readv(req, task);
	else
		ret = fd_do_writev(req, task);

	if (ret < 0)
		return ret;

	if (ret) {
		task->task_scsi_status = GOOD;
		transport_complete_task(task, 1);
	}

	return PYX_TRANSPORT_SENT_TO_TRANSPORT;
}

/*	fd_free_task(): (Part of se_subsystem_api_t template)
 *
 *
 */
void fd_free_task(se_task_t *task)
{
	fd_request_t *req;

	req = (fd_request_t *) task->transport_req;
	kfree(req->fd_iovs);

	kfree(req);
}

ssize_t fd_set_configfs_dev_params(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	const char *page, ssize_t count)
{
	fd_dev_t *fd_dev = (fd_dev_t *) se_dev->se_dev_su_ptr;
	char *buf, *cur, *ptr, *ptr2;
	int params = 0;
	/*
	 * Make sure we take into account the NULL terminator when copying
	 * the const buffer here..
	 */
	buf = kzalloc(count + 1, GFP_KERNEL);
	if (!(buf)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" temporary buffer\n");
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

		ptr2 = strstr(cur, "fd_dev_name");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ptr = strstrip(ptr);
			snprintf(fd_dev->fd_dev_name, FD_MAX_DEV_NAME,
					"%s", ptr);
			printk(KERN_INFO "FILEIO: Referencing Path: %s\n",
					fd_dev->fd_dev_name);
			fd_dev->fbd_flags |= FBDF_HAS_PATH;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "fd_dev_size");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			if (tcm_strict_strtoull(ptr, 0, &fd_dev->fd_dev_size) < 0) {
				printk(KERN_ERR "tcm_strict_strtoull() failed for"
						" fd_dev_size=\n");
				continue;
			}
			printk(KERN_INFO "FILEIO: Referencing Size: %llu"
					" bytes\n", fd_dev->fd_dev_size);
			fd_dev->fbd_flags |= FBDF_HAS_SIZE;
			params++;
			continue;
		}
		ptr2 = strstr(cur, "fd_buffered_io");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			if (strncmp(ptr, "1", 1))
				continue;

			printk(KERN_INFO "FILEIO: Using buffered I/O"
				" operations for fd_dev_t\n");

			fd_dev->fbd_flags |= FDBD_USE_BUFFERED_IO;
			params++;
			continue;
		} else
			cur = NULL;
	}

out:
	kfree(buf);
	return (params) ? count : -EINVAL;
}

ssize_t fd_check_configfs_dev_params(se_hba_t *hba, se_subsystem_dev_t *se_dev)
{
	fd_dev_t *fd_dev = (fd_dev_t *) se_dev->se_dev_su_ptr;

	if (!(fd_dev->fbd_flags & FBDF_HAS_PATH)) {
		printk(KERN_ERR "Missing fd_dev_name=\n");
		return -1;
	}

	return 0;
}

ssize_t fd_show_configfs_dev_params(
	se_hba_t *hba,
	se_subsystem_dev_t *se_dev,
	char *page)
{
	fd_dev_t *fd_dev = (fd_dev_t *) se_dev->se_dev_su_ptr;
	int bl = 0;

	__fd_get_dev_info(fd_dev, page, &bl);
	return (ssize_t)bl;
}

void fd_get_plugin_info(void *p, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "%s FILEIO Plugin %s\n",
			PYX_ISCSI_VENDOR, FD_VERSION);
}

void fd_get_hba_info(se_hba_t *hba, char *b, int *bl)
{
	fd_host_t *fd_host = (fd_host_t *)hba->hba_ptr;

	*bl += sprintf(b + *bl, "SE Host ID: %u  FD Host ID: %u\n",
		 hba->hba_id, fd_host->fd_host_id);
	*bl += sprintf(b + *bl, "        LIO FILEIO HBA\n");
}

void fd_get_dev_info(se_device_t *dev, char *b, int *bl)
{
	fd_dev_t *fd_dev = (fd_dev_t *) dev->dev_ptr;

	__fd_get_dev_info(fd_dev, b, bl);
}

void __fd_get_dev_info(fd_dev_t *fd_dev, char *b, int *bl)
{
	*bl += sprintf(b + *bl, "LIO FILEIO ID: %u", fd_dev->fd_dev_id);
	*bl += sprintf(b + *bl, "        File: %s  Size: %llu  Mode: %s  ",
			fd_dev->fd_dev_name, fd_dev->fd_dev_size,
			(fd_dev->fbd_flags & FDBD_USE_BUFFERED_IO) ?
			"Buffered" : "Synchronous");

	if (fd_dev->fd_bd) {
		struct block_device *bd = fd_dev->fd_bd;

		*bl += sprintf(b + *bl, "%s\n",
				(!bd->bd_contains) ? "" :
				(bd->bd_holder == (fd_dev_t *)fd_dev) ?
					"CLAIMED: FILEIO" : "CLAIMED: OS");
	} else
		*bl += sprintf(b + *bl, "\n");
}

/*	fd_map_task_non_SG():
 *
 *
 */
void fd_map_task_non_SG(se_task_t *task)
{
	se_cmd_t *cmd = TASK_CMD(task);
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_bufflen		= task->task_size;
	req->fd_buf		= (void *) T_TASK(cmd)->t_task_buf;
	req->fd_sg_count	= 0;
}

/*	fd_map_task_SG():
 *
 *
 */
void fd_map_task_SG(se_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_bufflen		= task->task_size;
	req->fd_buf		= NULL;
	req->fd_sg_count	= task->task_sg_num;
}

/*      fd_CDB_inquiry():
 *
 *
 */
int fd_CDB_inquiry(se_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction  = FD_DATA_READ;
	fd_map_task_non_SG(task);

	return 0;
}

/*      fd_CDB_none():
 *
 *
 */
int fd_CDB_none(se_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction	= FD_DATA_NONE;
	req->fd_bufflen		= 0;
	req->fd_sg_count	= 0;
	req->fd_buf		= NULL;

	return 0;
}

/*	fd_CDB_read_non_SG():
 *
 *
 */
int fd_CDB_read_non_SG(se_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction = FD_DATA_READ;
	fd_map_task_non_SG(task);

	return 0;
}

/*	fd_CDB_read_SG):
 *
 *
 */
int fd_CDB_read_SG(se_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction = FD_DATA_READ;
	fd_map_task_SG(task);

	return req->fd_sg_count;
}

/*	fd_CDB_write_non_SG():
 *
 *
 */
int fd_CDB_write_non_SG(se_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction = FD_DATA_WRITE;
	fd_map_task_non_SG(task);

	return 0;
}

/*	fd_CDB_write_SG():
 *
 *
 */
int fd_CDB_write_SG(se_task_t *task, u32 size)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	req->fd_data_direction = FD_DATA_WRITE;
	fd_map_task_SG(task);

	return req->fd_sg_count;
}

/*	fd_check_lba():
 *
 *
 */
int fd_check_lba(unsigned long long lba, se_device_t *dev)
{
	return 0;
}

/*	fd_check_for_SG(): (Part of se_subsystem_api_t template)
 *
 *
 */
int fd_check_for_SG(se_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	return req->fd_sg_count;
}

/*	fd_get_cdb(): (Part of se_subsystem_api_t template)
 *
 *
 */
unsigned char *fd_get_cdb(se_task_t *task)
{
	fd_request_t *req = (fd_request_t *) task->transport_req;

	return req->fd_scsi_cdb;
}

/*	fd_get_blocksize(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 fd_get_blocksize(se_device_t *dev)
{
	return FD_BLOCKSIZE;
}

/*	fd_get_device_rev(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 fd_get_device_rev(se_device_t *dev)
{
	return SCSI_SPC_2; /* Returns SPC-3 in Initiator Data */
}

/*	fd_get_device_type(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 fd_get_device_type(se_device_t *dev)
{
	return TYPE_DISK;
}

/*	fd_get_dma_length(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 fd_get_dma_length(u32 task_size, se_device_t *dev)
{
	return PAGE_SIZE;
}

/*	fd_get_max_sectors(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 fd_get_max_sectors(se_device_t *dev)
{
	return FD_MAX_SECTORS;
}

/*	fd_get_queue_depth(): (Part of se_subsystem_api_t template)
 *
 *
 */
u32 fd_get_queue_depth(se_device_t *dev)
{
	return FD_DEVICE_QUEUE_DEPTH;
}

u32 fd_get_max_queue_depth(se_device_t *dev)
{
	return FD_MAX_DEVICE_QUEUE_DEPTH;
}
