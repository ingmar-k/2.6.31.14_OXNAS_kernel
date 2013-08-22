/*******************************************************************************
 * Filename:  target_core_configfs.c
 *
 * This file contains ConfigFS logic for the Generic Target Engine project.
 *
 * Copyright (c) 2008-2009 Rising Tide, Inc.
 * Copyright (c) 2008-2009 Linux-iSCSI.org
 *
 * Nicholas A. Bellinger <nab@kernel.org>
 *
 * based on configfs Copyright (C) 2005 Oracle.  All rights reserved.
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
 ****************************************************************************/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
#include <generated/utsrelease.h>
#else
#include <linux/utsrelease.h>
#endif
#include <linux/utsname.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/configfs.h>
#include <linux/proc_fs.h>

#include <../lio-core/iscsi_linux_defs.h>

#include <target/target_core_base.h>
#include <target/target_core_device.h>
#include <target/target_core_hba.h>
#include <target/target_core_plugin.h>
#include <target/target_core_seobj.h>
#include <target/target_core_transport.h>
#include <target/target_core_alua.h>
#include <target/target_core_pr.h>
#include <target/target_core_fabric_ops.h>
#include <target/target_core_configfs.h>
#include <target/configfs_macros.h>

struct list_head g_tf_list;
struct mutex g_tf_lock;

struct target_core_configfs_attribute {
	struct configfs_attribute attr;
	ssize_t (*show)(void *, char *);
	ssize_t (*store)(void *, const char *, size_t);
};

static inline se_hba_t *item_to_hba(struct config_item *item)
{
	return container_of(to_config_group(item), struct se_hba_s, hba_group);
}

se_hba_t *target_core_get_hba_from_item(
	struct config_item *item)
{
	se_hba_t *hba = container_of(to_config_group(item),
				se_hba_t, hba_group);	
	if (!(hba))
		return NULL;

	if (core_get_hba(hba) < 0)	
		return NULL;

	return hba;
}

static inline struct config_item * to_item(struct list_head * entry)
{
        return container_of(entry,struct config_item,ci_entry);
}

struct config_item *config_group_find_item(struct config_group *group,
                                           const char *name)
{
        struct list_head * entry;
        struct config_item * ret = NULL;

        list_for_each(entry,&group->cg_children) {
                struct config_item * item = to_item(entry);
                if (config_item_name(item) &&
                    !strcmp(config_item_name(item), name)) {
                        ret = config_item_get(item);
                        break;
                }
        }
        return ret;
}

/*
 * Attributes for /sys/kernel/config/target/
 */
static ssize_t target_core_attr_show(struct config_item *item,
				      struct configfs_attribute *attr,
				      char *page)
{
	return sprintf(page, "Target Engine Core ConfigFS Infrastructure %s"
		" on %s/%s on "UTS_RELEASE"\n", TARGET_CORE_CONFIGFS_VERSION,
		TCM_UTS_SYSNAME, TCM_UTS_MACHINE);
}

static struct configfs_item_operations target_core_fabric_item_ops = {
	.show_attribute = target_core_attr_show,
};

static struct configfs_attribute target_core_item_attr_version = {
	.ca_owner	= THIS_MODULE,
	.ca_name	= "version",
	.ca_mode	= S_IRUGO,
};

static struct target_fabric_configfs *target_core_get_fabric(
	const char *name)
{
	struct target_fabric_configfs *tf;

	if (!(name))
		return NULL;

	mutex_lock(&g_tf_lock);
	list_for_each_entry(tf, &g_tf_list, tf_list) {
		if (!(strcmp(tf->tf_name, name))) {
			atomic_inc(&tf->tf_access_cnt);
			mutex_unlock(&g_tf_lock);
			return tf;
		}
	}
	mutex_unlock(&g_tf_lock);

	return NULL;
}

/*
 * Called from struct target_core_group_ops->make_group()
 */
static struct config_group *target_core_register_fabric(
	struct config_group *group,
	const char *name)
{
	struct config_group *fabric_cg;
	struct target_fabric_configfs *tf;
	int ret;

	printk(KERN_INFO "Target_Core_ConfigFS: REGISTER -> group: %p name:"
			" %s\n", group, name);

	fabric_cg = kzalloc(sizeof(struct config_group), GFP_KERNEL);
	if (!(fabric_cg))
		return ERR_PTR(-ENOMEM);

        /*
	 * Below are some hardcoded request_module() calls to automatically
	 * local fabric modules when the following is called:
	 *
	 * mkdir -p /sys/kernel/config/target/$MODULE_NAME
	 *
	 * Note that this does not limit which TCM fabric module can be
	 * registered, but simply provids auto loading logic for modules with
	 * mkdir(2) system calls with known TCM fabric modules.
	 */
	if (!(strncmp(name, "iscsi", 5))) {
		/*
		 * Automatically load the LIO Target fabric module when the
		 * following is called:
		 *
		 * mkdir -p $CONFIGFS/target/iscsi
		*/
		ret = request_module("iscsi_target_mod");
		if (ret < 0) {
			printk(KERN_ERR "request_module() failed for"
				" iscsi_target_mod.ko: %d\n", ret);
			kfree(fabric_cg);
			return ERR_PTR(-EINVAL);
		}
	} else if (!(strncmp(name, "loopback", 8))) {
		/*
		 * Automatically load the tcm_loop fabric module when the
		 * following is called:
		 *
		 * mkdir -p $CONFIGFS/target/loopback
		 */
		ret = request_module("tcm_loop");
		if (ret < 0) {
			printk(KERN_ERR "request_module() failed for"
				" tcm_loop.ko: %d\n", ret);
			kfree(fabric_cg);
			return ERR_PTR(-EINVAL);
		}
	}

	tf = target_core_get_fabric(name);
	if (!(tf)) {
		printk(KERN_ERR "target_core_get_fabric() failed for %s\n",
			name);
		kfree(fabric_cg);
		return ERR_PTR(-EINVAL);
	}
	printk(KERN_INFO "Target_Core_ConfigFS: REGISTER -> Located fabric:"
			" %s\n", tf->tf_name);
	/*
	 * On a successful target_core_get_fabric() look, the returned
	 * struct target_fabric_configfs *tf will contain a usage reference.
	 */
	printk(KERN_INFO "Target_Core_ConfigFS: REGISTER -> %p\n",
			tf->tf_fabric_cit);
	config_group_init_type_name(&tf->tf_group, name, tf->tf_fabric_cit);
	/*
	 * Setup any default configfs groups in the top level directory of
	 * this fabric module.
	 */
	if (tf->reg_default_groups_callback != NULL)
		tf->reg_default_groups_callback(tf);

	printk(KERN_INFO "Target_Core_ConfigFS: REGISTER -> Allocated Fabric:"
			" %s\n", tf->tf_group.cg_item.ci_name);
	/*
	 * Setup tf_ops.tf_subsys pointer for usage with configfs_depend_item()
	 */
	tf->tf_ops.tf_subsys = tf->tf_subsys;
	tf->tf_fabric = &tf->tf_group.cg_item;
	printk(KERN_INFO "Target_Core_ConfigFS: REGISTER -> Set tf->tf_fabric"
			" for %s\n", name);

	return &tf->tf_group;
}

/*
 * Called from struct target_core_group_ops->drop_item()
 */
static void target_core_deregister_fabric(
	struct config_group *group,
	struct config_item *item)
{
	struct target_fabric_configfs *tf = container_of(
		to_config_group(item), struct target_fabric_configfs, tf_group);

	printk(KERN_INFO "Target_Core_ConfigFS: DEREGISTER -> Looking up %s in"
		" tf list\n", config_item_name(item));

	printk(KERN_INFO "Target_Core_ConfigFS: DEREGISTER -> located fabric:"
			" %s\n", tf->tf_name);
	atomic_dec(&tf->tf_access_cnt);

	printk(KERN_INFO "Target_Core_ConfigFS: DEREGISTER -> Releasing"
			" tf->tf_fabric for %s\n", tf->tf_name);
	tf->tf_fabric = NULL;

	printk(KERN_INFO "Target_Core_ConfigFS: DEREGISTER -> Releasing ci"
			" %s\n", config_item_name(item));
	config_item_put(item);
}

static struct configfs_group_operations target_core_fabric_group_ops = {
	.make_group	= &target_core_register_fabric,
	.drop_item	= &target_core_deregister_fabric,
};

/*
 * All item attributes appearing in /sys/kernel/target/ appear here.
 */
static struct configfs_attribute *target_core_fabric_item_attrs[] = {
	&target_core_item_attr_version,
	NULL,
};

/*
 * Provides Fabrics Groups and Item Attributes for /sys/kernel/config/target/
 */
static struct config_item_type target_core_fabrics_item = {
	.ct_item_ops	= &target_core_fabric_item_ops,
	.ct_group_ops	= &target_core_fabric_group_ops,
	.ct_attrs	= target_core_fabric_item_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem target_core_fabrics = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "target",
			.ci_type = &target_core_fabrics_item,
		},
	},
};

static struct configfs_subsystem *target_core_subsystem[] = {
	&target_core_fabrics,
	NULL,
};

/*##############################################################################
// Start functions called by external Target Fabrics Modules
//############################################################################*/

/*
 * First function called by fabric modules to:
 *
 * 1) Allocate a struct target_fabric_configfs and save the *fabric_cit pointer.
 * 2) Add struct target_fabric_configfs to g_tf_list
 * 3) Return struct target_fabric_configfs to fabric module to be passed
 *    into target_fabric_configfs_register().
 */
struct target_fabric_configfs *target_fabric_configfs_init(
	struct config_item_type *fabric_cit,
	const char *name)
{
	struct target_fabric_configfs *tf;

	if (!(fabric_cit)) {
		printk(KERN_ERR "Missing struct config_item_type * pointer\n");
		return NULL;
	}
	if (!(name)) {
		printk(KERN_ERR "Unable to locate passed fabric name\n");
		return NULL;
	}
	if (strlen(name) > TARGET_FABRIC_NAME_SIZE) {
		printk(KERN_ERR "Passed name: %s exceeds TARGET_FABRIC"
			"_NAME_SIZE\n", name);
		return NULL;
	}

	tf = kzalloc(sizeof(struct target_fabric_configfs), GFP_KERNEL);
	if (!(tf))
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&tf->tf_list);
	atomic_set(&tf->tf_access_cnt, 0);
	tf->tf_fabric_cit = fabric_cit;
	tf->tf_subsys = target_core_subsystem[0];
	snprintf(tf->tf_name, TARGET_FABRIC_NAME_SIZE, "%s", name);

	mutex_lock(&g_tf_lock);
	list_add_tail(&tf->tf_list, &g_tf_list);
	mutex_unlock(&g_tf_lock);

	printk(KERN_INFO "<<<<<<<<<<<<<<<<<<<<<< BEGIN FABRIC API >>>>>>>>"
			">>>>>>>>>>>>>>\n");
	printk(KERN_INFO "Initialized struct target_fabric_configfs: %p for"
			" %s\n", tf, tf->tf_name);
	return tf;
}
EXPORT_SYMBOL(target_fabric_configfs_init);

/*
 * Called by fabric plugins after FAILED target_fabric_configfs_register() call.
 */
void target_fabric_configfs_free(
	struct target_fabric_configfs *tf)
{
	mutex_lock(&g_tf_lock);
	list_del(&tf->tf_list);
	mutex_unlock(&g_tf_lock);

	printk("Releasing fabric: %p\n", tf->tf_group.default_groups);
	kfree(tf->tf_group.default_groups);
	kfree(tf);
}
EXPORT_SYMBOL(target_fabric_configfs_free);

/*
 * Note that config_group_find_item() calls config_item_get() and grabs the
 * reference to the returned struct config_item *
 * It will be released with config_put_item() in
 * target_fabric_configfs_deregister()
 */
struct config_item *target_fabric_configfs_find_by_name(
	struct configfs_subsystem *target_su,
	const char *name)
{
	struct config_item *fabric;

//	mutex_lock(&target_su->su_mutex);
	fabric = config_group_find_item(&target_su->su_group, name);
//	mutex_unlock(&target_su->su_mutex);

	return fabric;
}

/*
 * Called 2nd from fabric module with returned parameter of
 * struct target_fabric_configfs * from target_fabric_configfs_init().
 *
 * Upon a successful registration, the new fabric's struct config_item is
 * return.  Also, a pointer to this struct is set in the passed
 * struct target_fabric_configfs.
 */
int target_fabric_configfs_register(
	struct target_fabric_configfs *tf)
{
	struct config_group *su_group;

	if (!(tf)) {
		printk(KERN_ERR "Unable to locate target_fabric_configfs"
			" pointer\n");
		return -EINVAL;
	}
	if (!(tf->tf_subsys)) {
		printk(KERN_ERR "Unable to target struct config_subsystem"
			" pointer\n");
		return -EINVAL;
	}
	su_group = &tf->tf_subsys->su_group;
	if (!(su_group)) {
		printk(KERN_ERR "Unable to locate target struct config_group"
			" pointer\n");
		return -EINVAL;
	}
	printk(KERN_INFO "<<<<<<<<<<<<<<<<<<<<<< END FABRIC API >>>>>>>>>>>>"
		">>>>>>>>>>\n");
	return 0;
}
EXPORT_SYMBOL(target_fabric_configfs_register);

void target_fabric_configfs_deregister(
	struct target_fabric_configfs *tf)
{
	struct config_group *su_group;
	struct configfs_subsystem *su;

	if (!(tf)) {
		printk(KERN_ERR "Unable to locate passed target_fabric_"
			"configfs\n");
		return;
	}
	su = tf->tf_subsys;
	if (!(su)) {
		printk(KERN_ERR "Unable to locate passed tf->tf_subsys"
			" pointer\n");
		return;
	}
	su_group = &tf->tf_subsys->su_group;
	if (!(su_group)) {
		printk(KERN_ERR "Unable to locate target struct config_group"
			" pointer\n");
		return;
	}

	printk(KERN_INFO "<<<<<<<<<<<<<<<<<<<<<< BEGIN FABRIC API >>>>>>>>>>"
			">>>>>>>>>>>>\n");
	mutex_lock(&g_tf_lock);
	if (atomic_read(&tf->tf_access_cnt)) {
		mutex_unlock(&g_tf_lock);
		printk(KERN_ERR "Non zero tf->tf_access_cnt for fabric %s\n",
			tf->tf_name);
		BUG();
	}
	list_del(&tf->tf_list);
	mutex_unlock(&g_tf_lock);

	printk(KERN_INFO "Target_Core_ConfigFS: DEREGISTER -> Releasing tf:"
			" %s\n", tf->tf_name);
	tf->tf_fabric_cit = NULL;
	tf->tf_subsys = NULL;
	printk("Releasing fabric: %p\n", tf->tf_group.default_groups);
	kfree(tf->tf_group.default_groups);
	kfree(tf);

	printk("<<<<<<<<<<<<<<<<<<<<<< END FABRIC API >>>>>>>>>>>>>>>>>"
			">>>>>\n");
	return;
}
EXPORT_SYMBOL(target_fabric_configfs_deregister);

/*##############################################################################
// Stop functions called by external Target Fabrics Modules
//############################################################################*/

/* Start functions for struct config_item_type target_core_dev_attrib_cit */

#define DEF_DEV_ATTRIB_SHOW(_name)					\
static ssize_t target_core_dev_show_attr_##_name(			\
	struct se_dev_attrib_s *da,					\
	char *page)							\
{									\
	se_device_t *dev;						\
	se_subsystem_dev_t *se_dev = da->da_sub_dev;			\
	ssize_t rb;							\
									\
	spin_lock(&se_dev->se_dev_lock);				\
	dev = se_dev->se_dev_ptr;					\
	if (!(dev)) {							\
		spin_unlock(&se_dev->se_dev_lock); 			\
		return -ENODEV;						\
	}								\
	rb = snprintf(page, PAGE_SIZE, "%u\n", (u32)DEV_ATTRIB(dev)->_name); \
	spin_unlock(&se_dev->se_dev_lock);				\
									\
	return rb;							\
}

#define DEF_DEV_ATTRIB_STORE(_name)					\
static ssize_t target_core_dev_store_attr_##_name(			\
	struct se_dev_attrib_s *da,					\
	const char *page,						\
	size_t count)							\
{									\
	se_device_t *dev;						\
	se_subsystem_dev_t *se_dev = da->da_sub_dev;			\
	unsigned long val;						\
	int ret;							\
									\
	spin_lock(&se_dev->se_dev_lock);				\
	dev = se_dev->se_dev_ptr;					\
	if (!(dev)) {							\
		spin_unlock(&se_dev->se_dev_lock);			\
		return -ENODEV;						\
	}								\
	ret = tcm_strict_strtoul(page, 0, &val);			\
	if (ret < 0) {							\
		spin_unlock(&se_dev->se_dev_lock);			\
		printk(KERN_ERR "tcm_strict_strtoul() failed with"	\
			" ret: %d\n", ret);				\
		return -EINVAL;						\
	}								\
	ret = se_dev_set_##_name(dev, (u32)val);			\
	spin_unlock(&se_dev->se_dev_lock);				\
									\
	return (!ret) ? count : -EINVAL;				\
}

#define DEF_DEV_ATTRIB(_name)						\
DEF_DEV_ATTRIB_SHOW(_name);						\
DEF_DEV_ATTRIB_STORE(_name);

#define DEF_DEV_ATTRIB_RO(_name)					\
DEF_DEV_ATTRIB_SHOW(_name);

CONFIGFS_EATTR_STRUCT(target_core_dev_attrib, se_dev_attrib_s);
#define SE_DEV_ATTR(_name, _mode)					\
static struct target_core_dev_attrib_attribute				\
			target_core_dev_attrib_##_name =		\
		__CONFIGFS_EATTR(_name, _mode,				\
		target_core_dev_show_attr_##_name,			\
		target_core_dev_store_attr_##_name);

#define SE_DEV_ATTR_RO(_name);						\
static struct target_core_dev_attrib_attribute				\
			target_core_dev_attrib_##_name =		\
		__CONFIGFS_EATTR_RO(_name,				\
		target_core_dev_show_attr_##_name);

DEF_DEV_ATTRIB(emulate_ua_intlck_ctrl);
SE_DEV_ATTR(emulate_ua_intlck_ctrl, S_IRUGO | S_IWUSR);

DEF_DEV_ATTRIB(emulate_tas);
SE_DEV_ATTR(emulate_tas, S_IRUGO | S_IWUSR);

DEF_DEV_ATTRIB(enforce_pr_isids);
SE_DEV_ATTR(enforce_pr_isids, S_IRUGO | S_IWUSR);

DEF_DEV_ATTRIB_RO(hw_block_size);
SE_DEV_ATTR_RO(hw_block_size);

DEF_DEV_ATTRIB(block_size);
SE_DEV_ATTR(block_size, S_IRUGO | S_IWUSR);

DEF_DEV_ATTRIB_RO(hw_max_sectors);
SE_DEV_ATTR_RO(hw_max_sectors);

DEF_DEV_ATTRIB(max_sectors);
SE_DEV_ATTR(max_sectors, S_IRUGO | S_IWUSR);

DEF_DEV_ATTRIB_RO(hw_queue_depth);
SE_DEV_ATTR_RO(hw_queue_depth);

DEF_DEV_ATTRIB(queue_depth);
SE_DEV_ATTR(queue_depth, S_IRUGO | S_IWUSR);

DEF_DEV_ATTRIB(task_timeout);
SE_DEV_ATTR(task_timeout, S_IRUGO | S_IWUSR);

CONFIGFS_EATTR_OPS(target_core_dev_attrib, se_dev_attrib_s, da_group);

static struct configfs_attribute *target_core_dev_attrib_attrs[] = {
	&target_core_dev_attrib_emulate_ua_intlck_ctrl.attr,
	&target_core_dev_attrib_emulate_tas.attr,
	&target_core_dev_attrib_enforce_pr_isids.attr,
	&target_core_dev_attrib_hw_block_size.attr,
	&target_core_dev_attrib_block_size.attr,
	&target_core_dev_attrib_hw_max_sectors.attr,
	&target_core_dev_attrib_max_sectors.attr,
	&target_core_dev_attrib_hw_queue_depth.attr,
	&target_core_dev_attrib_queue_depth.attr,
	&target_core_dev_attrib_task_timeout.attr,
	NULL,
};

static struct configfs_item_operations target_core_dev_attrib_ops = {
	.show_attribute		= target_core_dev_attrib_attr_show,
	.store_attribute	= target_core_dev_attrib_attr_store,
};

static struct config_item_type target_core_dev_attrib_cit = {
	.ct_item_ops		= &target_core_dev_attrib_ops,
	.ct_attrs		= target_core_dev_attrib_attrs,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item_type target_core_dev_attrib_cit */

/*  Start functions for struct config_item_type target_core_dev_wwn_cit */

CONFIGFS_EATTR_STRUCT(target_core_dev_wwn, t10_wwn_s);
#define SE_DEV_WWN_ATTR(_name, _mode)					\
static struct target_core_dev_wwn_attribute target_core_dev_wwn_##_name = \
		__CONFIGFS_EATTR(_name, _mode,				\
		target_core_dev_wwn_show_attr_##_name,			\
		target_core_dev_wwn_store_attr_##_name);

#define SE_DEV_WWN_ATTR_RO(_name);					\
static struct target_core_dev_wwn_attribute target_core_dev_wwn_##_name = \
		__CONFIGFS_EATTR_RO(_name,				\
		target_core_dev_wwn_show_attr_##_name);

/*
 * VPD page 0x80 Unit serial
 */
static ssize_t target_core_dev_wwn_show_attr_vpd_unit_serial(
	struct t10_wwn_s *t10_wwn,
	char *page)
{
	se_subsystem_dev_t *se_dev = t10_wwn->t10_sub_dev;
	se_device_t *dev;

	dev = se_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	return sprintf(page, "T10 VPD Unit Serial Number: %s\n",
		&t10_wwn->unit_serial[0]);
}

static ssize_t target_core_dev_wwn_store_attr_vpd_unit_serial(
	struct t10_wwn_s *t10_wwn,
	const char *page,
	size_t count)
{
	se_subsystem_dev_t *su_dev = t10_wwn->t10_sub_dev;
	se_device_t *dev;
	unsigned char buf[INQUIRY_VPD_SERIAL_LEN];

	/*
	 * If Linux/SCSI subsystem_api_t plugin got a VPD Unit Serial
	 * from the struct scsi_device level firmware, do not allow
	 * VPD Unit Serial to be emulated.
	 *
	 * Note this struct scsi_device could also be emulating VPD
	 * information from its drivers/scsi LLD.  But for now we assume
	 * it is doing 'the right thing' wrt a world wide unique
	 * VPD Unit Serial Number that OS dependent multipath can depend on.
	 */
	if (su_dev->su_dev_flags & SDF_FIRMWARE_VPD_UNIT_SERIAL) {
		printk(KERN_ERR "Underlying SCSI device firmware provided VPD"
			" Unit Serial, ignoring request\n");
		return -EOPNOTSUPP;
	}

	if ((strlen(page) + 1) > INQUIRY_VPD_SERIAL_LEN) {
		printk(KERN_ERR "Emulated VPD Unit Serial exceeds"
		" INQUIRY_VPD_SERIAL_LEN: %d\n", INQUIRY_VPD_SERIAL_LEN);
		return -EOVERFLOW;
	}
	/*
	 * Check to see if any active $FABRIC_MOD exports exist.  If they
	 * do exist, fail here as changing this information on the fly
	 * (underneath the initiator side OS dependent multipath code)
	 * could cause negative effects.
	 */
	dev = su_dev->se_dev_ptr;
	if ((dev)) {
		if (DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj)) {
			printk(KERN_ERR "Unable to set VPD Unit Serial while"
				" active %d $FABRIC_MOD exports exist\n",
				DEV_OBJ_API(dev)->check_count(
					&dev->dev_export_obj));
			return -EINVAL;
		}
	}
	/*
	 * This currently assumes ASCII encoding for emulated VPD Unit Serial.
	 *
	 * Also, strip any newline added from the userspace
	 * echo $UUID > $TARGET/$HBA/$STORAGE_OBJECT/wwn/vpd_unit_serial
	 */
	memset(buf, 0, INQUIRY_VPD_SERIAL_LEN);
	snprintf(buf, INQUIRY_VPD_SERIAL_LEN, "%s", page);
	snprintf(su_dev->t10_wwn.unit_serial, INQUIRY_VPD_SERIAL_LEN,
			"%s", strstrip(buf));
	su_dev->su_dev_flags |= SDF_EMULATED_VPD_UNIT_SERIAL;

	printk(KERN_INFO "Target_Core_ConfigFS: Set emulated VPD Unit Serial:"
			" %s\n", su_dev->t10_wwn.unit_serial);
	if (dev)
		transport_rescan_evpd_device_ident(dev);	

	return count;
}

SE_DEV_WWN_ATTR(vpd_unit_serial, S_IRUGO | S_IWUSR);

/*
 * VPD page 0x83 Protocol Identifier
 */
static ssize_t target_core_dev_wwn_show_attr_vpd_protocol_identifier(
	struct t10_wwn_s *t10_wwn,
	char *page)
{
	se_subsystem_dev_t *se_dev = t10_wwn->t10_sub_dev;
	se_device_t *dev;
	t10_vpd_t *vpd;
	unsigned char buf[VPD_TMP_BUF_SIZE];
	ssize_t len = 0;

	dev = se_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	memset(buf, 0, VPD_TMP_BUF_SIZE);

	spin_lock(&t10_wwn->t10_vpd_lock);
	list_for_each_entry(vpd, &t10_wwn->t10_vpd_list, vpd_list) {
		if (!(vpd->protocol_identifier_set))
			continue;

		transport_dump_vpd_proto_id(vpd, buf, VPD_TMP_BUF_SIZE);

		if ((len + strlen(buf) > PAGE_SIZE))
			break;

		len += sprintf(page+len, "%s", buf);
	}
	spin_unlock(&t10_wwn->t10_vpd_lock);

	return len;
}

static ssize_t target_core_dev_wwn_store_attr_vpd_protocol_identifier(
	struct t10_wwn_s *t10_wwn,
	const char *page,
	size_t count)
{
	return -ENOSYS;
}

SE_DEV_WWN_ATTR(vpd_protocol_identifier, S_IRUGO | S_IWUSR);

/*
 * Generic wrapper for dumping VPD identifiers by association.
 */
#define DEF_DEV_WWN_ASSOC_SHOW(_name, _assoc)				\
static ssize_t target_core_dev_wwn_show_attr_##_name(			\
	struct t10_wwn_s *t10_wwn,					\
	char *page)							\
{									\
	se_subsystem_dev_t *se_dev = t10_wwn->t10_sub_dev;		\
	se_device_t *dev;						\
	t10_vpd_t *vpd;							\
	unsigned char buf[VPD_TMP_BUF_SIZE];				\
	ssize_t len = 0;						\
									\
	dev = se_dev->se_dev_ptr;					\
	if (!(dev))							\
		return -ENODEV;						\
									\
	spin_lock(&t10_wwn->t10_vpd_lock);				\
	list_for_each_entry(vpd, &t10_wwn->t10_vpd_list, vpd_list) {	\
		if (vpd->association != _assoc)				\
			continue;					\
									\
		memset(buf, 0, VPD_TMP_BUF_SIZE);			\
		transport_dump_vpd_assoc(vpd, buf, VPD_TMP_BUF_SIZE);	\
		if ((len + strlen(buf) > PAGE_SIZE))			\
			break;						\
		len += sprintf(page+len, "%s", buf);			\
									\
		memset(buf, 0, VPD_TMP_BUF_SIZE);			\
		transport_dump_vpd_ident_type(vpd, buf, VPD_TMP_BUF_SIZE); \
		if ((len + strlen(buf) > PAGE_SIZE))			\
			break;						\
		len += sprintf(page+len, "%s", buf);			\
									\
		memset(buf, 0, VPD_TMP_BUF_SIZE);			\
		transport_dump_vpd_ident(vpd, buf, VPD_TMP_BUF_SIZE); \
		if ((len + strlen(buf) > PAGE_SIZE))			\
			break;						\
		len += sprintf(page+len, "%s", buf);			\
	}								\
	spin_unlock(&t10_wwn->t10_vpd_lock);				\
									\
	return len;							\
}

/*
 * VPD page 0x83 Assoication: Logical Unit
 */
DEF_DEV_WWN_ASSOC_SHOW(vpd_assoc_logical_unit, 0x00);

static ssize_t target_core_dev_wwn_store_attr_vpd_assoc_logical_unit(
	struct t10_wwn_s *t10_wwn,
	const char *page,
	size_t count)
{
	return -ENOSYS;
}

SE_DEV_WWN_ATTR(vpd_assoc_logical_unit, S_IRUGO | S_IWUSR);

/*
 * VPD page 0x83 Association: Target Port
 */
DEF_DEV_WWN_ASSOC_SHOW(vpd_assoc_target_port, 0x10);

static ssize_t target_core_dev_wwn_store_attr_vpd_assoc_target_port(
	struct t10_wwn_s *t10_wwn,
	const char *page,
	size_t count)
{
	return -ENOSYS;
}

SE_DEV_WWN_ATTR(vpd_assoc_target_port, S_IRUGO | S_IWUSR);

/*
 * VPD page 0x83 Association: SCSI Target Device
 */
DEF_DEV_WWN_ASSOC_SHOW(vpd_assoc_scsi_target_device, 0x20);

static ssize_t target_core_dev_wwn_store_attr_vpd_assoc_scsi_target_device(
	struct t10_wwn_s *t10_wwn,
	const char *page,
	size_t count)
{
	return -ENOSYS;
}

SE_DEV_WWN_ATTR(vpd_assoc_scsi_target_device, S_IRUGO | S_IWUSR);

CONFIGFS_EATTR_OPS(target_core_dev_wwn, t10_wwn_s, t10_wwn_group);

static struct configfs_attribute *target_core_dev_wwn_attrs[] = {
	&target_core_dev_wwn_vpd_unit_serial.attr,
	&target_core_dev_wwn_vpd_protocol_identifier.attr,
	&target_core_dev_wwn_vpd_assoc_logical_unit.attr,
	&target_core_dev_wwn_vpd_assoc_target_port.attr,
	&target_core_dev_wwn_vpd_assoc_scsi_target_device.attr,
	NULL,
};

static struct configfs_item_operations target_core_dev_wwn_ops = {
	.show_attribute		= target_core_dev_wwn_attr_show,
	.store_attribute	= target_core_dev_wwn_attr_store,
};

static struct config_item_type target_core_dev_wwn_cit = {
	.ct_item_ops		= &target_core_dev_wwn_ops,
	.ct_attrs		= target_core_dev_wwn_attrs,
	.ct_owner		= THIS_MODULE,
};

/*  End functions for struct config_item_type target_core_dev_wwn_cit */

/*  Start functions for struct config_item_type target_core_dev_pr_cit */

CONFIGFS_EATTR_STRUCT(target_core_dev_pr, se_subsystem_dev_s);
#define SE_DEV_PR_ATTR(_name, _mode)					\
static struct target_core_dev_pr_attribute target_core_dev_pr_##_name = \
	__CONFIGFS_EATTR(_name, _mode,					\
	target_core_dev_pr_show_attr_##_name,				\
	target_core_dev_pr_store_attr_##_name);

#define SE_DEV_PR_ATTR_RO(_name);					\
static struct target_core_dev_pr_attribute target_core_dev_pr_##_name =	\
	__CONFIGFS_EATTR_RO(_name,					\
	target_core_dev_pr_show_attr_##_name);				\

/*
 * res_holder
 */
static ssize_t target_core_dev_pr_show_spc3_res(
	struct se_device_s *dev,
	char *page,
	ssize_t *len)
{
	se_node_acl_t *se_nacl;
	t10_pr_registration_t *pr_reg;
	char i_buf[PR_REG_ISID_ID_LEN];
	int prf_isid;

	memset(i_buf, 0, PR_REG_ISID_ID_LEN);

	spin_lock(&dev->dev_reservation_lock);
	pr_reg = dev->dev_pr_res_holder;
	if (!(pr_reg)) {
		*len += sprintf(page + *len, "No SPC-3 Reservation holder\n");
		spin_unlock(&dev->dev_reservation_lock);
		return *len;
	}
	se_nacl = pr_reg->pr_reg_nacl;
	prf_isid = core_pr_dump_initiator_port(pr_reg, &i_buf[0],
				PR_REG_ISID_ID_LEN);

	*len += sprintf(page + *len, "SPC-3 Reservation: %s Initiator: %s%s\n",
		TPG_TFO(se_nacl->se_tpg)->get_fabric_name(),
		se_nacl->initiatorname, (prf_isid) ? &i_buf[0] : "");
	spin_unlock(&dev->dev_reservation_lock);

	return *len;
}

static ssize_t target_core_dev_pr_show_spc2_res(
	struct se_device_s *dev,
	char *page,
	ssize_t *len)
{
	se_node_acl_t *se_nacl;

	spin_lock(&dev->dev_reservation_lock);
	se_nacl = dev->dev_reserved_node_acl;
	if (!(se_nacl)) {
		*len += sprintf(page + *len, "No SPC-2 Reservation holder\n");
		spin_unlock(&dev->dev_reservation_lock);
		return *len;
	}
	*len += sprintf(page + *len, "SPC-2 Reservation: %s Initiator: %s\n",
		TPG_TFO(se_nacl->se_tpg)->get_fabric_name(),
		se_nacl->initiatorname);
	spin_unlock(&dev->dev_reservation_lock);

	return *len;
}

static ssize_t target_core_dev_pr_show_attr_res_holder(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	ssize_t len = 0;

	if (!(su_dev->se_dev_ptr))
		return -ENODEV;

	switch (T10_RES(su_dev)->res_type) {
	case SPC3_PERSISTENT_RESERVATIONS:
		target_core_dev_pr_show_spc3_res(su_dev->se_dev_ptr,
				page, &len);
		break;
	case SPC2_RESERVATIONS:
		target_core_dev_pr_show_spc2_res(su_dev->se_dev_ptr,
				page, &len);
		break;
	case SPC_PASSTHROUGH:
		len += sprintf(page+len, "Passthrough\n");
		break;
	default:
		len += sprintf(page+len, "Unknown\n");
		break;
	}

	return len;
}

SE_DEV_PR_ATTR_RO(res_holder);

/*
 * res_pr_all_tgt_pts
 */
static ssize_t target_core_dev_pr_show_attr_res_pr_all_tgt_pts(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	se_device_t *dev;
	t10_pr_registration_t *pr_reg;
	ssize_t len = 0;

	dev = su_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return len;

	spin_lock(&dev->dev_reservation_lock);
	pr_reg = dev->dev_pr_res_holder;
	if (!(pr_reg)) {
		len = sprintf(page, "No SPC-3 Reservation holder\n");
		spin_unlock(&dev->dev_reservation_lock);
		return len;
	}
	/*
	 * See All Target Ports (ALL_TG_PT) bit in spcr17, section 6.14.3
	 * Basic PERSISTENT RESERVER OUT parameter list, page 290
	 */
	if (pr_reg->pr_reg_all_tg_pt)
		len = sprintf(page, "SPC-3 Reservation: All Target"
			" Ports registration\n");
	else
		len = sprintf(page, "SPC-3 Reservation: Single"
			" Target Port registration\n");
	spin_unlock(&dev->dev_reservation_lock);

	return len;
}

SE_DEV_PR_ATTR_RO(res_pr_all_tgt_pts);

/*
 * res_pr_generation
 */
static ssize_t target_core_dev_pr_show_attr_res_pr_generation(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	if (!(su_dev->se_dev_ptr))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return 0;

	return sprintf(page, "0x%08x\n", T10_RES(su_dev)->pr_generation);
}

SE_DEV_PR_ATTR_RO(res_pr_generation);

/*
 * res_pr_holder_tg_port
 */
static ssize_t target_core_dev_pr_show_attr_res_pr_holder_tg_port(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	se_device_t *dev;
	se_node_acl_t *se_nacl;
	se_lun_t *lun;
	se_portal_group_t *se_tpg;
	t10_pr_registration_t *pr_reg;
	struct target_core_fabric_ops *tfo;
	ssize_t len = 0;

	dev = su_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return len;

	spin_lock(&dev->dev_reservation_lock);
	pr_reg = dev->dev_pr_res_holder;
	if (!(pr_reg)) {
		len = sprintf(page, "No SPC-3 Reservation holder\n");
		spin_unlock(&dev->dev_reservation_lock);
		return len;
	}
	se_nacl = pr_reg->pr_reg_nacl;
	se_tpg = se_nacl->se_tpg;
	lun = pr_reg->pr_reg_tg_pt_lun;
	tfo = TPG_TFO(se_tpg);

	len += sprintf(page+len, "SPC-3 Reservation: %s"
		" Target Node Endpoint: %s\n", tfo->get_fabric_name(),
		tfo->tpg_get_wwn(se_tpg));
	len += sprintf(page+len, "SPC-3 Reservation: Relative Port"
		" Identifer Tag: %hu %s Portal Group Tag: %hu"
		" %s Logical Unit: %u\n", lun->lun_sep->sep_rtpi,
		tfo->get_fabric_name(), tfo->tpg_get_tag(se_tpg),
		tfo->get_fabric_name(), lun->unpacked_lun);
	spin_unlock(&dev->dev_reservation_lock);

	return len;
}

SE_DEV_PR_ATTR_RO(res_pr_holder_tg_port);

/*
 * res_pr_registered_i_pts
 */
static ssize_t target_core_dev_pr_show_attr_res_pr_registered_i_pts(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	struct target_core_fabric_ops *tfo;
	t10_pr_registration_t *pr_reg;
	unsigned char buf[384];
	char i_buf[PR_REG_ISID_ID_LEN];
	ssize_t len = 0;
	int reg_count = 0, prf_isid;

	if (!(su_dev->se_dev_ptr))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return len;

	len += sprintf(page+len, "SPC-3 PR Registrations:\n");

	spin_lock(&T10_RES(su_dev)->registration_lock);
	list_for_each_entry(pr_reg, &T10_RES(su_dev)->registration_list,
			pr_reg_list) {

		memset(buf, 0, 384);
		memset(i_buf, 0, PR_REG_ISID_ID_LEN);
		tfo = pr_reg->pr_reg_nacl->se_tpg->se_tpg_tfo;
		prf_isid = core_pr_dump_initiator_port(pr_reg, &i_buf[0],
					PR_REG_ISID_ID_LEN);
		sprintf(buf, "%s Node: %s%s Key: 0x%016Lx PRgen: 0x%08x\n",
			tfo->get_fabric_name(),
			pr_reg->pr_reg_nacl->initiatorname, (prf_isid) ?
			&i_buf[0] : "", pr_reg->pr_res_key,
			pr_reg->pr_res_generation);

		if ((len + strlen(buf) > PAGE_SIZE))
			break;

		len += sprintf(page+len, "%s", buf);
		reg_count++;
	}
	spin_unlock(&T10_RES(su_dev)->registration_lock);

	if (!(reg_count))
		len += sprintf(page+len, "None\n");

	return len;
}

SE_DEV_PR_ATTR_RO(res_pr_registered_i_pts);

/*
 * res_pr_type
 */
static ssize_t target_core_dev_pr_show_attr_res_pr_type(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	se_device_t *dev;
	t10_pr_registration_t *pr_reg;
	ssize_t len = 0;

	dev = su_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return len;

	spin_lock(&dev->dev_reservation_lock);
	pr_reg = dev->dev_pr_res_holder;
	if (!(pr_reg)) {
		len = sprintf(page, "No SPC-3 Reservation holder\n");
		spin_unlock(&dev->dev_reservation_lock);
		return len;
	}
	len = sprintf(page, "SPC-3 Reservation Type: %s\n",
		core_scsi3_pr_dump_type(pr_reg->pr_res_type));
	spin_unlock(&dev->dev_reservation_lock);

	return len;
}

SE_DEV_PR_ATTR_RO(res_pr_type);

/*
 * res_type
 */
static ssize_t target_core_dev_pr_show_attr_res_type(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	ssize_t len = 0;

	if (!(su_dev->se_dev_ptr))
		return -ENODEV;

	switch (T10_RES(su_dev)->res_type) {
	case SPC3_PERSISTENT_RESERVATIONS:
		len = sprintf(page, "SPC3_PERSISTENT_RESERVATIONS\n");
		break;
	case SPC2_RESERVATIONS:
		len = sprintf(page, "SPC2_RESERVATIONS\n");
		break;
	case SPC_PASSTHROUGH:
		len = sprintf(page, "SPC_PASSTHROUGH\n");
		break;
	default:
		len = sprintf(page, "UNKNOWN\n");
		break;
	}

	return len;
}

SE_DEV_PR_ATTR_RO(res_type);

/*
 * res_aptpl_active
 */

static ssize_t target_core_dev_pr_show_attr_res_aptpl_active(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	if (!(su_dev->se_dev_ptr))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return 0;

	return sprintf(page, "APTPL Bit Status: %s\n",
		(T10_RES(su_dev)->pr_aptpl_active) ? "Activated" : "Disabled");
}

SE_DEV_PR_ATTR_RO(res_aptpl_active);

/*
 * res_aptpl_metadata
 */
static ssize_t target_core_dev_pr_show_attr_res_aptpl_metadata(
	struct se_subsystem_dev_s *su_dev,
	char *page)
{
	if (!(su_dev->se_dev_ptr))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return 0;

	return sprintf(page, "Ready to process PR APTPL metadata..\n");
}

static ssize_t target_core_dev_pr_store_attr_res_aptpl_metadata(
	struct se_subsystem_dev_s *su_dev,
	const char *page,
	size_t count)
{
	se_device_t *dev;
	unsigned char *i_fabric, *t_fabric, *i_port = NULL, *t_port = NULL;
	unsigned char *isid = NULL;
	char *ptr, *ptr2, *cur, *buf;
	unsigned long long tmp_ll;
	unsigned long tmp_l;
	u64 sa_res_key = 0;
	u32 mapped_lun = 0, target_lun = 0;
	int ret = -1, res_holder = 0, all_tg_pt = 0;
	u16 port_rpti = 0, tpgt = 0;
	u8 type = 0, scope;

	dev = su_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	if (T10_RES(su_dev)->res_type != SPC3_PERSISTENT_RESERVATIONS)
		return 0;

	if (DEV_OBJ_API(dev)->check_count(&dev->dev_export_obj)) {
		printk(KERN_INFO "Unable to process APTPL metadata while"
			" active fabric exports exist\n");
		return -EINVAL;
	}
	/*
	 * Allocate and copy input to our own buffer so that we can setup
	 * NULL terminators later for incoming PR APTPL metadata..
	 */
	buf = kzalloc(count, GFP_KERNEL);
	memcpy(buf, page, count);
	cur = &buf[0];

	while (cur) {
		ptr = strstr(cur, "=");
		if (!(ptr))
			goto out;

		*ptr = '\0';
		ptr++;
		/*
		 * PR APTPL Metadata for Initiator Port
		 */
		ptr2 = strstr(cur, "initiator_fabric");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			i_fabric = ptr;
			continue;
		}
		ptr2 = strstr(cur, "initiator_node");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			if (strlen(ptr) > PR_APTPL_MAX_IPORT_LEN) {
				printk(KERN_ERR "APTPL metadata initiator_node="
					" exceeds PR_APTPL_MAX_IPORT_LEN: %d\n",
					PR_APTPL_MAX_IPORT_LEN);	
				ret = -1;
				break;
			}
			i_port = ptr;
			continue;
		}
		ptr2 = strstr(cur, "initiator_sid");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			if (strlen(ptr) > PR_REG_ISID_LEN) {
				printk(KERN_ERR "APTPL metadata initiator_isid"
					"= exceeds PR_REG_ISID_LEN: %d\n",
					PR_REG_ISID_LEN);
				ret = -1;
				break;
			}
			isid = ptr;
			continue;
		}
		ptr2 = strstr(cur, "sa_res_key");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoull(ptr, 0, &tmp_ll);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoull() failed for"
					" sa_res_key=\n");
				break;
			}
			sa_res_key = (u64)tmp_ll;
			continue;
		}
		/*
		 * PR APTPL Metadata for Reservation
		 */
		ptr2 = strstr(cur, "res_holder");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" res_holder=\n");
				break;
			}
			res_holder = (int)tmp_l;
			continue;
		}
		ptr2 = strstr(cur, "res_type");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" res_type=\n");
				break;
			}
			type = (u8)tmp_l;
			continue;
		}
		ptr2 = strstr(cur, "res_scope");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" res_scope=\n");
				break;
			}
			scope = (u8)tmp_l;
			continue;
		}
		ptr2 = strstr(cur, "res_all_tg_pt");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" res_all_tg_pt=\n");
				break;
			}
			all_tg_pt = (int)tmp_l;	
			continue;
		}
		ptr2 = strstr(cur, "mapped_lun");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" mapped_lun=\n");	
				break;
			}
			mapped_lun = (u32)tmp_l;
			continue;
		}
		/*
		 * PR APTPL Metadata for Target Port
		 */	
		ptr2 = strstr(cur, "target_fabric");	
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			t_fabric = ptr;
			continue;
		}
		ptr2 = strstr(cur, "target_node");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			if (strlen(ptr) > PR_APTPL_MAX_TPORT_LEN) {
				printk(KERN_ERR "APTPL metadata target_node="
					" exceeds PR_APTPL_MAX_TPORT_LEN: %d\n",
					PR_APTPL_MAX_TPORT_LEN);        
				ret = -1;
				break;
			}
			t_port = ptr;
			continue;
		}
		ptr2 = strstr(cur, "tpgt");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" tpgt=\n");
				break;
			}
			tpgt = (u16)tmp_l;
			continue;
		}
		ptr2 = strstr(cur, "port_rtpi");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" port_rtpi=\n");	
				break;
			}
			port_rpti = (u16)tmp_l;
			continue;
		}
		ptr2 = strstr(cur, "target_lun");
		if (ptr2) {
			transport_check_dev_params_delim(ptr, &cur);
			ret = tcm_strict_strtoul(ptr, 0, &tmp_l);
			if (ret < 0) {
				printk(KERN_ERR "tcm_strict_strtoul() failed for"
					" target_lun=\n");
				break;
			}
			target_lun = (u32)tmp_l;
			continue;
		} else
			cur = NULL;
	}

	if (!(i_port) || !(t_port) || !(sa_res_key)) {
		printk(KERN_ERR "Illegal parameters for APTPL registration\n");
		ret = -1;
		goto out;	
	}

	if (res_holder && !(type)) {
		printk(KERN_ERR "Illegal PR type: 0x%02x for reservation"
				" holder\n", type);
		ret = -1;
		goto out;
	}

	ret = core_scsi3_alloc_aptpl_registration(T10_RES(su_dev), sa_res_key,
			i_port, isid, mapped_lun, t_port, tpgt, target_lun,
			res_holder, all_tg_pt, type);
out:
	kfree(buf);
	return (ret == 0) ? count : -EINVAL;
}

SE_DEV_PR_ATTR(res_aptpl_metadata, S_IRUGO | S_IWUSR);

CONFIGFS_EATTR_OPS(target_core_dev_pr, se_subsystem_dev_s, se_dev_pr_group);

static struct configfs_attribute *target_core_dev_pr_attrs[] = {
	&target_core_dev_pr_res_holder.attr,
	&target_core_dev_pr_res_pr_all_tgt_pts.attr,
	&target_core_dev_pr_res_pr_generation.attr,
	&target_core_dev_pr_res_pr_holder_tg_port.attr,
	&target_core_dev_pr_res_pr_registered_i_pts.attr,
	&target_core_dev_pr_res_pr_type.attr,
	&target_core_dev_pr_res_type.attr,
	&target_core_dev_pr_res_aptpl_active.attr,
	&target_core_dev_pr_res_aptpl_metadata.attr,
	NULL,
};

static struct configfs_item_operations target_core_dev_pr_ops = {
	.show_attribute		= target_core_dev_pr_attr_show,
	.store_attribute	= target_core_dev_pr_attr_store,
};

static struct config_item_type target_core_dev_pr_cit = {
	.ct_item_ops		= &target_core_dev_pr_ops,
	.ct_attrs		= target_core_dev_pr_attrs,
	.ct_owner		= THIS_MODULE,
};

/*  End functions for struct config_item_type target_core_dev_pr_cit */

/* Start functions for struct config_item type target_core_dev_snap_cit */

CONFIGFS_EATTR_STRUCT(target_core_dev_snap, se_subsystem_dev_s);
#define SE_DEV_SNAP_ATTR(_name, _mode)						\
static struct target_core_dev_snap_attribute target_core_dev_snap_attr_##_name = \
	__CONFIGFS_EATTR(_name, _mode,						\
	target_core_dev_snap_show_attr_##_name,					\
	target_core_dev_snap_store_attr_##_name);

#define DEF_SNAP_ATTRIB_STR_SHOW(_name)						\
static ssize_t target_core_dev_snap_show_attr_##_name(				\
	struct se_subsystem_dev_s *se_dev,					\
	char *page)								\
{										\
	return snprintf(page, PAGE_SIZE, "%s\n", SE_DEV_SNAP(se_dev)->_name);	\
}

#define DEF_SNAP_ATTRIB_STR_STORE(_name, _max)					\
static ssize_t target_core_dev_snap_store_attr_##_name(				\
	struct se_subsystem_dev_s *se_dev,					\
	const char *page,							\
	size_t count)								\
{										\
	if (strlen(page) > _max) {						\
		printk(KERN_ERR "String length for attrib: %s exceeds max:"	\
			" %d\n", __stringify(_name), _max);			\
		return -EINVAL;							\
	}									\
	snprintf(SE_DEV_SNAP(se_dev)->_name, PAGE_SIZE, "%s", page);		\
	return count;								\
}

#define DEF_SNAP_ATTRIB_STR(_name, _max)					\
DEF_SNAP_ATTRIB_STR_SHOW(_name)							\
DEF_SNAP_ATTRIB_STR_STORE(_name, _max)

#define DEF_SNAP_ATTRIB_INT_SHOW(_name)						\
static ssize_t target_core_dev_snap_show_attr_##_name(				\
	struct se_subsystem_dev_s *se_dev,					\
	char *page)								\
{										\
	return snprintf(page, PAGE_SIZE, "%d\n", SE_DEV_SNAP(se_dev)->_name);	\
}

#define DEF_SNAP_ATTRIB_INT_STORE(_name, _max, _min)				\
static ssize_t target_core_dev_snap_store_attr_##_name(				\
	struct se_subsystem_dev_s *se_dev,					\
	const char *page,							\
	size_t count)								\
{										\
	int ret;								\
	unsigned long val;							\
										\
	ret = tcm_strict_strtoul(page, 0, &val);				\
	if (ret < 0) {								\
		printk(KERN_ERR "tcm_strict_strtoul() failed for %s with"	\
			" ret: %d\n", __stringify(_name), ret);			\
		return -EINVAL;							\
	}									\
	if ((_max != 0) && (val > _max)) {					\
		printk(KERN_ERR "snap attribute: %s exceeds max: %d\n",		\
				__stringify(_name), _max);			\
		return -EINVAL;							\
	}									\
	if (val < _min) {							\
		printk(KERN_ERR "snap attribute: %s less than min: %d\n",	\
				__stringify(_name), _min);			\
		return -EINVAL;							\
	}									\
	SE_DEV_SNAP(se_dev)->_name = (int)val;					\
	return count;								\
}

#define DEF_SNAP_ATTRIB_INT(_name, _max, _min)					\
DEF_SNAP_ATTRIB_INT_SHOW(_name)							\
DEF_SNAP_ATTRIB_INT_STORE(_name, _max, _min)

DEF_SNAP_ATTRIB_STR(contact, SNAP_CONTACT_LEN);
SE_DEV_SNAP_ATTR(contact, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_STR(lv_group, SNAP_GROUP_LEN);
SE_DEV_SNAP_ATTR(lv_group, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_STR(lvc_size, SNAP_LVC_LEN);
SE_DEV_SNAP_ATTR(lvc_size, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(pid, 0, 0);
SE_DEV_SNAP_ATTR(pid, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(enabled, 1, 0);
SE_DEV_SNAP_ATTR(enabled, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(permissions, 1, 0);
SE_DEV_SNAP_ATTR(permissions, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(max_snapshots, 256, 1); /* Max number of snapshots to rotate */
SE_DEV_SNAP_ATTR(max_snapshots, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(max_warn, 60, 0); /* Max minutes for warning emails about usage */
SE_DEV_SNAP_ATTR(max_warn, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(check_interval, 900, 5); /* 15 Minute max, 5 second min */
SE_DEV_SNAP_ATTR(check_interval, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(create_interval, 604800, 60); /* One 7-day week max, 1 minute min */
SE_DEV_SNAP_ATTR(create_interval, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(usage, 100, 0); /* Snapshot usage */
SE_DEV_SNAP_ATTR(usage, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(usage_warn, 100, 0); /* Snapshot usage before sending warning */
SE_DEV_SNAP_ATTR(usage_warn, S_IRUGO | S_IWUSR);

DEF_SNAP_ATTRIB_INT(vgs_usage_warn, 100, 0); /* Volume group usage before sending warning */
SE_DEV_SNAP_ATTR(vgs_usage_warn, S_IRUGO | S_IWUSR);

CONFIGFS_EATTR_OPS(target_core_dev_snap, se_subsystem_dev_s, se_dev_snap_group);

static struct configfs_attribute *target_core_dev_snap_attrs[] = {
	&target_core_dev_snap_attr_contact.attr,
	&target_core_dev_snap_attr_lv_group.attr,
	&target_core_dev_snap_attr_lvc_size.attr,
	&target_core_dev_snap_attr_pid.attr,
	&target_core_dev_snap_attr_enabled.attr,
	&target_core_dev_snap_attr_permissions.attr,
	&target_core_dev_snap_attr_max_snapshots.attr,
	&target_core_dev_snap_attr_max_warn.attr,
	&target_core_dev_snap_attr_check_interval.attr,
	&target_core_dev_snap_attr_create_interval.attr,
	&target_core_dev_snap_attr_usage.attr,
	&target_core_dev_snap_attr_usage_warn.attr,
	&target_core_dev_snap_attr_vgs_usage_warn.attr,
	NULL,
};

static struct configfs_item_operations target_core_dev_snap_ops = {
	.show_attribute		= target_core_dev_snap_attr_show,
	.store_attribute	= target_core_dev_snap_attr_store,
};

static struct config_item_type target_core_dev_snap_cit = {
	.ct_item_ops		= &target_core_dev_snap_ops,
	.ct_attrs		= target_core_dev_snap_attrs,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item type target_core_dev_snap_cit */

/*  Start functions for struct config_item_type target_core_dev_cit */

static ssize_t target_core_show_dev_info(void *p, char *page)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = se_dev->se_dev_hba;
	se_subsystem_api_t *t;
	int ret = 0, bl = 0;
	ssize_t read_bytes = 0;

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
			hba->type, &ret);
	if (!t || (ret != 0))
		return 0;

	if (!(se_dev->se_dev_ptr))
		return -ENODEV;

	transport_dump_dev_state(se_dev->se_dev_ptr, page, &bl);
	read_bytes += bl;
	read_bytes += t->show_configfs_dev_params(hba, se_dev, page+read_bytes);
	return read_bytes;
}

static struct target_core_configfs_attribute target_core_attr_dev_info = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "info",
		    .ca_mode = S_IRUGO },
	.show	= target_core_show_dev_info,
	.store	= NULL,
};

static ssize_t target_core_store_dev_control(
	void *p,
	const char *page,
	size_t count)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = se_dev->se_dev_hba;
	se_subsystem_api_t *t;
	int ret = 0;

	if (!(se_dev->se_dev_su_ptr)) {
		printk(KERN_ERR "Unable to locate se_subsystem_dev_t>se"
				"_dev_su_ptr\n");
		return -EINVAL;
	}

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
			hba->type, &ret);
	if (!t || (ret != 0))
		return -EINVAL;

	return t->set_configfs_dev_params(hba, se_dev, page, count);
}

static struct target_core_configfs_attribute target_core_attr_dev_control = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "control",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= target_core_store_dev_control,
};

static ssize_t target_core_store_dev_fd(void *p, const char *page, size_t count)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_device_t *dev;
	se_hba_t *hba = se_dev->se_dev_hba;
	se_subsystem_api_t *t;
	int ret = 0;

	if (se_dev->se_dev_ptr) {
		printk(KERN_ERR "se_dev->se_dev_ptr already set, ignoring"
			" fd request\n");
		return -EEXIST;
	}

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
			hba->type, &ret);
	if (!t || (ret != 0))
		return -EINVAL;

	if (!(t->create_virtdevice_from_fd)) {
		printk(KERN_ERR "se_subsystem_api_t->create_virtdevice_from"
			"_fd() NULL for: %s\n", hba->transport->name);
		return -EINVAL;
	}
	/*
	 * The subsystem PLUGIN is responsible for calling target_core_mod
	 * symbols to claim the underlying struct block_device for TYPE_DISK.
	 */
	dev = t->create_virtdevice_from_fd(se_dev, page);
	if (!(dev) || IS_ERR(dev))
		goto out;

	se_dev->se_dev_ptr = dev;
	printk(KERN_INFO "Target_Core_ConfigFS: Registered %s se_dev->se_dev"
		"_ptr: %p from fd\n", hba->transport->name, se_dev->se_dev_ptr);
	return count;
out:
	return -EINVAL;
}

static struct target_core_configfs_attribute target_core_attr_dev_fd = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "fd",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= target_core_store_dev_fd,
};

static ssize_t target_core_show_dev_alias(void *p, char *page)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;

	if (!(se_dev->su_dev_flags & SDF_USING_ALIAS))
		return 0;

	return snprintf(page, PAGE_SIZE, "%s\n", se_dev->se_dev_alias);
}

static ssize_t target_core_store_dev_alias(
	void *p,
	const char *page,
	size_t count)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = se_dev->se_dev_hba;
	ssize_t read_bytes;

	if (count > (SE_DEV_ALIAS_LEN-1)) {
		printk(KERN_ERR "alias count: %d exceeds"
			" SE_DEV_ALIAS_LEN-1: %u\n", (int)count,
			SE_DEV_ALIAS_LEN-1);
		return -EINVAL;
	}

	se_dev->su_dev_flags |= SDF_USING_ALIAS;
	read_bytes = snprintf(&se_dev->se_dev_alias[0], SE_DEV_ALIAS_LEN,
			"%s", page);

	printk(KERN_INFO "Target_Core_ConfigFS: %s/%s set alias: %s\n",
		config_item_name(&hba->hba_group.cg_item),
		config_item_name(&se_dev->se_dev_group.cg_item),
		se_dev->se_dev_alias);

	return read_bytes;
}

static struct target_core_configfs_attribute target_core_attr_dev_alias = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "alias",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_alias,
	.store	= target_core_store_dev_alias,
};

static ssize_t target_core_show_dev_udev_path(void *p, char *page)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;

	if (!(se_dev->su_dev_flags & SDF_USING_UDEV_PATH))
		return 0;

	return snprintf(page, PAGE_SIZE, "%s\n", se_dev->se_dev_udev_path);
}

static ssize_t target_core_store_dev_udev_path(
	void *p,
	const char *page,
	size_t count)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = se_dev->se_dev_hba;
	ssize_t read_bytes;

	if (count > (SE_UDEV_PATH_LEN-1)) {
		printk(KERN_ERR "udev_path count: %d exceeds"
			" SE_UDEV_PATH_LEN-1: %u\n", count,
			SE_UDEV_PATH_LEN-1);
		return -EINVAL;
	}

	se_dev->su_dev_flags |= SDF_USING_UDEV_PATH;
	read_bytes = snprintf(&se_dev->se_dev_udev_path[0], SE_UDEV_PATH_LEN,
			"%s", page);

	printk(KERN_INFO "Target_Core_ConfigFS: %s/%s set udev_path: %s\n",
		config_item_name(&hba->hba_group.cg_item),
		config_item_name(&se_dev->se_dev_group.cg_item),
		se_dev->se_dev_udev_path);
		
	return read_bytes;
}

static struct target_core_configfs_attribute target_core_attr_dev_udev_path = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "udev_path",
		    .ca_mode =  S_IRUGO | S_IWUSR },
	.show	= target_core_show_dev_udev_path,
	.store	= target_core_store_dev_udev_path,
};

static ssize_t target_core_store_dev_enable(
	void *p,
	const char *page,
	size_t count)
{
	se_subsystem_dev_t *se_dev = (se_subsystem_dev_t *)p;
	se_device_t *dev;
	se_hba_t *hba = se_dev->se_dev_hba;
	se_subsystem_api_t *t;
	char *ptr;
	int ret = 0;

	ptr = strstr(page, "1");
	if (!(ptr)) {
		printk(KERN_ERR "For dev_enable ops, only valid value"
				" is \"1\"\n");
		return -EINVAL;
	}
	if ((se_dev->se_dev_ptr)) {
		printk(KERN_ERR "se_dev->se_dev_ptr already set for storage"
				" object\n");
		return -EEXIST;
	}

	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
			hba->type, &ret);
	if (!t || (ret != 0))
		return -EINVAL;

	if (t->check_configfs_dev_params(hba, se_dev) < 0)
		return -EINVAL;

	dev = t->create_virtdevice(hba, se_dev, se_dev->se_dev_su_ptr);
	if (!(dev) || IS_ERR(dev))
		return -EINVAL;

	se_dev->se_dev_ptr = dev;
	printk(KERN_INFO "Target_Core_ConfigFS: Registered se_dev->se_dev_ptr:"
		" %p\n", se_dev->se_dev_ptr);

	return count;
}

static struct target_core_configfs_attribute target_core_attr_dev_enable = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "enable",
		    .ca_mode = S_IWUSR },
	.show	= NULL,
	.store	= target_core_store_dev_enable,
};

static ssize_t target_core_show_alua_lu_gp(void *p, char *page)
{
	se_device_t *dev;
	se_subsystem_dev_t *su_dev = (se_subsystem_dev_t *)p;
	struct config_item *lu_ci;
	t10_alua_lu_gp_t *lu_gp;
	t10_alua_lu_gp_member_t *lu_gp_mem;
	ssize_t len = 0;

	dev = su_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	if (T10_ALUA(su_dev)->alua_type != SPC3_ALUA_EMULATED)
		return len;

	lu_gp_mem = dev->dev_alua_lu_gp_mem;
	if (!(lu_gp_mem)) {
		printk(KERN_ERR "NULL se_device_t->dev_alua_lu_gp_mem"
				" pointer\n");
		return -EINVAL;
	}

	spin_lock(&lu_gp_mem->lu_gp_mem_lock);
	lu_gp = lu_gp_mem->lu_gp;
	if ((lu_gp)) {
		lu_ci = &lu_gp->lu_gp_group.cg_item;
		len += sprintf(page, "LU Group Alias: %s\nLU Group ID: %hu\n",
			config_item_name(lu_ci), lu_gp->lu_gp_id);
	}
	spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

	return len;
}

static ssize_t target_core_store_alua_lu_gp(
	void *p,
	const char *page,
	size_t count)
{
	se_device_t *dev;
	se_subsystem_dev_t *su_dev = (se_subsystem_dev_t *)p;
	se_hba_t *hba = su_dev->se_dev_hba;
	t10_alua_lu_gp_t *lu_gp = NULL, *lu_gp_new = NULL;
	t10_alua_lu_gp_member_t *lu_gp_mem;
	unsigned char buf[LU_GROUP_NAME_BUF];
	int move = 0;

	dev = su_dev->se_dev_ptr;
	if (!(dev))
		return -ENODEV;

	if (T10_ALUA(su_dev)->alua_type != SPC3_ALUA_EMULATED) {
		printk(KERN_WARNING "SPC3_ALUA_EMULATED not enabled for %s/%s\n",
			config_item_name(&hba->hba_group.cg_item),
			config_item_name(&su_dev->se_dev_group.cg_item));
		return -EINVAL;
	}
	if (count > LU_GROUP_NAME_BUF) {
		printk(KERN_ERR "ALUA LU Group Alias too large!\n");
		return -EINVAL;
	}
	memset(buf, 0, LU_GROUP_NAME_BUF);
	memcpy(buf, page, count);
	/*
	 * Any ALUA logical unit alias besides "NULL" means we will be
	 * making a new group association.
	 */
	if (strcmp(strstrip(buf), "NULL")) {
		/*
		 * core_alua_get_lu_gp_by_name() will increment reference to
		 * t10_alua_lu_gp_t.  This reference is released with
		 * core_alua_get_lu_gp_by_name below().
		 */
		lu_gp_new = core_alua_get_lu_gp_by_name(strstrip(buf));
		if (!(lu_gp_new))
			return -ENODEV;
	}
	lu_gp_mem = dev->dev_alua_lu_gp_mem;
	if (!(lu_gp_mem)) {
		if (lu_gp_new)
			core_alua_put_lu_gp_from_name(lu_gp_new);
		printk(KERN_ERR "NULL se_device_t->dev_alua_lu_gp_mem"
				" pointer\n");
		return -EINVAL;
	}

	spin_lock(&lu_gp_mem->lu_gp_mem_lock);
	lu_gp = lu_gp_mem->lu_gp;
	if ((lu_gp)) {
		/*
		 * Clearing an existing lu_gp association, and replacing
		 * with NULL
		 */
		if (!(lu_gp_new)) {
			printk(KERN_INFO "Target_Core_ConfigFS: Releasing %s/%s"
				" from ALUA LU Group: core/alua/lu_gps/%s, ID:"
				" %hu\n",
				config_item_name(&hba->hba_group.cg_item),
				config_item_name(&su_dev->se_dev_group.cg_item),
				config_item_name(&lu_gp->lu_gp_group.cg_item),
				lu_gp->lu_gp_id);

			__core_alua_drop_lu_gp_mem(lu_gp_mem, lu_gp);
			spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

			return count;
		}
		/*
		 * Removing existing association of lu_gp_mem with lu_gp
		 */
		__core_alua_drop_lu_gp_mem(lu_gp_mem, lu_gp);
		move = 1;
	}
	/*
	 * Associate lu_gp_mem with lu_gp_new.
	 */
	__core_alua_attach_lu_gp_mem(lu_gp_mem, lu_gp_new);
	spin_unlock(&lu_gp_mem->lu_gp_mem_lock);

	printk(KERN_INFO "Target_Core_ConfigFS: %s %s/%s to ALUA LU Group:"
		" core/alua/lu_gps/%s, ID: %hu\n",
		(move) ? "Moving" : "Adding",
		config_item_name(&hba->hba_group.cg_item),
		config_item_name(&su_dev->se_dev_group.cg_item),
		config_item_name(&lu_gp_new->lu_gp_group.cg_item),
		lu_gp_new->lu_gp_id);

	core_alua_put_lu_gp_from_name(lu_gp_new);
	return count;
}

static struct target_core_configfs_attribute target_core_attr_dev_alua_lu_gp = {
	.attr	= { .ca_owner = THIS_MODULE,
		    .ca_name = "alua_lu_gp",
		    .ca_mode = S_IRUGO | S_IWUSR },
	.show	= target_core_show_alua_lu_gp,
	.store	= target_core_store_alua_lu_gp,
};

static struct configfs_attribute *lio_core_dev_attrs[] = {
	&target_core_attr_dev_info.attr,
	&target_core_attr_dev_control.attr,
	&target_core_attr_dev_fd.attr,
	&target_core_attr_dev_alias.attr,
	&target_core_attr_dev_udev_path.attr,
	&target_core_attr_dev_enable.attr,
	&target_core_attr_dev_alua_lu_gp.attr,
	NULL,
};

static void target_core_dev_release(struct config_item *item)
{
	se_subsystem_dev_t *se_dev = container_of(to_config_group(item),
				se_subsystem_dev_t, se_dev_group);
	se_hba_t *hba = item_to_hba(&se_dev->se_dev_hba->hba_group.cg_item);
	se_subsystem_api_t *t = hba->transport;
	struct config_group *dev_cg = &se_dev->se_dev_group;

	kfree(dev_cg->default_groups);
	/*
	 * This pointer will set when the storage is enabled with:
	 * `echo 1 > $CONFIGFS/core/$HBA/$DEV/dev_enable`
	 */
	if (se_dev->se_dev_ptr) {
		printk(KERN_INFO "Target_Core_ConfigFS: Calling se_free_"
			"virtual_device() for se_dev_ptr: %p\n",
			se_dev->se_dev_ptr);

		se_free_virtual_device(se_dev->se_dev_ptr, hba);
        } else {
		/*
		 * Release se_subsystem_dev_t->se_dev_su_ptr..
		 */
		printk(KERN_INFO "Target_Core_ConfigFS: Calling t->free_"
			"device() for se_dev_su_ptr: %p\n",
			se_dev->se_dev_su_ptr);

		t->free_device(se_dev->se_dev_su_ptr);
	}

	printk(KERN_INFO "Target_Core_ConfigFS: Deallocating se_subsystem"
			"_dev_t: %p\n", se_dev);
        kfree(se_dev);
}

static ssize_t target_core_dev_show(struct config_item *item,
				     struct configfs_attribute *attr,
				     char *page)
{
	se_subsystem_dev_t *se_dev = container_of(
			to_config_group(item), se_subsystem_dev_t,
			se_dev_group);
	struct target_core_configfs_attribute *tc_attr = container_of(
			attr, struct target_core_configfs_attribute, attr);

	if (!(tc_attr->show))
		return -EINVAL;

	return tc_attr->show((void *)se_dev, page);
}

static ssize_t target_core_dev_store(struct config_item *item,
				      struct configfs_attribute *attr,
				      const char *page, size_t count)
{
	se_subsystem_dev_t *se_dev = container_of(
			to_config_group(item), se_subsystem_dev_t,
			se_dev_group);
	struct target_core_configfs_attribute *tc_attr = container_of(
			attr, struct target_core_configfs_attribute, attr);

	if (!(tc_attr->store))
		return -EINVAL;

	return tc_attr->store((void *)se_dev, page, count);
}

static struct configfs_item_operations target_core_dev_item_ops = {
	.release		= target_core_dev_release,
	.show_attribute		= target_core_dev_show,
	.store_attribute	= target_core_dev_store,
};

static struct config_item_type target_core_dev_cit = {
	.ct_item_ops		= &target_core_dev_item_ops,
	.ct_attrs		= lio_core_dev_attrs,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item_type target_core_dev_cit */

/* Start functions for struct config_item_type target_core_alua_lu_gp_cit */

CONFIGFS_EATTR_STRUCT(target_core_alua_lu_gp, t10_alua_lu_gp_s);
#define SE_DEV_ALUA_LU_ATTR(_name, _mode)				\
static struct target_core_alua_lu_gp_attribute				\
			target_core_alua_lu_gp_##_name =		\
	__CONFIGFS_EATTR(_name, _mode,					\
	target_core_alua_lu_gp_show_attr_##_name,			\
	target_core_alua_lu_gp_store_attr_##_name);			

#define SE_DEV_ALUA_LU_ATTR_RO(_name)					\
static struct target_core_alua_lu_gp_attribute				\
			target_core_alua_lu_gp_##_name =		\
	__CONFIGFS_EATTR_RO(_name,					\
	target_core_alua_lu_gp_show_attr_##_name);

/*
 * lu_gp_id
 */
static ssize_t target_core_alua_lu_gp_show_attr_lu_gp_id(
	struct t10_alua_lu_gp_s *lu_gp,
	char *page)
{
	if (!(lu_gp->lu_gp_valid_id))
		return 0;

	return sprintf(page, "%hu\n", lu_gp->lu_gp_id);
}

static ssize_t target_core_alua_lu_gp_store_attr_lu_gp_id(
	struct t10_alua_lu_gp_s *lu_gp,
	const char *page,
	size_t count)
{
	struct config_group *alua_lu_gp_cg = &lu_gp->lu_gp_group;
	unsigned long lu_gp_id;
	int ret;

	ret = tcm_strict_strtoul(page, 0, &lu_gp_id);
	if (ret < 0) {
		printk(KERN_ERR "tcm_strict_strtoul() returned %d for"
			" lu_gp_id\n", ret);
		return -EINVAL;
	}
	if (lu_gp_id > 0x0000ffff) {
		printk(KERN_ERR "ALUA lu_gp_id: %lu exceeds maximum:"
			" 0x0000ffff\n", lu_gp_id);
		return -EINVAL;
	}

	ret = core_alua_set_lu_gp_id(lu_gp, (u16)lu_gp_id);
	if (ret < 0)
		return -EINVAL;

	printk(KERN_INFO "Target_Core_ConfigFS: Set ALUA Logical Unit"
		" Group: core/alua/lu_gps/%s to ID: %hu\n",
		config_item_name(&alua_lu_gp_cg->cg_item),
		lu_gp->lu_gp_id);

	return count;
}

SE_DEV_ALUA_LU_ATTR(lu_gp_id, S_IRUGO | S_IWUSR);

/*
 * members
 */
static ssize_t target_core_alua_lu_gp_show_attr_members(
	struct t10_alua_lu_gp_s *lu_gp,
	char *page)
{
	se_device_t *dev;
	se_hba_t *hba;
	se_subsystem_dev_t *su_dev;
	t10_alua_lu_gp_member_t *lu_gp_mem;
	ssize_t len = 0, cur_len;
	unsigned char buf[LU_GROUP_NAME_BUF];

	memset(buf, 0, LU_GROUP_NAME_BUF);

	spin_lock(&lu_gp->lu_gp_lock);
	list_for_each_entry(lu_gp_mem, &lu_gp->lu_gp_mem_list, lu_gp_mem_list) {
		dev = lu_gp_mem->lu_gp_mem_dev;
		su_dev = dev->se_sub_dev;
		hba = su_dev->se_dev_hba;

		cur_len = snprintf(buf, LU_GROUP_NAME_BUF, "%s/%s\n",
			config_item_name(&hba->hba_group.cg_item),
			config_item_name(&su_dev->se_dev_group.cg_item));
		cur_len++; /* Extra byte for NULL terminator */

		if ((cur_len + len) > PAGE_SIZE) {
			printk(KERN_WARNING "Ran out of lu_gp_show_attr"
				"_members buffer\n");
			break;
		}
		memcpy(page+len, buf, cur_len);
		len += cur_len;
	}
	spin_unlock(&lu_gp->lu_gp_lock);

	return len;
}

SE_DEV_ALUA_LU_ATTR_RO(members);

CONFIGFS_EATTR_OPS(target_core_alua_lu_gp, t10_alua_lu_gp_s, lu_gp_group);

static struct configfs_attribute *target_core_alua_lu_gp_attrs[] = {
	&target_core_alua_lu_gp_lu_gp_id.attr,
	&target_core_alua_lu_gp_members.attr,
	NULL,
};

static void target_core_alua_lu_gp_release(struct config_item *item)
{
	t10_alua_lu_gp_t *lu_gp = container_of(to_config_group(item),
			struct t10_alua_lu_gp_s, lu_gp_group);

	core_alua_free_lu_gp(lu_gp);
}

static struct configfs_item_operations target_core_alua_lu_gp_ops = {
	.release		= target_core_alua_lu_gp_release,
	.show_attribute		= target_core_alua_lu_gp_attr_show,
	.store_attribute	= target_core_alua_lu_gp_attr_store,
};

static struct config_item_type target_core_alua_lu_gp_cit = {
	.ct_item_ops		= &target_core_alua_lu_gp_ops,
	.ct_attrs		= target_core_alua_lu_gp_attrs,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item_type target_core_alua_lu_gp_cit */

/* Start functions for struct config_item_type target_core_alua_lu_gps_cit */

static struct config_group *target_core_alua_create_lu_gp(
	struct config_group *group,
	const char *name)
{
	t10_alua_lu_gp_t *lu_gp;
	struct config_group *alua_lu_gp_cg = NULL;
	struct config_item *alua_lu_gp_ci = NULL;

	lu_gp = core_alua_allocate_lu_gp(name, 0);
	if (!(lu_gp))
		return NULL;

	alua_lu_gp_cg = &lu_gp->lu_gp_group;
	alua_lu_gp_ci = &alua_lu_gp_cg->cg_item;

	config_group_init_type_name(alua_lu_gp_cg, name,
			&target_core_alua_lu_gp_cit);

	printk(KERN_INFO "Target_Core_ConfigFS: Allocated ALUA Logical Unit"
		" Group: core/alua/lu_gps/%s\n",
		config_item_name(alua_lu_gp_ci));

	return alua_lu_gp_cg;

}

static void target_core_alua_drop_lu_gp(
	struct config_group *group,
	struct config_item *item)
{
	t10_alua_lu_gp_t *lu_gp = container_of(to_config_group(item),
			t10_alua_lu_gp_t, lu_gp_group);

	printk(KERN_INFO "Target_Core_ConfigFS: Releasing ALUA Logical Unit"
		" Group: core/alua/lu_gps/%s, ID: %hu\n",
		config_item_name(item), lu_gp->lu_gp_id);
	/*
	 * core_alua_free_lu_gp() is called from target_core_alua_lu_gp_ops->release()
	 * -> target_core_alua_lu_gp_release()
	 */
	config_item_put(item);
}

static struct configfs_group_operations target_core_alua_lu_gps_group_ops = {
	.make_group		= &target_core_alua_create_lu_gp,
	.drop_item		= &target_core_alua_drop_lu_gp,
};

static struct config_item_type target_core_alua_lu_gps_cit = {
	.ct_item_ops		= NULL,
	.ct_group_ops		= &target_core_alua_lu_gps_group_ops,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item_type target_core_alua_lu_gps_cit */

/* Start functions for struct config_item_type target_core_alua_tg_pt_gp_cit */

CONFIGFS_EATTR_STRUCT(target_core_alua_tg_pt_gp, t10_alua_tg_pt_gp_s);
#define SE_DEV_ALUA_TG_PT_ATTR(_name, _mode)				\
static struct target_core_alua_tg_pt_gp_attribute			\
			target_core_alua_tg_pt_gp_##_name =		\
	__CONFIGFS_EATTR(_name, _mode,					\
	target_core_alua_tg_pt_gp_show_attr_##_name,			\
	target_core_alua_tg_pt_gp_store_attr_##_name);

#define SE_DEV_ALUA_TG_PT_ATTR_RO(_name)				\
static struct target_core_alua_tg_pt_gp_attribute			\
			target_core_alua_tg_pt_gp_##_name =		\
	__CONFIGFS_EATTR_RO(_name,					\
	target_core_alua_tg_pt_gp_show_attr_##_name);

/*
 * alua_access_state
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_alua_access_state(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	return sprintf(page, "%d\n",
		atomic_read(&tg_pt_gp->tg_pt_gp_alua_access_state));
}

static ssize_t target_core_alua_tg_pt_gp_store_attr_alua_access_state(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	se_subsystem_dev_t *su_dev = tg_pt_gp->tg_pt_gp_su_dev;
	unsigned long tmp;
	int new_state, ret;

	if (!(tg_pt_gp->tg_pt_gp_valid_id)) {
		printk(KERN_ERR "Unable to do implict ALUA on non valid"
			" tg_pt_gp ID: %hu\n", tg_pt_gp->tg_pt_gp_valid_id);
		return -EINVAL;
	}
	
	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk("Unable to extract new ALUA access state from"
				" %s\n", page);
		return -EINVAL;
	}
	new_state = (int)tmp;

	if (!(tg_pt_gp->tg_pt_gp_alua_access_type & TPGS_IMPLICT_ALUA)) {
		printk(KERN_ERR "Unable to process implict configfs ALUA"
			" transition while TPGS_IMPLICT_ALUA is diabled\n");
		return -EINVAL;
	}

	ret = core_alua_do_port_transition(tg_pt_gp, su_dev->se_dev_ptr,
					NULL, NULL, new_state, 0);
	return (!ret) ? count : -EINVAL;	
}

SE_DEV_ALUA_TG_PT_ATTR(alua_access_state, S_IRUGO | S_IWUSR);

/*
 * alua_access_status
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_alua_access_status(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	return sprintf(page, "%s\n",
		core_alua_dump_status(tg_pt_gp->tg_pt_gp_alua_access_status));
}

static ssize_t target_core_alua_tg_pt_gp_store_attr_alua_access_status(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int new_status, ret;
	
	if (!(tg_pt_gp->tg_pt_gp_valid_id)) {
		printk(KERN_ERR "Unable to do set ALUA access status on non"
			" valid tg_pt_gp ID: %hu\n",
			tg_pt_gp->tg_pt_gp_valid_id);
		return -EINVAL;		
	}

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract new ALUA access status"
				" from %s\n", page);
		return -EINVAL;
	}
	new_status = (int)tmp;

	if ((new_status != ALUA_STATUS_NONE) &&
	    (new_status != ALUA_STATUS_ALTERED_BY_EXPLICT_STPG) &&
	    (new_status != ALUA_STATUS_ALTERED_BY_IMPLICT_ALUA)) {
		printk(KERN_ERR "Illegal ALUA access status: 0x%02x\n", new_status);
		return -EINVAL;
	}

	tg_pt_gp->tg_pt_gp_alua_access_status = new_status;
	return count;
}

SE_DEV_ALUA_TG_PT_ATTR(alua_access_status, S_IRUGO | S_IWUSR);

/*
 * alua_access_type
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_alua_access_type(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	return core_alua_show_access_type(tg_pt_gp, page);
}

static ssize_t target_core_alua_tg_pt_gp_store_attr_alua_access_type(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	return core_alua_store_access_type(tg_pt_gp, page, count);
}

SE_DEV_ALUA_TG_PT_ATTR(alua_access_type, S_IRUGO | S_IWUSR);

/*
 * alua_write_metadata
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_alua_write_metadata(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	return sprintf(page, "%d\n", tg_pt_gp->tg_pt_gp_write_metadata);
}

static ssize_t target_core_alua_tg_pt_gp_store_attr_alua_write_metadata(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	unsigned long tmp;
	int ret;

	ret = tcm_strict_strtoul(page, 0, &tmp);
	if (ret < 0) {
		printk(KERN_ERR "Unable to extract alua_write_metadata\n");	
		return -EINVAL;
	}

	if ((tmp != 0) && (tmp != 1)) {
		printk(KERN_ERR "Illegal value for alua_write_metadata:"
			" %lu\n", tmp);
		return -EINVAL;
	}
	tg_pt_gp->tg_pt_gp_write_metadata = (int)tmp;

	return count;
}

SE_DEV_ALUA_TG_PT_ATTR(alua_write_metadata, S_IRUGO | S_IWUSR);



/*
 * nonop_delay_msecs
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_nonop_delay_msecs(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	return core_alua_show_nonop_delay_msecs(tg_pt_gp, page);

}

static ssize_t target_core_alua_tg_pt_gp_store_attr_nonop_delay_msecs(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	return core_alua_store_nonop_delay_msecs(tg_pt_gp, page, count);
}

SE_DEV_ALUA_TG_PT_ATTR(nonop_delay_msecs, S_IRUGO | S_IWUSR);

/*
 * trans_delay_msecs
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_trans_delay_msecs(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	return core_alua_show_trans_delay_msecs(tg_pt_gp, page);
}

static ssize_t target_core_alua_tg_pt_gp_store_attr_trans_delay_msecs(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	return core_alua_store_trans_delay_msecs(tg_pt_gp, page, count);	
}

SE_DEV_ALUA_TG_PT_ATTR(trans_delay_msecs, S_IRUGO | S_IWUSR);

/*
 * preferred
 */

static ssize_t target_core_alua_tg_pt_gp_show_attr_preferred(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	return core_alua_show_preferred_bit(tg_pt_gp, page);
}

static ssize_t target_core_alua_tg_pt_gp_store_attr_preferred(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	return core_alua_store_preferred_bit(tg_pt_gp, page, count);
}

SE_DEV_ALUA_TG_PT_ATTR(preferred, S_IRUGO | S_IWUSR);

/*
 * tg_pt_gp_id
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_tg_pt_gp_id(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	if (!(tg_pt_gp->tg_pt_gp_valid_id))
		return 0;

	return sprintf(page, "%hu\n", tg_pt_gp->tg_pt_gp_id);
}

static ssize_t target_core_alua_tg_pt_gp_store_attr_tg_pt_gp_id(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	const char *page,
	size_t count)
{
	struct config_group *alua_tg_pt_gp_cg = &tg_pt_gp->tg_pt_gp_group;
	unsigned long tg_pt_gp_id;	
	int ret;

	ret = tcm_strict_strtoul(page, 0, &tg_pt_gp_id);
	if (ret < 0) {
		printk(KERN_ERR "tcm_strict_strtoul() returned %d for"
			" tg_pt_gp_id\n", ret);
		return -EINVAL;
	}
	if (tg_pt_gp_id > 0x0000ffff) {
		printk(KERN_ERR "ALUA tg_pt_gp_id: %lu exceeds maximum:"
			" 0x0000ffff\n", tg_pt_gp_id);
		return -EINVAL;
	}

	ret = core_alua_set_tg_pt_gp_id(tg_pt_gp, (u16)tg_pt_gp_id);
	if (ret < 0)
		return -EINVAL;

	printk(KERN_INFO "Target_Core_ConfigFS: Set ALUA Target Port Group: "
		"core/alua/tg_pt_gps/%s to ID: %hu\n",
		config_item_name(&alua_tg_pt_gp_cg->cg_item),
		tg_pt_gp->tg_pt_gp_id);

	return count;
}

SE_DEV_ALUA_TG_PT_ATTR(tg_pt_gp_id, S_IRUGO | S_IWUSR);

/*
 * members
 */
static ssize_t target_core_alua_tg_pt_gp_show_attr_members(
	struct t10_alua_tg_pt_gp_s *tg_pt_gp,
	char *page)
{
	se_port_t *port;
	se_portal_group_t *tpg;
	se_lun_t *lun;
	t10_alua_tg_pt_gp_member_t *tg_pt_gp_mem;
	ssize_t len = 0, cur_len;
	unsigned char buf[TG_PT_GROUP_NAME_BUF];

	memset(buf, 0, TG_PT_GROUP_NAME_BUF);

	spin_lock(&tg_pt_gp->tg_pt_gp_lock);
	list_for_each_entry(tg_pt_gp_mem, &tg_pt_gp->tg_pt_gp_mem_list,
			tg_pt_gp_mem_list) {
		port = tg_pt_gp_mem->tg_pt;
		tpg = port->sep_tpg;
		lun = port->sep_lun;

		cur_len = snprintf(buf, TG_PT_GROUP_NAME_BUF, "%s/%s/tpgt_%hu"
			"/%s\n", TPG_TFO(tpg)->get_fabric_name(),
			TPG_TFO(tpg)->tpg_get_wwn(tpg),
			TPG_TFO(tpg)->tpg_get_tag(tpg),
			config_item_name(&lun->lun_group.cg_item));
		cur_len++; /* Extra byte for NULL terminator */

		if ((cur_len + len) > PAGE_SIZE) {
			printk(KERN_WARNING "Ran out of lu_gp_show_attr"
				"_members buffer\n");
			break;
		}
		memcpy(page+len, buf, cur_len);
		len += cur_len;
	}
	spin_unlock(&tg_pt_gp->tg_pt_gp_lock);

	return len;
}

SE_DEV_ALUA_TG_PT_ATTR_RO(members);

CONFIGFS_EATTR_OPS(target_core_alua_tg_pt_gp, t10_alua_tg_pt_gp_s,
			tg_pt_gp_group);

static struct configfs_attribute *target_core_alua_tg_pt_gp_attrs[] = {
	&target_core_alua_tg_pt_gp_alua_access_state.attr,
	&target_core_alua_tg_pt_gp_alua_access_status.attr,
	&target_core_alua_tg_pt_gp_alua_access_type.attr,
	&target_core_alua_tg_pt_gp_alua_write_metadata.attr,
	&target_core_alua_tg_pt_gp_nonop_delay_msecs.attr,
	&target_core_alua_tg_pt_gp_trans_delay_msecs.attr,
	&target_core_alua_tg_pt_gp_preferred.attr,
	&target_core_alua_tg_pt_gp_tg_pt_gp_id.attr,
	&target_core_alua_tg_pt_gp_members.attr,
	NULL,
};

static void target_core_alua_tg_pt_gp_release(struct config_item *item)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp = container_of(to_config_group(item),
			struct t10_alua_tg_pt_gp_s, tg_pt_gp_group);

	core_alua_free_tg_pt_gp(tg_pt_gp);
}

static struct configfs_item_operations target_core_alua_tg_pt_gp_ops = {
	.release		= target_core_alua_tg_pt_gp_release,
	.show_attribute		= target_core_alua_tg_pt_gp_attr_show,
	.store_attribute	= target_core_alua_tg_pt_gp_attr_store,
};

static struct config_item_type target_core_alua_tg_pt_gp_cit = {
	.ct_item_ops		= &target_core_alua_tg_pt_gp_ops,
	.ct_attrs		= target_core_alua_tg_pt_gp_attrs,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item_type target_core_alua_tg_pt_gp_cit */

/* Start functions for struct config_item_type target_core_alua_tg_pt_gps_cit */

static struct config_group *target_core_alua_create_tg_pt_gp(
	struct config_group *group,
	const char *name)
{
	t10_alua_t *alua = container_of(group, t10_alua_t,
					alua_tg_pt_gps_group);
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	se_subsystem_dev_t *su_dev = alua->t10_sub_dev;
	struct config_group *alua_tg_pt_gp_cg = NULL;
	struct config_item *alua_tg_pt_gp_ci = NULL;

	tg_pt_gp = core_alua_allocate_tg_pt_gp(su_dev, name, 0);
	if (!(tg_pt_gp))
		return NULL;

	alua_tg_pt_gp_cg = &tg_pt_gp->tg_pt_gp_group;
	alua_tg_pt_gp_ci = &alua_tg_pt_gp_cg->cg_item;

	config_group_init_type_name(alua_tg_pt_gp_cg, name,
			&target_core_alua_tg_pt_gp_cit);

	printk(KERN_INFO "Target_Core_ConfigFS: Allocated ALUA Target Port"
		" Group: alua/tg_pt_gps/%s\n",
		config_item_name(alua_tg_pt_gp_ci));

	return alua_tg_pt_gp_cg;
}

static void target_core_alua_drop_tg_pt_gp(
	struct config_group *group,
	struct config_item *item)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp = container_of(to_config_group(item),
			t10_alua_tg_pt_gp_t, tg_pt_gp_group);

	printk(KERN_INFO "Target_Core_ConfigFS: Releasing ALUA Target Port"
		" Group: alua/tg_pt_gps/%s, ID: %hu\n",
		config_item_name(item), tg_pt_gp->tg_pt_gp_id);
	/*
 	 * core_alua_free_tg_pt_gp() is called from target_core_alua_tg_pt_gp_ops->release()
 	 * -> target_core_alua_tg_pt_gp_release().
 	 */
	config_item_put(item);
}

static struct configfs_group_operations target_core_alua_tg_pt_gps_group_ops = {
	.make_group		= &target_core_alua_create_tg_pt_gp,
	.drop_item		= &target_core_alua_drop_tg_pt_gp,
};

static struct config_item_type target_core_alua_tg_pt_gps_cit = {
	.ct_group_ops		= &target_core_alua_tg_pt_gps_group_ops,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item_type target_core_alua_tg_pt_gps_cit */

/* Start functions for struct config_item_type target_core_alua_cit */

/*
 * target_core_alua_cit is a ConfigFS group that lives under
 * /sys/kernel/config/target/core/alua.  There are default groups
 * core/alua/lu_gps and core/alua/tg_pt_gps that are attached to
 * target_core_alua_cit in target_core_init_configfs() below.
 */
static struct config_item_type target_core_alua_cit = {
	.ct_item_ops		= NULL,
	.ct_attrs		= NULL,
	.ct_owner		= THIS_MODULE,
};

/* End functions for struct config_item_type target_core_alua_cit */

/* Start functions for struct config_item_type target_core_hba_cit */

static struct config_group *target_core_call_createdev(
	struct config_group *group,
	const char *name)
{
	t10_alua_tg_pt_gp_t *tg_pt_gp;
	se_subsystem_dev_t *se_dev;
	se_hba_t *hba;
	se_subsystem_api_t *t;
	struct config_item *hba_ci;
	struct config_group *dev_cg = NULL, *tg_pt_gp_cg = NULL;
	int ret = 0;

	hba_ci = &group->cg_item;
	if (!(hba_ci)) {
		printk(KERN_ERR "Unable to locate config_item hba_ci\n");
		return NULL;
	}

	hba = target_core_get_hba_from_item(hba_ci);
	if (!(hba)) {
		printk(KERN_ERR "Unable to locate se_hba_t from struct config_item\n");
		return NULL;
	}

	/*
	 * Locate the se_subsystem_api_t from parent's se_hba_t.
	 */
	t = (se_subsystem_api_t *)plugin_get_obj(PLUGIN_TYPE_TRANSPORT,
			hba->type, &ret);
	if (!t || (ret != 0)) {
		core_put_hba(hba);
		return NULL;
	}

	se_dev = kzalloc(sizeof(se_subsystem_dev_t), GFP_KERNEL);
	if (!(se_dev)) {
		printk(KERN_ERR "Unable to allocate memory for"
				" se_subsystem_dev_t\n");
		return NULL;
	}
	INIT_LIST_HEAD(&se_dev->g_se_dev_list);
	INIT_LIST_HEAD(&se_dev->t10_wwn.t10_vpd_list);
	spin_lock_init(&se_dev->t10_wwn.t10_vpd_lock);
	INIT_LIST_HEAD(&se_dev->t10_reservation.registration_list);
	INIT_LIST_HEAD(&se_dev->t10_reservation.aptpl_reg_list);
	spin_lock_init(&se_dev->t10_reservation.registration_lock);
	spin_lock_init(&se_dev->t10_reservation.aptpl_reg_lock);
	INIT_LIST_HEAD(&se_dev->t10_alua.tg_pt_gps_list);
	spin_lock_init(&se_dev->t10_alua.tg_pt_gps_lock);
	spin_lock_init(&se_dev->se_dev_lock);
	se_dev->t10_reservation.pr_aptpl_buf_len = PR_APTPL_BUF_LEN;
	se_dev->t10_wwn.t10_sub_dev = se_dev;
	se_dev->t10_alua.t10_sub_dev = se_dev;
	se_dev->se_dev_attrib.da_sub_dev = se_dev;

	se_dev->se_dev_hba = hba;
	dev_cg = &se_dev->se_dev_group;

	dev_cg->default_groups = kzalloc(sizeof(struct config_group) * 6,
			GFP_KERNEL);
	if (!(dev_cg->default_groups))
		goto out;
	/*
	 * Set se_dev_su_ptr from se_subsystem_api_t returned void ptr
	 * for ->allocate_virtdevice()
	 *
	 * se_dev->se_dev_ptr will be set after ->create_virtdev()
	 * has been called successfully in the next level up in the
	 * configfs tree for device object's struct config_group.  This
	 * pointer is set in target_core_store_dev_fd() and
	 * target_core_store_dev_enable() above depending upon the
	 * reference method for struct scsi_device.
	 */
	se_dev->se_dev_su_ptr = t->allocate_virtdevice(hba, name);
	if (!(se_dev->se_dev_su_ptr)) {
		printk(KERN_ERR "Unable to locate subsystem dependent pointer"
			" from allocate_virtdevice()\n");
		goto out;
	}
	spin_lock(&se_global->g_device_lock);
	list_add_tail(&se_dev->g_se_dev_list, &se_global->g_se_dev_list);
	spin_unlock(&se_global->g_device_lock);

	config_group_init_type_name(&se_dev->se_dev_group, name,
			&target_core_dev_cit);
	config_group_init_type_name(&se_dev->se_dev_attrib.da_group, "attrib",
			&target_core_dev_attrib_cit);
	config_group_init_type_name(&se_dev->se_dev_pr_group, "pr",
			&target_core_dev_pr_cit);
	config_group_init_type_name(&se_dev->se_dev_snap_group, "snap",
			&target_core_dev_snap_cit);
	config_group_init_type_name(&se_dev->t10_wwn.t10_wwn_group, "wwn",
			&target_core_dev_wwn_cit);
	config_group_init_type_name(&se_dev->t10_alua.alua_tg_pt_gps_group,
			"alua", &target_core_alua_tg_pt_gps_cit);
	dev_cg->default_groups[0] = &se_dev->se_dev_attrib.da_group;
	dev_cg->default_groups[1] = &se_dev->se_dev_pr_group;
	dev_cg->default_groups[2] = &se_dev->se_dev_snap_group;
	dev_cg->default_groups[3] = &se_dev->t10_wwn.t10_wwn_group;
	dev_cg->default_groups[4] = &se_dev->t10_alua.alua_tg_pt_gps_group;
	dev_cg->default_groups[5] = NULL;
	/*
	 * Add core/$HBA/$DEV/alua/tg_pt_gps/default_tg_pt_gp
	 */
	tg_pt_gp = core_alua_allocate_tg_pt_gp(se_dev, "default_tg_pt_gp", 1);
	if (!(tg_pt_gp))
		goto out;

	tg_pt_gp_cg = &T10_ALUA(se_dev)->alua_tg_pt_gps_group;
	tg_pt_gp_cg->default_groups = kzalloc(sizeof(struct config_group) * 2,
				GFP_KERNEL);
	if (!(tg_pt_gp_cg->default_groups)) {
		printk(KERN_ERR "Unable to allocate tg_pt_gp_cg->"
				"default_groups\n");
		goto out;
	}

	config_group_init_type_name(&tg_pt_gp->tg_pt_gp_group,
			"default_tg_pt_gp", &target_core_alua_tg_pt_gp_cit);
	tg_pt_gp_cg->default_groups[0] = &tg_pt_gp->tg_pt_gp_group;
	tg_pt_gp_cg->default_groups[1] = NULL;
	T10_ALUA(se_dev)->default_tg_pt_gp = tg_pt_gp;

	printk(KERN_INFO "Target_Core_ConfigFS: Allocated se_subsystem_dev_t:"
		" %p se_dev_su_ptr: %p\n", se_dev, se_dev->se_dev_su_ptr);

	core_put_hba(hba);
	return &se_dev->se_dev_group;
out:
	if (T10_ALUA(se_dev)->default_tg_pt_gp) {
		core_alua_free_tg_pt_gp(T10_ALUA(se_dev)->default_tg_pt_gp);
		T10_ALUA(se_dev)->default_tg_pt_gp = NULL;
        }
	if (tg_pt_gp_cg)
		kfree(tg_pt_gp_cg->default_groups);
	if (dev_cg)
		kfree(dev_cg->default_groups);
	if (se_dev->se_dev_su_ptr)
		t->free_device(se_dev->se_dev_su_ptr);
	kfree(se_dev);
	core_put_hba(hba);
	return NULL;
}

static void target_core_call_freedev(
	struct config_group *group,
	struct config_item *item)
{
	se_subsystem_dev_t *se_dev = container_of(to_config_group(item),
				se_subsystem_dev_t, se_dev_group);
	se_hba_t *hba;
	se_subsystem_api_t *t;
	struct config_item *df_item;
	struct config_group *dev_cg, *tg_pt_gp_cg;
	int i, ret = 0;

	hba = target_core_get_hba_from_item(
			&se_dev->se_dev_hba->hba_group.cg_item);
	t = plugin_get_obj(PLUGIN_TYPE_TRANSPORT, hba->type, &ret);

	spin_lock(&se_global->g_device_lock);
	list_del(&se_dev->g_se_dev_list);
	spin_unlock(&se_global->g_device_lock);

	tg_pt_gp_cg = &T10_ALUA(se_dev)->alua_tg_pt_gps_group;
	for (i = 0; tg_pt_gp_cg->default_groups[i]; i++) {
		df_item = &tg_pt_gp_cg->default_groups[i]->cg_item;
		tg_pt_gp_cg->default_groups[i] = NULL;
		config_item_put(df_item);
	}
	kfree(tg_pt_gp_cg->default_groups);
	/*
	 * core_alua_free_tg_pt_gp() is called from ->default_tg_pt_gp
	 * directly from target_core_alua_tg_pt_gp_release().
	 */
	T10_ALUA(se_dev)->default_tg_pt_gp = NULL;

	dev_cg = &se_dev->se_dev_group;
	for (i = 0; dev_cg->default_groups[i]; i++) {
		df_item = &dev_cg->default_groups[i]->cg_item;
		dev_cg->default_groups[i] = NULL;
		config_item_put(df_item);
	}

	config_item_put(item);
	core_put_hba(hba);
}

static struct configfs_group_operations target_core_hba_group_ops = {
	.make_group		= target_core_call_createdev,
	.drop_item		= target_core_call_freedev,
};

static ssize_t target_core_hba_show(struct config_item *item,
				struct configfs_attribute *attr,
				char *page)
{
	se_hba_t *hba = container_of(to_config_group(item), se_hba_t,
					hba_group);

	if (!(hba)) {
		printk(KERN_ERR "Unable to locate se_hba_t\n");
		return 0;
	}

	return sprintf(page, "HBA Index: %d plugin: %s version: %s\n",
			hba->hba_id, hba->transport->name,
			TARGET_CORE_CONFIGFS_VERSION);
}

static struct configfs_attribute target_core_hba_attr = {
	.ca_owner		= THIS_MODULE,
	.ca_name		= "hba_info",
	.ca_mode		= S_IRUGO,
};

static void target_core_hba_release(struct config_item *item)
{
	se_hba_t *hba = container_of(to_config_group(item),
				se_hba_t, hba_group);
	se_core_del_hba(hba);
}

static struct configfs_item_operations target_core_hba_item_ops = {
	.release		= target_core_hba_release,
	.show_attribute		= target_core_hba_show,
};

static struct configfs_attribute *target_core_hba_attrs[] = {
	&target_core_hba_attr,
	NULL,
};

static struct config_item_type target_core_hba_cit = {
	.ct_item_ops		= &target_core_hba_item_ops,
	.ct_group_ops		= &target_core_hba_group_ops,
	.ct_attrs		= target_core_hba_attrs,
	.ct_owner		= THIS_MODULE,
};

static struct config_group *target_core_call_addhbatotarget(
	struct config_group *group,
	const char *name)
{
	char *se_plugin_str, *str, *str2;
	se_hba_t *hba;
	se_plugin_t *se_plugin;
	char buf[TARGET_CORE_NAME_MAX_LEN];
	unsigned long plugin_dep_id = 0;
	int hba_type = 0, ret;

	memset(buf, 0, TARGET_CORE_NAME_MAX_LEN);
	if (strlen(name) > TARGET_CORE_NAME_MAX_LEN) {
		printk(KERN_ERR "Passed *name strlen(): %d exceeds"
			" TARGET_CORE_NAME_MAX_LEN: %d\n", (int)strlen(name),
			TARGET_CORE_NAME_MAX_LEN);
		return ERR_PTR(-ENAMETOOLONG);
	}
	snprintf(buf, TARGET_CORE_NAME_MAX_LEN, "%s", name);

	str = strstr(buf, "_");
	if (!(str)) {
		printk(KERN_ERR "Unable to locate \"_\" for $SUBSYSTEM_PLUGIN_$HOST_ID\n");
		return ERR_PTR(-EINVAL);
	}
	se_plugin_str = buf;
	/*
	 * Special case for subsystem plugins that have "_" in their names.
	 * Namely rd_direct and rd_mcp..
	 */
	str2 = strstr(str+1, "_");
	if ((str2)) {
		*str2 = '\0'; /* Terminate for *se_plugin_str */
		str2++; /* Skip to start of plugin dependent ID */
		str = str2;
	} else {
		*str = '\0'; /* Terminate for *se_plugin_str */
		str++; /* Skip to start of plugin dependent ID */
	}

	se_plugin = transport_core_get_plugin_by_name(se_plugin_str);
	if (!(se_plugin))
		return ERR_PTR(-EINVAL);

	hba_type = se_plugin->plugin_type;
	ret = tcm_strict_strtoul(str, 0, &plugin_dep_id);
	if (ret < 0) {
		printk(KERN_ERR "tcm_strict_strtoul() returned %d for"
				" plugin_dep_id\n", ret);
		return ERR_PTR(-EINVAL);
	}
	printk(KERN_INFO "Target_Core_ConfigFS: Located se_plugin: %p"
		" plugin_name: %s hba_type: %d plugin_dep_id: %lu\n",
		se_plugin, se_plugin->plugin_name, hba_type, plugin_dep_id);

	hba = core_alloc_hba(hba_type);
	if (!(hba))
		return ERR_PTR(-EINVAL);

	ret = se_core_add_hba(hba, (u32)plugin_dep_id);
	if (ret < 0)
		goto out;

	config_group_init_type_name(&hba->hba_group, name,
			&target_core_hba_cit);

	return &hba->hba_group;
out:
	kmem_cache_free(se_hba_cache, hba);
	return ERR_PTR(ret);
}


static void target_core_call_delhbafromtarget(
	struct config_group *group,
	struct config_item *item)
{
	/*
	 * core_delete_hba() is called from target_core_hba_item_ops->release()
	 * -> target_core_hba_release()
	 */
	config_item_put(item);
}

static struct configfs_group_operations target_core_group_ops = {
	.make_group	= target_core_call_addhbatotarget,
	.drop_item	= target_core_call_delhbafromtarget,
};

static struct config_item_type target_core_cit = {
	.ct_item_ops	= NULL,
	.ct_group_ops	= &target_core_group_ops,
	.ct_attrs	= NULL,
	.ct_owner	= THIS_MODULE,
};

/* Stop functions for struct config_item_type target_core_hba_cit */

int target_core_init_configfs(void)
{
	struct config_group *target_cg, *hba_cg = NULL, *alua_cg = NULL;
	struct config_group *lu_gp_cg = NULL;
	struct configfs_subsystem *subsys;
#ifdef SNMP_SUPPORT
	struct proc_dir_entry *scsi_target_proc;
#endif
	t10_alua_lu_gp_t *lu_gp;
	int ret;

	printk(KERN_INFO "TARGET_CORE[0]: Loading Generic Kernel Storage"
		" Engine: %s on %s/%s on "UTS_RELEASE"\n",
		TARGET_CORE_VERSION, TCM_UTS_SYSNAME, TCM_UTS_MACHINE);

	subsys = target_core_subsystem[0];
	config_group_init(&subsys->su_group);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	mutex_init(&subsys->su_mutex);
#else
	init_MUTEX(&subsys->su_sem);	
#endif

	INIT_LIST_HEAD(&g_tf_list);
	mutex_init(&g_tf_lock);
#ifdef SNMP_SUPPORT
	init_scsi_index_table();
#endif
	ret = init_se_global();
	if (ret < 0)
		return -1;
	/*
	 * Create $CONFIGFS/target/core default group for HBA <-> Storage Object
	 * and ALUA Logical Unit Group and Target Port Group infrastructure.
	 */
	target_cg = &subsys->su_group;
	target_cg->default_groups = kzalloc(sizeof(struct config_group) * 2,
				GFP_KERNEL);
	if (!(target_cg->default_groups)) {
		printk(KERN_ERR "Unable to allocate target_cg->default_groups\n");
		goto out_global;
	}

	config_group_init_type_name(&se_global->target_core_hbagroup,
			"core", &target_core_cit);
	target_cg->default_groups[0] = &se_global->target_core_hbagroup;
	target_cg->default_groups[1] = NULL;
	/*
	 * Create ALUA infrastructure under /sys/kernel/config/target/core/alua/
	 */
	hba_cg = &se_global->target_core_hbagroup;
	hba_cg->default_groups = kzalloc(sizeof(struct config_group) * 2,
				GFP_KERNEL);
	if (!(hba_cg->default_groups)) {
		printk(KERN_ERR "Unable to allocate hba_cg->default_groups\n");
		goto out_global;
	}

	config_group_init_type_name(&se_global->alua_group,
			"alua", &target_core_alua_cit);
	hba_cg->default_groups[0] = &se_global->alua_group;
	hba_cg->default_groups[1] = NULL;
	/*
	 * Add ALUA Logical Unit Group and Target Port Group ConfigFS
	 * groups under /sys/kernel/config/target/core/alua/
	 */
	alua_cg = &se_global->alua_group;
	alua_cg->default_groups = kzalloc(sizeof(struct config_group) * 2,
			GFP_KERNEL);
	if (!(alua_cg->default_groups)) {
		printk(KERN_ERR "Unable to allocate alua_cg->default_groups\n");
		goto out_global;
	}

	config_group_init_type_name(&se_global->alua_lu_gps_group,
			"lu_gps", &target_core_alua_lu_gps_cit);
	alua_cg->default_groups[0] = &se_global->alua_lu_gps_group;
	alua_cg->default_groups[1] = NULL;
	/*
	 * Add core/alua/lu_gps/default_lu_gp
	 */
	lu_gp = core_alua_allocate_lu_gp("default_lu_gp", 1);
	if (!(lu_gp))
		goto out_global;

	lu_gp_cg = &se_global->alua_lu_gps_group;
	lu_gp_cg->default_groups = kzalloc(sizeof(struct config_group) * 2,
			GFP_KERNEL);
	if (!(lu_gp_cg->default_groups)) {
		printk(KERN_ERR "Unable to allocate lu_gp_cg->default_groups\n");
		goto out_global;
	}

	config_group_init_type_name(&lu_gp->lu_gp_group, "default_lu_gp",
				&target_core_alua_lu_gp_cit);
	lu_gp_cg->default_groups[0] = &lu_gp->lu_gp_group;
	lu_gp_cg->default_groups[1] = NULL;
	se_global->default_lu_gp = lu_gp;
	/*
	 * Register the target_core_mod subsystem with configfs.
	 */
	ret = configfs_register_subsystem(subsys);
	if (ret < 0) {
		printk(KERN_ERR "Error %d while registering subsystem %s\n",
			ret, subsys->su_group.cg_item.ci_namebuf);
		goto out_global;
	}
	printk(KERN_INFO "TARGET_CORE[0]: Initialized ConfigFS Fabric"
		" Infrastructure: "TARGET_CORE_CONFIGFS_VERSION" on %s/%s"
		" on "UTS_RELEASE"\n", TCM_UTS_SYSNAME, TCM_UTS_MACHINE);

	plugin_load_all_classes();
	if (core_dev_setup_virtual_lun0() < 0)
		goto out;
#ifdef SNMP_SUPPORT
	scsi_target_proc = proc_mkdir("scsi_target", 0);
	if (!(scsi_target_proc)) {
		printk(KERN_ERR "proc_mkdir(scsi_target, 0) failed\n");
		goto out;
	}
	ret = init_scsi_target_mib();
	if (ret < 0)
		goto out;
#endif
	return 0;

out:
	configfs_unregister_subsystem(subsys);
#ifdef SNMP_SUPPORT
	remove_proc_entry("scsi_target", 0);
#endif
	core_dev_release_virtual_lun0();
	plugin_unload_all_classes();
out_global:
	if (se_global->default_lu_gp) {
		core_alua_free_lu_gp(se_global->default_lu_gp);
		se_global->default_lu_gp = NULL;
	}
	if (lu_gp_cg)
		kfree(lu_gp_cg->default_groups);
	if (alua_cg)
		kfree(alua_cg->default_groups);
	if (hba_cg)
		kfree(hba_cg->default_groups);
	kfree(target_cg->default_groups);
	release_se_global();
	return -1;
}

void target_core_exit_configfs(void)
{
	struct configfs_subsystem *subsys;
	struct config_group *hba_cg, *alua_cg, *lu_gp_cg;
	struct config_item *item;
	int i;

	se_global->in_shutdown = 1;
	subsys = target_core_subsystem[0];

	lu_gp_cg = &se_global->alua_lu_gps_group;
	for (i = 0; lu_gp_cg->default_groups[i]; i++) {
		item = &lu_gp_cg->default_groups[i]->cg_item;
		lu_gp_cg->default_groups[i] = NULL;
		config_item_put(item);
	}
	kfree(lu_gp_cg->default_groups);
	lu_gp_cg->default_groups = NULL;

	alua_cg = &se_global->alua_group;
	for (i = 0; alua_cg->default_groups[i]; i++) {
		item = &alua_cg->default_groups[i]->cg_item;
		alua_cg->default_groups[i] = NULL;
		config_item_put(item);
	}
	kfree(alua_cg->default_groups);
	alua_cg->default_groups = NULL;

	hba_cg = &se_global->target_core_hbagroup;
	for (i = 0; hba_cg->default_groups[i]; i++) {
		item = &hba_cg->default_groups[i]->cg_item;
		hba_cg->default_groups[i] = NULL;
		config_item_put(item);
	}
	kfree(hba_cg->default_groups);
	hba_cg->default_groups = NULL;
	/*
	 * We expect subsys->su_group.default_groups to be released
	 * by configfs subsystem provider logic..
	 */
	configfs_unregister_subsystem(subsys);
	kfree(subsys->su_group.default_groups);

	core_alua_free_lu_gp(se_global->default_lu_gp);
	se_global->default_lu_gp = NULL;

	printk(KERN_INFO "TARGET_CORE[0]: Released ConfigFS Fabric"
			" Infrastructure\n");
#ifdef SNMP_SUPPORT
	remove_scsi_target_mib();
	remove_proc_entry("scsi_target", 0);
#endif
	core_dev_release_virtual_lun0();
	plugin_unload_all_classes();
	release_se_global();

	return;
}

MODULE_DESCRIPTION("Target_Core_Mod/ConfigFS");
MODULE_AUTHOR("nab@Linux-iSCSI.org");
MODULE_LICENSE("GPL");

module_init(target_core_init_configfs);
module_exit(target_core_exit_configfs);
