#define STOP 	0
#define START	1

#define SATA_HD_DEAD		0
#define SATA_HD_ALIVE		1

#define SATA_HD_NO_ACTIVE       0
#define SATA_HD_ACTIVE   	1
#define SATA_HD_STANDBY_1	2
#define SATA_HD_STANDBY_2	3

#define MAX_HD_NUM		2

static struct timer_list pm_timer;
static DECLARE_WORK(sd_work, NULL);

static struct workqueue_struct *sd_work_queue;

//MAX_HD_NUM can not exceed 26 (a ~ z)
//char hd_name[MAX_HD_NUM];

atomic_t  hd_name[MAX_HD_NUM];
atomic_t  SATA_hd_read_write[MAX_HD_NUM];
atomic_t  SATA_State_Counter[MAX_HD_NUM];

static int SATA_HD_LIVE[MAX_HD_NUM];

struct device* sdisk_gendev[MAX_HD_NUM];

int	timer_period = 60;
static int suspend_time_counter;

static int disk_suspdtime_read_fn(char *buf, char **start, off_t offset,
                int count, int *eof, void *data);

static int disk_suspdtime_write_fn(struct file *file, const char __user *buffer,
                unsigned long count, void *data);

static void hd_scan(void)
{
	struct device *dev;
	struct gendisk *sgp = NULL;
	struct class_dev_iter iter;
	int	i, is_find = 0, new_pos = -1;

	for(i = 0 ; i < MAX_HD_NUM ; i++)
		SATA_HD_LIVE[i] = SATA_HD_DEAD;

	mutex_lock(&block_class_lock);
	class_dev_iter_init(&iter, &block_class, NULL, &disk_type);

	while ((dev = class_dev_iter_next(&iter)))
	{
		sgp = dev_to_disk(dev);
		if(sgp == NULL) continue;

		if(strncmp(sgp->disk_name, "sd", 2) == 0)
		{
			struct scsi_disk *sdkp;
			struct device *dev;
			struct Scsi_Host *shst;

			sdkp = scsi_disk_get(sgp);
			dev = &(sdkp->device->sdev_gendev);
			shst = dev_to_shost(dev);

			is_find = 0;
			new_pos = -1;

			if(strncmp(shst->hostt->name, "oxnas", 5) == 0)
			{
				for(i = 0 ; i < MAX_HD_NUM ; i++)
				{
					if(sdisk_gendev[i] == dev)
					{
						is_find = 1;
						SATA_HD_LIVE[i] =  SATA_HD_ALIVE;
						//printk(KERN_ERR"find disk at %d\n", i);
						break;
					}
					else if(new_pos == -1 && sdisk_gendev[i] == NULL)
					{
						//printk(KERN_ERR"new_pos = %d, %d\n", new_pos, i);
						new_pos = i;
					}
					else;
					//if(sdisk[i] == NULL)
					//{
					//	sdisk[i] = sdkp;
				//		hd_name[i] = sgp->disk_name[2];
				//	}
				}

				if(!is_find && new_pos != -1)
				{
					//printk(KERN_ERR"Assign %s to HD%d\n", sgp->disk_name, new_pos);
					sdisk_gendev[new_pos] = dev;
					atomic_set(&hd_name[new_pos], sgp->disk_name[2]);
					SATA_HD_LIVE[new_pos] = SATA_HD_ALIVE;
					new_pos = -1;
				}
			}
		}
	}

	class_dev_iter_exit(&iter);
	mutex_unlock(&block_class_lock);

	for(i = 0 ; i < MAX_HD_NUM ; i++)
	{
		if(SATA_HD_LIVE[i] == SATA_HD_DEAD)
			sdisk_gendev[i] = NULL;

		SATA_HD_LIVE[i] = SATA_HD_DEAD;
	}
}


static void scsi_disk_suspend(int hd_num)				//(struct scsi_disk *sdkp)
{
	int	i, ret = 0;

	i = hd_num;

	if(atomic_read(&SATA_hd_read_write[i]) == SATA_HD_STANDBY_1)
	{
		struct scsi_disk* sdkp;

		atomic_set(&SATA_hd_read_write[i], SATA_HD_STANDBY_2);
		sdkp = scsi_disk_get_from_dev(sdisk_gendev[i]);

		if(sdkp->WCE)
			ret = sd_sync_cache(sdkp);

		if(!ret)
			sd_start_stop_device(sdkp, 0);

		scsi_disk_put(sdkp);
	}
}

static void sd_monitor_timer_work(struct work_struct *in)
{
	int i;

	hd_scan();

	for(i = 0 ; i < MAX_HD_NUM ; i++)
	{
		if(sdisk_gendev[i] == NULL) continue;

		//printk(KERN_ERR"sd%c: status %d\n", atomic_read(&hd_name[i]), atomic_read(&SATA_hd_read_write[i]));
		switch(atomic_read(&SATA_hd_read_write[i]))
		{
			case SATA_HD_NO_ACTIVE:
				if(atomic_read(&SATA_State_Counter[i]) == suspend_time_counter)
				{
					atomic_set(&SATA_hd_read_write[i], SATA_HD_STANDBY_1);
					printk("*********************************************\n");
					printk("*		HD:sd%c standby now	    *\n", atomic_read(&hd_name[i]));
					printk("*********************************************\n");
					scsi_disk_suspend(i);
				}
				else
				{
					//printk("HD%d: sd%c, conuter %d\n",i , atomic_read(&hd_name[i]),
					//	atomic_read(&SATA_State_Counter[i]));
					atomic_inc(&SATA_State_Counter[i]);
				}
				break;
			case SATA_HD_ACTIVE:
				atomic_set(&SATA_hd_read_write[i], SATA_HD_NO_ACTIVE);
				atomic_set(&SATA_State_Counter[i], 1);
				break;
			default:
				break;
		}
	}
}

static void sd_monitor_timer_func(unsigned long in_data)
{
	PREPARE_WORK(&sd_work, sd_monitor_timer_work);
	queue_work(sd_work_queue, &sd_work);

	pm_timer.function = (void* )sd_monitor_timer_func;
	pm_timer.data = 0;
	mod_timer(&pm_timer, jiffies + HZ * timer_period);
}

int sd_enable_power_saving(unsigned long PowerSavingTime)
{
	int	i;

	//printk(KERN_ERR"Enter %s\n", __FUNCTION__);
	for(i = 0 ; i < MAX_HD_NUM ; i++)
	{
		atomic_set(&SATA_hd_read_write[i], SATA_HD_NO_ACTIVE);
		atomic_set(&SATA_State_Counter[i], 0);
		sdisk_gendev[i] = NULL;
	}

	if(PowerSavingTime > 0)
		suspend_time_counter = PowerSavingTime;


//	sd_work_queue = create_workqueue("sd_wq");
//	init_timer(&pm_timer);
	pm_timer.function = (void *)sd_monitor_timer_func;
	mod_timer(&pm_timer, jiffies + HZ * timer_period);

	//printk(KERN_ERR"Leave %s\n", __FUNCTION__);
	return 0;
}


void sd_disable_power_saving(void)
{
	int	i;

	if(timer_pending(&pm_timer))
		del_timer(&pm_timer);

	for(i = 0 ; i < MAX_HD_NUM ; i++)
	{
		atomic_set(&SATA_hd_read_write[i], SATA_HD_NO_ACTIVE);
		atomic_set(&SATA_State_Counter[i], 0);
	}

}

void  sd_init_power_saving(void)
{
	struct proc_dir_entry	*p;

	init_timer(&pm_timer);
	sd_work_queue = create_workqueue("sd_wq");

	p = create_proc_entry("d_suspdtime", 0, NULL);
	p->read_proc = disk_suspdtime_read_fn;
	p->write_proc = disk_suspdtime_write_fn;

}

void sd_exit_power_saving(void)
{
	if(timer_pending(&pm_timer))
		del_timer(&pm_timer);

	remove_proc_entry("d_suspdtime", NULL);
}

static int disk_suspdtime_read_fn(char *buf, char **start, off_t offset,
		int count, int *eof, void *data)
{
	unsigned short time_to_power_save_mins;
	int     len= 0, limit = count - 80, i ;
	int	SATA_Status[2] ;

	time_to_power_save_mins = suspend_time_counter;
	hd_scan();

	for(i = 0 ; i < MAX_HD_NUM ; i++)
	{
		if(sdisk_gendev[i] == NULL)
			SATA_Status[i] = -1;
		else
			SATA_Status[i] = atomic_read(&SATA_hd_read_write[i]);
	}

	len += sprintf(buf, "%d\n", time_to_power_save_mins);
	buf = buf + len;

	for(i = 0 ; i < MAX_HD_NUM ; i++)
	{
		int	 len1;

		if(SATA_Status[i] != -1)
			//len1 = sprintf(buf, "Disk sd%c: No_Disk\n", atomic_read(&hd_name[i]));
		{
			//#define SATA_HD_NO_ACTIVE       0
			//#define SATA_HD_ACTIVE          1
			//#define SATA_HD_STANDBY_1       2
			//#define SATA_HD_STANDBY_2       3

			if(SATA_Status[i] == SATA_HD_NO_ACTIVE)
				len1 = sprintf(buf, "Disk sd%c: NO_ACTIVE\n", atomic_read(&hd_name[i]));
			else if(SATA_Status[i] == SATA_HD_ACTIVE)
				len1 = sprintf(buf, "Disk sd%c: ACTIVE\n", atomic_read(&hd_name[i]));
			else if(SATA_Status[i] == SATA_HD_STANDBY_1)
				len1 = sprintf(buf, "Disk sd%c: STANDBY\n", atomic_read(&hd_name[i]));
			else if(SATA_Status[i] == SATA_HD_STANDBY_2)
				len1 = sprintf(buf, "Disk sd%c: STANDBY\n", atomic_read(&hd_name[i]));
			else
				 len1 = sprintf(buf, "Disk%c: Unknown\n",  atomic_read(&hd_name[i]));

			len += len1;
			buf += len1;

		}
	}


	if(len > limit) printk(KERN_ERR"Out of page buf\n");


	*eof = 1;

	return len;
}


static int disk_suspdtime_write_fn(struct file *file, const char __user *buffer,
		unsigned long count, void *data)
{
	char    my_buf[50], sd_name;
	int     i, value1 = 0, access_case = 1;

	if(count > 50)
	{
		printk(KERN_ERR"Fail to write to proc.\n");
		return -EFAULT;
	}

	copy_from_user(my_buf, buffer, count);


	for(i = 0 ; i < count ; i++)
	{
		if(my_buf[i] >= 'a' && my_buf[i] <= 'z')
		{
			access_case = 2;
			sd_name = my_buf[i];
			break;
		}
		else if(my_buf[i] >= '0' && my_buf[i] <= '9')
			value1 = value1 * 10 + (my_buf[i] - '0');
		else;
	}

	if(access_case == 1)
	{
		if(value1 == 0)
		{
			sd_disable_power_saving();
			suspend_time_counter = 0;
		}
		else
		{
			sd_disable_power_saving();
			suspend_time_counter = 0;
			sd_enable_power_saving(value1);
		}
	}
	else
	{
		for(i = 0 ; i < MAX_HD_NUM ; i++)
		{
			struct scsi_disk* sdkp;
			int	ret = 0;

			if(atomic_read(&hd_name[i]) == sd_name)
			{
				atomic_set(&SATA_hd_read_write[i], SATA_HD_STANDBY_2);
				sdkp = scsi_disk_get_from_dev(sdisk_gendev[i]);

				if(!sdkp) continue;

				if(sdkp->WCE)
					ret = sd_sync_cache(sdkp);

				if(!ret)
					sd_start_stop_device(sdkp, 0);
				scsi_disk_put(sdkp);

			}
		}
	}

	return count;
}


