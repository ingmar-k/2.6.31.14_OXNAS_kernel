/*
 * Copyright (c) 2010 Cloud Engines, Inc.
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * Boot LED control
 */

#include <linux/io.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <mach/bootled.h>
#include <mach/hardware.h>


#define BOOTLED_TRANSITION_JIFFIES	(HZ/12)


static void bootled_off(void);
static void bootled_on(void);
static void bootled_timer_func(unsigned long state);


static struct timer_list bootled_timer =
	TIMER_INITIALIZER(&bootled_timer_func, 0, 0);


static void bootled_off(void)
{
	writel(0x00020000, GPIO_B_OUTPUT_SET);
}

static void bootled_on(void)
{
	writel(0x00020000, GPIO_B_OUTPUT_CLEAR);
}

void bootled_start(void)
{
	writel(0x00020000, GPIO_B_OUTPUT_ENABLE_SET);

	bootled_timer_func(0);
}

void bootled_stop(void)
{
	(void)del_timer_sync(&bootled_timer);

	bootled_off();
}
EXPORT_SYMBOL(bootled_stop);

static void bootled_timer_func(unsigned long ison)
{
	if (ison != 0) {
		bootled_off();
		ison = 0;
	} else {
		bootled_on();
		ison = 1;
	}

	bootled_timer.expires = jiffies + BOOTLED_TRANSITION_JIFFIES;
	bootled_timer.data = ison;
	add_timer(&bootled_timer);
}
