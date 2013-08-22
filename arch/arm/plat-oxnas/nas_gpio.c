/*
 * linux/arch/arm/mach-oxnas/nas_gpio.c
 *
 */
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/timer.h>
#include <linux/kobject.h>
#include <linux/workqueue.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/cdev.h>
//#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <mach/hardware.h>
#include <asm/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/delay.h>

#include "nas_gpio.h"


#define DRIVER_NAME	"MitraStar NAS GPIO driver/controller"
#define DRIVER_VERSION	"1.00"

MODULE_AUTHOR("Raymond Tseng <Raymond.Tseng@zyxel.com.tw>");
MODULE_DESCRIPTION(DRIVER_NAME);
MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");



#if defined(CONFIG_ZyXEL_STG100R1)
static int Model = MODEL_STG100R1;
#elif defined(CONFIG_ZyXEL_STG100R2)
static int Model = MODEL_STG100R2;
#elif defined(CONFIG_ZyXEL_STG100R3)
static int Model = MODEL_STG100R3;
#elif defined(CONFIG_ZyXEL_STG211R1)
static int Model = MODEL_STG211R1;
#elif defined(CONFIG_ZyXEL_STG211R2)
static int Model = MODEL_STG211R2;
#elif defined(CONFIG_ZyXEL_STG212)
static int Model = MODEL_STG212;
#else
static int Model = MODEL_UNKNOWN;
#endif


struct _btn Btn[] = {
#if defined(CONFIG_ZyXEL_STG100R1)
	{
		id:		BTN_OK,
		name:		"OK Button",
		gpio:		6,
		mask:		(1UL << 6),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	ok_button_irq_handler,
		timer:		{
					data:		0,
					function:	ok_button_timer_handler,
				},
	},
	{
		id:		BTN_SELECT,
		name:		"Select Button",
		gpio:		5,
		mask:		(1UL << 5),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	select_button_irq_handler,
		timer:		{
					data:		0,
					function:	select_button_timer_handler,
				},
	},
	{
		id:		BTN_RESET,
		name:		"Reset Button",
		gpio:		5,
		mask:		(1UL << 5),
		irq:		GPIOA_INTERRUPT,
		reg_irq_event:	GPIO_A_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_A_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_A_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_A_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_A_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	reset_button_irq_handler,
		timer:		{
					data:		0,
					function:	reset_button_timer_handler,
				},
	},
	{
		id:		BTN_EJECT,
		name:		"Eject Button",
		gpio:		8,
		mask:		(1UL << 8),
		irq:		GPIOA_INTERRUPT,
		reg_irq_event:	GPIO_A_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_A_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_A_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_A_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_A_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	eject_button_irq_handler,
		timer:		{
					data:		0,
					function:	eject_button_timer_handler,
				},
	},
#elif defined(CONFIG_ZyXEL_STG100R2)
	{
		id:		BTN_COPY,
		name:		"Copy Button",
		gpio:		5,
		mask:		(1UL << 5),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	copy_button_irq_handler,
		timer:		{
					data:		0,
					function:	copy_button_timer_handler,
				},
	},
	{
		id:		BTN_RESET,
		name:		"Reset Button",
		gpio:		5,
		mask:		(1UL << 5),
		irq:		GPIOA_INTERRUPT,
		reg_irq_event:	GPIO_A_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_A_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_A_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_A_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_A_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	reset_button_irq_handler,
		timer:		{
					data:		0,
					function:	traditional_reset_button_timer_handler,
				},
	},
#elif defined(CONFIG_ZyXEL_STG100R3)
	{
		id:		BTN_COPY,
		name:		"Copy Button",
		gpio:		5,
		mask:		(1UL << 5),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	copy_button_irq_handler,
		timer:		{
					data:		0,
					function:	copy_button_timer_handler,
				},
	},
	{
		id:		BTN_RESET,
		name:		"Reset Button",
		gpio:		5,
		mask:		(1UL << 5),
		irq:		GPIOA_INTERRUPT,
		reg_irq_event:	GPIO_A_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_A_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_A_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_A_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_A_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	reset_button_irq_handler,
		timer:		{
					data:		0,
					function:	traditional_reset_button_timer_handler,
				},
	},
	{
		id:		BTN_EJECT_FRONT,
		name:		"Front Eject Button",
		gpio:		6,
		mask:		(1UL << 6),
		irq:		GPIOA_INTERRUPT,
		reg_irq_event:	GPIO_A_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_A_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_A_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_A_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_A_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	front_eject_button_irq_handler,
		timer:		{
					data:		0,
					function:	front_eject_button_timer_handler,
				},
	},
	{
		id:		BTN_EJECT_REAR,
		name:		"Rear Eject Button",
		gpio:		25,
		mask:		(1UL << 25),
		irq:		GPIOA_INTERRUPT,
		reg_irq_event:	GPIO_A_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_A_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_A_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_A_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_A_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	rear_eject_button_irq_handler,
		timer:		{
					data:		0,
					function:	rear_eject_button_timer_handler,
				},
	},
#elif defined(CONFIG_ZyXEL_STG211)
	{
		id:		BTN_POWER,
		name:		"Power Button",
		gpio:		8,
		mask:		(1UL << 8),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_RISING_EDGE_ACTIVE_HIGH_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		HIGH_ACTIVE,
		irq_handler:	power_button_irq_handler,
		timer:		{
					data:		0,
					function:	power_button_timer_handler,
				},
	},
	{
		id:		BTN_COPY,
		name:		"Copy Button",
		gpio:		6,
		mask:		(1UL << 6),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	copy_button_irq_handler,
		timer:		{
					data:		0,
					function:	copy_button_timer_handler,
				},
	},
	{
		id:		BTN_RESET,
		name:		"Reset Button",
		gpio:		5,
		mask:		(1UL << 5),
		irq:		GPIOA_INTERRUPT,
		reg_irq_event:	GPIO_A_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_A_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_A_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_A_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_A_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	reset_button_irq_handler,
		timer:		{
					data:		0,
					function:	traditional_reset_button_timer_handler,
				},
	},
#elif defined(CONFIG_ZyXEL_STG212)
	{
		id:		BTN_COPY,
		name:		"Copy Button",
		gpio:		13,
		mask:		(1UL << 13),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	copy_button_irq_handler,
		timer:		{
					data:		0,
					function:	copy_button_timer_handler,
				},
	},
	{
		id:		BTN_RESET,
		name:		"Reset Button",
		gpio:		11,
		mask:		(1UL << 11),
		irq:		GPIOB_INTERRUPT,
		reg_irq_event:	GPIO_B_INTERRUPT_EVENT,
		reg_oe_clear:	GPIO_B_OUTPUT_ENABLE_CLEAR,
		reg_debounce:	GPIO_B_INPUT_DEBOUNCE_ENABLE,
		reg_irq_enable:	GPIO_B_FALLING_EDGE_ACTIVE_LOW_ENABLE,
		reg_data:	GPIO_B_DATA,
		active:		LOW_ACTIVE,
		irq_handler:	reset_button_irq_handler,
		timer:		{
					data:		0,
					function:	traditional_reset_button_timer_handler,
				},
	},
#endif
};
int num_btns = sizeof(Btn) / sizeof(struct _btn);




struct _led_set LED_SET[LED_TOTAL] = {
#if defined(CONFIG_ZyXEL_STG211)
	[LED_SYS] = {
		.presence = 1,					/* SYS LED exists. */
		.id = LED_SYS,
		.name = "SYS LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,				/* SYS LED contains red LED. */
			.gpio = 25,
			.mask = (1 << 25),
			.color = RED,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 26,
			.mask = (1 << 26),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_HDD] = {
		.presence = 1,
		.id = LED_HDD,
		.name = "HDD LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,
			.gpio = 6,
			.mask = (1 << 6),
			.color = RED,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 5,
			.mask = (1 << 5),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_USB] = {
		.presence = 1,
		.id = LED_USB,
		.name = "USB LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,
			.gpio = 8,
			.mask = (1 << 8),
			.color = RED,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 29,
			.mask = (1 << 29),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_ESATA] = {
		.presence = 1,
		.id = LED_ESATA,
		.name = "eSATA LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,
			.gpio = 14,
			.mask = (1 << 14),
			.color = RED,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 13,
			.mask = (1 << 13),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_COPY] = {
		.presence = 1,
		.id = LED_COPY,
		.name = "Copy LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,
			.gpio = 28,
			.mask = (1 << 28),
			.color = RED,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 27,
			.mask = (1 << 27),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_LAN] = {
		.presence = 1,
		.id = LED_LAN,
		.name = "LAN LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 9,
			.mask = (1 << 9),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_YELLOW] = {
			.presence = 1,
			.gpio = 10,
			.mask = (1 << 10),
			.color = YELLOW,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
#elif defined(CONFIG_ZyXEL_STG100R1)
	[LED_LAN] = {
		.presence = 1,
		.id = LED_LAN,
		.name = "LAN LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 9,
			.mask = (1 << 9),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_YELLOW] = {
			.presence = 1,
			.gpio = 10,
			.mask = (1 << 10),
			.color = YELLOW,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
#elif defined(CONFIG_ZyXEL_STG100R2)
	[LED_SYS] = {
		.presence = 1,					/* SYS LED exists. */
		.id = LED_SYS,
		.name = "SYS LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,				/* SYS LED contains red LED. */
			.gpio = 2,
			.mask = (1 << 2),
			.color = RED,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 1,
			.mask = (1 << 1),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_COPY] = {
		.presence = 1,
		.id = LED_COPY,
		.name = "Copy LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,
			.gpio = 4,
			.mask = (1 << 4),
			.color = RED,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 3,
			.mask = (1 << 3),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
#elif defined(CONFIG_ZyXEL_STG100R3)
	[LED_SYS] = {
		.presence = 1,					/* SYS LED exists. */
		.id = LED_SYS,
		.name = "SYS LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,				/* SYS LED contains red LED. */
			.gpio = 2,
			.mask = (1 << 2),
			.color = RED,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 1,
			.mask = (1 << 1),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_COPY] = {
		.presence = 1,
		.id = LED_COPY,
		.name = "Copy LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,
			.gpio = 4,
			.mask = (1 << 4),
			.color = RED,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 3,
			.mask = (1 << 3),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_USB] = {
		.presence = 1,
		.id = LED_USB,
		.name = "USB LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_BLUE] = {
			.presence = 1,
			.gpio = 26,
			.mask = (1 << 26),
			.color = BLUE,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_EJECT_READY] = {
		.presence = 1,
		.id = LED_EJECT_READY,
		.name = "Eject Ready LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 2,
			.mask = (1 << 2),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_QUOTA_1] = {
		.presence = 1,
		.id = LED_QUOTA_1,
		.name = "Quota 1 LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 1,
			.mask = (1 << 1),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_QUOTA_2] = {
		.presence = 1,
		.id = LED_QUOTA_2,
		.name = "Quota 2 LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 11,
			.mask = (1 << 11),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_QUOTA_3] = {
		.presence = 1,
		.id = LED_QUOTA_3,
		.name = "Quota 3 LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 27,
			.mask = (1 << 27),
			.color = GREEN,
			.reg_oe_set = GPIO_A_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_A_OUTPUT_SET,
			.reg_output_clear = GPIO_A_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
	[LED_QUOTA_4] = {
		.presence = 1,
		.id = LED_QUOTA_4,
		.name = "Quota 4 LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 0,
			.mask = (1 << 0),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
	},
#elif defined(CONFIG_ZyXEL_STG212)
	[LED_SYS] = {
		.presence = 1,					/* SYS LED exists. */
		.id = LED_SYS,
		.name = "SYS LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_BLUE] = {
			.presence = 1,				/* SYS LED contains red LED. */
			.gpio = 5,
			.mask = (1 << 5),
			.color = BLUE,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = HIGH_ACTIVE,
		},
		.led[LED_RED] = {
			.presence = 1,				/* SYS LED contains red LED. */
			.gpio = 6,
			.mask = (1 << 6),
			.color = RED,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = LOW_ACTIVE,
		},
	},
	[LED_COPY] = {
		.presence = 1,
		.id = LED_COPY,
		.name = "COPY LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_GREEN] = {
			.presence = 1,
			.gpio = 8,
			.mask = (1 << 8),
			.color = GREEN,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = LOW_ACTIVE,
		},
	},
	[LED_QUOTA_4] = {
		.presence = 1,
		.id = LED_QUOTA_4,
		.name = "Quota 4 LED",
		.lock = SPIN_LOCK_UNLOCKED,
		.timer = {
			.data = 0,
			.function = led_timer_handler,
		},
		.led[LED_RED] = {
			.presence = 1,
			.gpio = 6,
			.mask = (1 << 6),
			.color = RED,
			.reg_oe_set = GPIO_B_OUTPUT_ENABLE_SET,
			.reg_output_set = GPIO_B_OUTPUT_SET,
			.reg_output_clear = GPIO_B_OUTPUT_CLEAR,
			.active = LOW_ACTIVE,
		},
	},
#endif
};



/* Allow to run poweroff, shutdown, reboot. */
static atomic_t shutdown_enable_flag = ATOMIC_INIT(1);

/* for HTP test */
static atomic_t button_test_enable = ATOMIC_INIT(0);
static atomic_t button_test_num = ATOMIC_INIT(BUTTON_NUM);



struct cdev *lcd_cdev;
dev_t   lcd_dev  = 0;
static int lcd_nr_devs = 1;
static int lcdproc_pid = 0;		/* PID of lcdproc */
static int btn_pressed = BTN_NONE;	/* pressed button ID */


static int btncpy_pid = 0;		/* PID of do_btncpy */


extern spinlock_t oxnas_gpio_spinlock;


struct workqueue_struct *btn_workqueue;

static DECLARE_WORK(LCDButton, NULL);
static DECLARE_WORK(SoftPowerOff, NULL);
static DECLARE_WORK(ResetUserInfo, NULL);
static DECLARE_WORK(OpenBackdoor, NULL);
static DECLARE_WORK(ResetToDefault, NULL);
static DECLARE_WORK(DoCopy, NULL);
static DECLARE_WORK(DoSync, NULL);
static DECLARE_WORK(FrontEject, NULL);
static DECLARE_WORK(RearEject, NULL);

/* for HTP test */
static DECLARE_WORK(HTPTest, NULL);


////////////////////////////////////////////////////////////////////////////////

static struct proc_dir_entry  *nas_model_entry;

static int nas_model_read(char *buf, char **start, off_t offset, int count, int *eof, void *data)
{
	int len;

	switch (Model) {
	case MODEL_STG100R1:
		len = sprintf(buf, "STG100R1\n");
		break;

	case MODEL_STG100R2:
		len = sprintf(buf, "STG100R2\n");
		break;

	case MODEL_STG100R3:
		len = sprintf(buf, "STG100R3\n");
		break;

	case MODEL_STG211R1:
		len = sprintf(buf, "STG211R1\n");
		break;

	case MODEL_STG211R2:
		len = sprintf(buf, "STG211R2\n");
		break;

	case MODEL_STG212:
		len = sprintf(buf, "STG212\n");
		break;

	default:
		len = sprintf(buf, "Unknown\n");
		break;
	}

	*eof = 1;

	return len;
}

////////////////////////////////////////////////////////////////////////////////

/* Internal use; set bit only. */
void _turn_on_led(unsigned int id, unsigned int color)
{
	unsigned long flags;
	int i;

	/* System does not have LED_SET[id] */
	if (LED_SET[id].presence == 0) return;

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	for (i = 0; i < LED_COLOR_TOTAL; i++) {

		if ((color & LED_SET[id].led[i].color) && (LED_SET[id].led[i].presence != 0)) {
			if (LED_SET[id].led[i].active == HIGH_ACTIVE) {
				writel(LED_SET[id].led[i].mask, LED_SET[id].led[i].reg_output_set);
			} else if (LED_SET[id].led[i].active == LOW_ACTIVE) {
				writel(LED_SET[id].led[i].mask, LED_SET[id].led[i].reg_output_clear);
			}
		}

	}

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);
}

/* Internal use: set bit only. */
void _turn_off_led(unsigned int id, unsigned int color)
{
	unsigned long flags;
	int i;

	/* System does not have LED_SET[id] */
	if (LED_SET[id].presence == 0) return;

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	for (i = 0; i < LED_COLOR_TOTAL; i++) {

		if ((color & LED_SET[id].led[i].color) && (LED_SET[id].led[i].presence != 0)) {

			if (LED_SET[id].led[i].active == HIGH_ACTIVE) {
				writel(LED_SET[id].led[i].mask, LED_SET[id].led[i].reg_output_clear);
			} else if (LED_SET[id].led[i].active == LOW_ACTIVE) {
				writel(LED_SET[id].led[i].mask, LED_SET[id].led[i].reg_output_set);
			}
		}

	}

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);
}

/* Internal use; set bit only. */
void _turn_off_led_all(unsigned int id)
{
	unsigned long flags;
	int i;

	/* System does not have LED_SET[id] */
	if (LED_SET[id].presence == 0) return;

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if (LED_SET[id].led[i].presence == 0) continue;

		if (LED_SET[id].led[i].active == HIGH_ACTIVE) {
			writel(LED_SET[id].led[i].mask, LED_SET[id].led[i].reg_output_clear);
		} else if (LED_SET[id].led[i].active == LOW_ACTIVE) {
			writel(LED_SET[id].led[i].mask, LED_SET[id].led[i].reg_output_set);
		}

		LED_SET[id].led[i].state = LED_OFF;
	}

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);
}


void turn_on_led(unsigned int id, unsigned int color)
{
	int i;

	/* System does not have LED_SET[id] */
	if (LED_SET[id].presence == 0) return;

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if ((color & LED_SET[id].led[i].color) && (LED_SET[id].led[i].presence != 0)) {
			LED_SET[id].led[i].state = LED_ON;
		}
	}

	_turn_on_led(id, color);
}

void turn_off_led(unsigned int id, unsigned int color)
{
	int i;

	/* System does not have LED_SET[id] */
	if (LED_SET[id].presence == 0) return;

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if ((color & LED_SET[id].led[i].color) && (LED_SET[id].led[i].presence != 0)) {
			LED_SET[id].led[i].state = LED_OFF;
		}
	}

	_turn_off_led(id, color);
}

void turn_off_led_all(unsigned int id)
{
	int i;

	/* System does not have LED_SET[id] */
	if (LED_SET[id].presence == 0) return;

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if (LED_SET[id].led[i].presence == 0) continue;

		LED_SET[id].led[i].state = LED_OFF;
	}

	_turn_off_led_all(id);
}

void led_blink_start(unsigned int id, unsigned int color, unsigned int state)
{
	int i;

	if (LED_SET[id].presence == 0) return;
	if ((state != LED_BLINK_SLOW) && (state != LED_BLINK_FAST)) return;

	spin_lock(&(LED_SET[id].lock));

	if (LED_SET[id].timer_state == TIMER_RUNNING) {
		/* Maybe there is already a timer running, restart one. */
		LED_SET[id].timer_state = TIMER_SLEEPING;
		del_timer(&(LED_SET[id].timer));
	}

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if ((color & LED_SET[id].led[i].color) && (LED_SET[id].led[i].presence != 0)) {
			LED_SET[id].led[i].state = state;
		}
	}

	LED_SET[id].timer_state = TIMER_RUNNING;

	if (state == LED_BLINK_FAST)
		mod_timer(&LED_SET[id].timer, jiffies + JIFFIES_BLINK_FAST);
	else if (state == LED_BLINK_SLOW)
		mod_timer(&LED_SET[id].timer, jiffies + JIFFIES_BLINK_SLOW);

	spin_unlock(&(LED_SET[id].lock));
}

void led_blink_stop(unsigned int id)
{
	int i;

	if (LED_SET[id].presence == 0) return;

	spin_lock(&(LED_SET[id].lock));

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if (LED_SET[id].led[i].presence == 0) continue;

		LED_SET[id].led[i].state = LED_OFF;
	}

	if (LED_SET[id].timer_state == TIMER_RUNNING) {
		del_timer(&(LED_SET[id].timer));
	}
	LED_SET[id].timer_state = TIMER_SLEEPING;

	spin_unlock(&(LED_SET[id].lock));
}

/* all LED_SET[] timer handler for blinking */
static void led_timer_handler(unsigned long data)
{
	struct _led_set *led_set = (struct _led_set*) data;
	int state = LED_BLINK_SLOW;
	int i;

	spin_lock(&(led_set->lock));

	if (led_set->timer_state == TIMER_RUNNING) {
		/* Maybe there is already a timer running, restart one. */
		led_set->timer_state = TIMER_SLEEPING;
		del_timer(&(led_set->timer));
	}

	/* Invert the previous blinking state for next state. */
	led_set->blink_state ^= 1;

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if (led_set->led[i].presence == 0) continue;

		if ((led_set->led[i].state == LED_BLINK_FAST) || (led_set->led[i].state == LED_BLINK_SLOW)) {

			state = led_set->led[i].state;

			if (led_set->blink_state == 0) {
				_turn_off_led(led_set->id, led_set->led[i].color);
			} else {
				_turn_on_led(led_set->id, led_set->led[i].color);
			}
		}
	}

	led_set->timer_state = TIMER_RUNNING;

	if (state == LED_BLINK_FAST)
		mod_timer(&led_set->timer, jiffies + JIFFIES_BLINK_FAST);
	else if (state == LED_BLINK_SLOW)
		mod_timer(&led_set->timer, jiffies + JIFFIES_BLINK_SLOW);

	spin_unlock(&(led_set->lock));

}

void led_ioctl_set(struct _led_ioctl *led_data)
{
	unsigned int type = led_data->type;
	unsigned int color = led_data->color;
	unsigned int state = led_data->state;

	/* check the value range of LED_SET type */
	if ((type < 0) || (type >= LED_TOTAL)) return;

	/* check the LED_SET presence */
	if (LED_SET[type].presence == 0) return;

	switch (state) {
	case LED_OFF:
		led_blink_stop(type);
		turn_off_led_all(type);
		break;

	case LED_ON:
		led_blink_stop(type);
		turn_off_led_all(type);
		turn_on_led(type, color);
		break;

	case LED_BLINK_SLOW:
	case LED_BLINK_FAST:
		turn_off_led_all(type);
		led_blink_start(type, color, state);
	}

}

void led_ioctl_get(struct _led_ioctl *led_data)
{
	unsigned int type = led_data->type;
	int i;

	/* default return value */
	led_data->color = 0;
	led_data->state = LED_OFF;

	/* check the value range of LED_SET type */
	if ((type < 0) || (type >= LED_TOTAL))
		return;

	/* check the LED_SET presence */
	if (LED_SET[type].presence == 0) return;

	for (i = 0; i < LED_COLOR_TOTAL; i++) {
		if (LED_SET[type].led[i].presence == 0) continue;

		/* stupid code because I have to do backward compatibility for getLED */
		if (LED_SET[type].led[i].state != LED_OFF) {
			led_data->state = LED_SET[type].led[i].state;
			led_data->color |= LED_SET[type].led[i].color;
		}
	}
}

void init_leds(void)
{
	int i, j;
	unsigned long flags;

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	printk(KERN_INFO "Initialize LEDs\n");

	for (i = 0; i < LED_TOTAL; i++) {
		if (LED_SET[i].presence == 0) continue;

		for (j = 0; j < LED_COLOR_TOTAL; j++) {
			if (LED_SET[i].led[j].presence == 0) continue;

			writel(LED_SET[i].led[j].mask, LED_SET[i].led[j].reg_oe_set);
		}

		init_timer(&LED_SET[i].timer);
		LED_SET[i].timer.data = (unsigned long) &LED_SET[i];	/* timer handler can get own LED_SET[i] */

		printk(KERN_INFO " o %s\n", LED_SET[i].name);
	}

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);
}

////////////////////////////////////////////////////////////////////////////////

static struct timer_list buzzer_timer;
static int buzzer_round;		/* the remaining rounds to buzz */
static unsigned int buzz_time = JIFFIES_1_SEC / 2;	/* for each buzzing round, the time (jiffies) to buzz */
static unsigned int quiet_time = JIFFIES_1_SEC / 2;	/* for each buzzing round, the time (jiffies) to be quiet */
static int buzzer_freq = BUZZER_FREQ;	/* the frequency to buzz */
static short buzzer_timer_status = TIMER_SLEEPING;
spinlock_t buzzer_lock = SPIN_LOCK_UNLOCKED;
static int buzzer_presence = 0;		/* The presence of buzzer; default 0 is absent, non-zero is present. */

void init_buzzer(void)
{
	unsigned long flags;

	printk(KERN_INFO "Initialize buzzer\n");

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	/* set buzzer GPIO as output pin */
	writel((1UL << BUZZER_GPIO), BUZZER_OE_SET);

	/* initialize buzzer timer */
	init_timer(&buzzer_timer);
	buzzer_timer.function = buzzer_timer_handler;
	buzzer_timer_status = TIMER_SLEEPING;

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	buzzer_presence = 1;
}

static void buzzer_timer_handler(unsigned long data)
{
	static int buzzer_bit_state = 0;
	int i;

	spin_lock(&buzzer_lock);

	if (buzzer_round != 0) {

		/* Iteration is F times. Delay time is (10^6 / F / 2) microsecond (us).
		 * Theoretically, the for-loop requires 0.5 second.
		 */
		for (i = 0; i < buzzer_freq; i++) {
			if (buzzer_bit_state != 0) {
				writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_SET);
			} else {
				writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
			}

			/* 1 second = 10^6 us.
			 * If buzzer has to buzz with frequency F, the cycle time is 1/F second.
			 *
			 * In 1/2F second, buzzer bit is set to 1;
			 * and in another 1/2F second, buzzer bit is set to 0.
			 */
			udelay((1000000 / buzzer_freq) / 2);

			/* Invert the bit to let buzzer buzz. */
			buzzer_bit_state ^= 1;
		}

		/* Be quiet for 0.5 second */
		mod_timer(&buzzer_timer, jiffies + (JIFFIES_1_SEC / 2));

	} else {
		/* buzzer_round is 0, turn off buzzer */
	}

	if (buzzer_round > 0) --buzzer_round;

	spin_unlock(&buzzer_lock);
}

int set_buzzer(struct _buzzer_ioctl *data)
{
	spin_lock(&buzzer_lock);

	/* If buzzer is already running, stop it. */
	if (buzzer_timer_status == TIMER_RUNNING) {
		buzzer_timer_status = TIMER_SLEEPING;
		del_timer(&buzzer_timer);
	}

	if (data->buzz_time != 0) buzz_time = data->buzz_time;;
	if (data->quiet_time != 0) quiet_time = data->quiet_time;

	if (data->freq > 0)
		buzzer_freq = data->freq;
	else
		buzzer_freq = BUZZER_FREQ;

	if ((data->cmd == BUZZER_ON) || (BUZZER_FOREVER)) {

		buzzer_timer_status = TIMER_RUNNING;

		if ((data->round > 30) || (data->cmd == BUZZER_FOREVER)) {
			buzzer_round = -1;
		} else {
			buzzer_round = data->round;
		}

		buzzer_timer.function = buzzer_timer_handler;
		mod_timer(&buzzer_timer, jiffies + (HZ >> 3));	/* Start to buzz after 1/8 second. */
	}

	spin_unlock(&buzzer_lock);

	return 0;
}

/* Just do beep 1 time; for kernel use. */
static void Beep(void)
{
	static int buzzer_bit_state = 0;
	int i;

	if (buzzer_presence == 0) return;

	for (i = 0; i < buzzer_freq; i++) {
		if (buzzer_bit_state != 0) {
			writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_SET);
		} else {
			writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
		}

		/* 1 second = 10^6 us.
		 * If buzzer has to buzz with frequency F, the cycle time is 1/F second.
		 *
		 * In 1/2F second, buzzer bit is set to 1;
		 * and in another 1/2F second, buzzer bit is set to 0.
		 */
		udelay((1000000 / buzzer_freq) / 2);

		/* Invert the bit to let buzzer buzz. */
		buzzer_bit_state ^= 1;
	}
}

#if defined(CONFIG_ZyXEL_STG212)
void init_buzzer_stg212(void)
{
	unsigned long flags;

	printk(KERN_INFO "Initialize buzzer\n");

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	/* disable buzzer */
	if (BUZZER_ACTIVE == HIGH_ACTIVE) {
		writel((1UL << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
	} else {
		writel((1UL << BUZZER_GPIO), BUZZER_OUTPUT_SET);
	}

	/* set buzzer GPIO as output pin */
	writel((1UL << BUZZER_GPIO), BUZZER_OE_SET);

	/* initialize buzzer timer */
	init_timer(&buzzer_timer);
	buzzer_timer.function = buzzer_timer_handler_stg212;
	buzzer_timer_status = TIMER_SLEEPING;

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	buzzer_presence = 1;
}

static void buzzer_timer_handler_stg212(unsigned long data)
{
	static int buzzer_bit_state = 0;
	int i;
	unsigned buzz;
	unsigned int quiet;

	spin_lock(&buzzer_lock);

	if (buzzer_round != 0) {

		if (BUZZER_ACTIVE == HIGH_ACTIVE) {

			if (readl(BUZZER_OUTPUT) & (1 << BUZZER_GPIO)) {
				/* buzzing, turn it off */
				writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
				mod_timer(&buzzer_timer, jiffies + (JIFFIES_1_SEC * quiet_time) / 1000);
			} else {
				/* quiet, turn it on */
				writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_SET);
				mod_timer(&buzzer_timer, jiffies + (JIFFIES_1_SEC * buzz_time) / 1000);
				if (buzzer_round > 0) --buzzer_round;
			}

		} else {

			if (readl(BUZZER_OUTPUT) & (1 << BUZZER_GPIO)) {
				/* quiet, turn it on */
				writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
				mod_timer(&buzzer_timer, jiffies + (JIFFIES_1_SEC * buzz_time) / 1000);
				if (buzzer_round > 0) --buzzer_round;
			} else {
				/* buzzing, turn it off */
				writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_SET);
				mod_timer(&buzzer_timer, jiffies + (JIFFIES_1_SEC * quiet_time) / 1000);
			}

		}

	} else {
		/* buzzer_round is 0, turn off buzzer */
		if (BUZZER_ACTIVE == HIGH_ACTIVE) {
			writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
		} else {
			writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_SET);
		}

	}

	spin_unlock(&buzzer_lock);
}

int set_buzzer_stg212(struct _buzzer_ioctl *data)
{
	spin_lock(&buzzer_lock);

	/* If buzzer is already running, stop it. */
	if (buzzer_timer_status == TIMER_RUNNING) {
		buzzer_timer_status = TIMER_SLEEPING;
		del_timer(&buzzer_timer);
	}

	if (data->freq > 0)
		buzzer_freq = data->freq;
	else
		buzzer_freq = BUZZER_FREQ;

	if (data->buzz_time != 0) buzz_time = data->buzz_time;;
	if (data->quiet_time != 0) quiet_time = data->quiet_time;

	if ((data->cmd == BUZZER_ON) || (BUZZER_FOREVER)) {

		buzzer_timer_status = TIMER_RUNNING;

		if ((data->round > 30) || (data->cmd == BUZZER_FOREVER)) {
			buzzer_round = -1;
		} else {
			buzzer_round = data->round;
		}

		buzzer_timer.function = buzzer_timer_handler_stg212;
		mod_timer(&buzzer_timer, jiffies + (HZ >> 3));	/* Start to buzz after 1/8 second. */
	}

	spin_unlock(&buzzer_lock);

	return 0;
}

/* Just do beep 1 time; for kernel use. */
static void Beep_stg212(void)
{
	static int buzzer_bit_state = 0;
	int i;

	if (buzzer_presence == 0) return;

	/* enable buzzer */
	if (BUZZER_ACTIVE == HIGH_ACTIVE) {
		writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_SET);
	} else {
		writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
	}

	mdelay(500);

	/* disable buzzer */
	if (BUZZER_ACTIVE == HIGH_ACTIVE) {
		writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_CLEAR);
	} else {
		writel((1 << BUZZER_GPIO), BUZZER_OUTPUT_SET);
	}
}
#endif /* CONFIG_ZyXEL_STG212 */

////////////////////////////////////////////////////////////////////////////////

void zyxel_power_off()
{
#if defined(CONFIG_ZyXEL_STG100)
	/* STG-100 can't control system power through GPIO. */
#elif defined(CONFIG_ZyXEL_STG211)
	/* MF_A[11] == 1, power off */
	if (atomic_read(&shutdown_enable_flag)) {
		writel((1UL << 11), GPIO_A_OUTPUT_SET);
		writel((1UL << 11), GPIO_A_OUTPUT_ENABLE_SET);
	} else {
		printk(KERN_ERR "Any actions that may shutdown / reboot system are disabled.\n");
	}
#endif
}

////////////////////////////////////////////////////////////////////////////////

/* /proc/shutdownStatus
 * Flag of allowing to run poweroff, shutdown, reboot.
 */
static struct proc_dir_entry  *shutdown_status_entry;

static int shutdown_status_read(char *buf, char **start, off_t offset, int count, int *eof, void *data)
{
	int len;

	len = sprintf(buf, "%d\n", atomic_read(&shutdown_enable_flag));
	*eof = 1;

	return len;
}

static int shutdown_status_write(struct file *file, const char __user *buffer, unsigned long count, void *data)
{
	char my_buf[10];

	if (count > 2) {
		printk(KERN_ERR "Fail to write data.\n");
		return -EFAULT;
	}

	copy_from_user(my_buf, buffer, count);

	if (my_buf[0] == '0') {
		atomic_set(&shutdown_enable_flag, 0);
	} else {
		atomic_set(&shutdown_enable_flag, 1);
	}

	return count;
}

////////////////////////////////////////////////////////////////////////////////

/* /proc/htp
 * HTP pin is on or off; flag to check if it is necessary to run HTP.
 */
#if defined(CONFIG_ZyXEL_STG100R1) || defined(CONFIG_ZyXEL_STG211)

#define HTP_GPIO	7
#define HTP_DATA_REG	GPIO_A_DATA
#define HTP_OE_CLEAR	GPIO_A_OUTPUT_ENABLE_CLEAR

#elif defined(CONFIG_ZyXEL_STG100R2) || defined(CONFIG_ZyXEL_STG100R3)

#define HTP_GPIO	0
#define HTP_DATA_REG	GPIO_A_DATA
#define HTP_OE_CLEAR	GPIO_A_OUTPUT_ENABLE_CLEAR

#else /* default value */

#define HTP_GPIO	0
#define HTP_DATA_REG	GPIO_A_DATA
#define HTP_OE_CLEAR	GPIO_A_OUTPUT_ENABLE_CLEAR

#endif

static struct proc_dir_entry *htp_status_entry;

static int htp_status_read(char *buf, char **start, off_t offset, int count, int *eof, void *data)
{
	int len;
	unsigned long flags;

	/* Make sure the GPIO is an input pin first */
	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
	writel(1 << HTP_GPIO, HTP_OE_CLEAR);
	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	/* Read the HTP GPIO value */
	if (readl(HTP_DATA_REG) & (1 << HTP_GPIO)) {
		len = sprintf(buf, "1\n");
	} else {
		len = sprintf(buf, "0\n");
	}

	*eof = 1;

	return len;
}


////////////////////////////////////////////////////////////////////////////////

/* - Input
 *   0: backlight off
 *   none-zero: backlight on
 */
void lcd_backlight(unsigned long flag)
{
	/* MF_A[11]: LCD backlight; active low */
	unsigned int reg_value = 1 << 11;

	unsigned long flags;

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	/* Set output reg */
	if (flag != 0) {
		/* LCD blacklight on */
		writel(reg_value, GPIO_A_OUTPUT_CLEAR);
	} else {
		/* LCD blacklight off */
		writel(reg_value, GPIO_A_OUTPUT_SET);
	}

	/* Set output enable reg */
	writel(reg_value, GPIO_A_OUTPUT_ENABLE_SET);

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);
}

static ssize_t lcd_read(struct file *file, char *buf, size_t count, loff_t *ptr)
{
	return 0;
}

static ssize_t lcd_write(struct file * file, const char *buf, size_t count, loff_t * ppos)
{
	return 0;
}

static int lcd_open(struct inode *inode , struct file* filp)
{
	return 0;
}

static int lcd_release(struct inode *inode , struct file *filp)
{
	return 0;
}

static int lcd_ioctl(struct inode *inode, struct file *file, unsigned int cmd, unsigned long arg)
{
	struct _led_ioctl led_data;
	struct _buzzer_ioctl buzzer_data;

	switch (cmd) {
	case LCD_IOC_GET_MODEL:
		printk(KERN_INFO "ioctl get model, Model=%d\n", Model);
		put_user(Model, (unsigned long __user *) arg);
		break;

	case LCD_IOC_SET_PID:
		printk(KERN_INFO "ioctl set pid, arg=%lu\n", arg);
		if (!capable(CAP_SYS_ADMIN)) return -EPERM;
		lcdproc_pid = arg;
		break;

	case LCD_IOC_GET_BTN:
		printk(KERN_INFO "ioctl get btn, btn_pressed=%d\n", btn_pressed);
		put_user(btn_pressed, (unsigned long __user *) arg);
		break;

	case LCD_IOC_BTN_MENU:
		break;

	case LCD_IOC_BTN_ESC:
		printk(KERN_INFO "ioctl btn esc\n");
		break;

	case LCD_IOC_BTN_UP:
		printk(KERN_INFO "ioctl btn up\n");
		break;

	case LCD_IOC_BTN_DOWN:
		printk(KERN_INFO "ioctl btn down\n");
		break;

	case LCD_IOC_BTN_LEFT:
		printk(KERN_INFO "ioctl btn left\n");
		break;

	case LCD_IOC_BTN_RIGHT:
		printk(KERN_INFO "ioctl btn right\n");
		break;

	case LCD_IOC_SET_BACKLIGHT:
#if defined(CONFIG_ZyXEL_STG100R1)
		printk(KERN_INFO "%s: set LCD backlight = %lu\n", __FUNCTION__, arg);
		lcd_backlight(arg);
#else
		printk(KERN_ERR "The kernel config does NOT support LCD ioctl function.\n");
		printk(KERN_ERR "If there is really an LCD panel on system,\n");
		printk(KERN_ERR "please set correct kernel config and recompile kernel.\n");
#endif
		break;

	case NAS_IOC_SET_LED:
		copy_from_user(&led_data, (void __user *) arg, sizeof(struct _led_ioctl));
		led_ioctl_set(&led_data);
		break;

	case NAS_IOC_GET_LED:
		/* Steps:
		 * 1. Get LED type from user space.
		 * 2. Get LED status of the assigned type.
		 * 3. Write the status to user space.
		 */
		copy_from_user(&led_data, (void __user *) arg, sizeof(struct _led_ioctl));
		led_ioctl_get(&led_data);
		copy_to_user((void __user *) arg, &led_data, sizeof(struct _led_ioctl));
		break;

	case NAS_IOC_SET_BTNCPY_PID:
		if (!capable(CAP_SYS_ADMIN)) return -EPERM;
		btncpy_pid = arg;
		break;

	case NAS_IOC_SET_BUZZER:
		copy_from_user(&buzzer_data, (void __user *) arg, sizeof(struct _buzzer_ioctl));
#if defined(CONFIG_ZyXEL_STG211)
		set_buzzer(&buzzer_data);
#elif defined(CONFIG_ZyXEL_STG212)
		set_buzzer_stg212(&buzzer_data);
#endif
		break;

	case NAS_IOC_BUTTON_TEST_IN:
		btncpy_pid = arg >> 3;
		atomic_set(&button_test_enable, 1);
		atomic_set(&button_test_num, arg & 0x7);
		break;

	case NAS_IOC_BUTTON_TEST_OUT:
		atomic_set(&button_test_enable, 0);
		atomic_set(&button_test_num, BUTTON_NUM);
		break;

	case NAS_IOC_SET_POWER_RESUME:
		power_resume_set();
		break;

	case NAS_IOC_CLR_POWER_RESUME:
		power_resume_clear();
		break;

	default:
		return -ENOTTY;
	}

	return 0;
}

struct file_operations lcd_fops =
{
	owner:		THIS_MODULE,
	read:		lcd_read,
	write:		lcd_write,
	ioctl:		lcd_ioctl,
	open:		lcd_open,
	release:	lcd_release,
};


void ok_button_handler(struct work_struct *in)
{
	printk(KERN_INFO "ok_button_handler: lcdproc_pid=%d\n", lcdproc_pid);

	if (lcdproc_pid != 0) {
		sys_kill(lcdproc_pid, SIGUSR2);
	}
}

void select_button_handler(struct work_struct *in)
{
	printk(KERN_INFO "select_button_handler: lcdproc_pid=%d\n", lcdproc_pid);

	if (lcdproc_pid != 0) {
		sys_kill(lcdproc_pid, SIGUSR2);
	}
}

void reset_button_handler(struct work_struct *in)
{
	printk(KERN_INFO "reset_button_handler: lcdproc_pid=%d\n", lcdproc_pid);

	if (lcdproc_pid != 0) {
		sys_kill(lcdproc_pid, SIGUSR2);
	}
}

void eject_button_handler(struct work_struct *in)
{
	printk(KERN_INFO "eject_button_handler: lcdproc_pid=%d\n", lcdproc_pid);

	if (lcdproc_pid != 0) {
		sys_kill(lcdproc_pid, SIGUSR2);
	}
}

void power_button_handler(struct work_struct *in)
{
	char *argv[] = {"/sbin/halt", NULL};

	if (atomic_read(&shutdown_enable_flag))
		call_usermodehelper("/sbin/halt", argv, NULL, 0);
	else
		printk(KERN_ERR "Any actions that may shutdown / reboot system are disabled.\n");
}

void reset_user_info_handler(struct work_struct *in)
{
	if (atomic_read(&shutdown_enable_flag))
		call_usermodehelper("/usr/local/btn/reset_userinfo.sh", NULL, NULL, 0);
	else
		printk(KERN_ERR "Any actions that may shutdown / reboot system are disabled.\n");
}

void open_backdoor_handler(struct work_struct *in)
{
	if (atomic_read(&shutdown_enable_flag))
		call_usermodehelper("/usr/local/btn/open_back_door.sh", NULL, NULL, 0);
	else
		printk(KERN_ERR "Any actions that may shutdown / reboot system are disabled.\n");
}

void reset_to_default_handler(struct work_struct *in)
{
	if (atomic_read(&shutdown_enable_flag)) {

#if defined(CONFIG_ZyXEL_STG100) || defined(CONFIG_ZyXEL_STG211)
		Beep();
		ssleep(1);

		Beep();
		ssleep(1);

		Beep();
		ssleep(1);
#elif defined(CONFIG_ZyXEL_STG212)
		Beep_stg212();
		ssleep(1);

		Beep_stg212();
		ssleep(1);

		Beep_stg212();
		ssleep(1);
#endif

		call_usermodehelper("/usr/local/btn/reset_and_reboot.sh", NULL, NULL, 0);

	} else {

		printk(KERN_ERR "Any actions that may shutdown / reboot system are disabled.\n");

	}
}

void do_copy_handler(struct work_struct *in)
{
	/* do data copy */
	sys_kill(btncpy_pid, 10);
}

void do_sync_handler(struct work_struct *in)
{
	/* do data sync */
	sys_kill(btncpy_pid, 12);
}

void front_eject_handler(struct work_struct *in)
{
	printk(KERN_ERR "%s:/usr/local/btn/front_eject.sh\n", __FILE__);
	call_usermodehelper("/usr/local/btn/front_eject.sh", NULL, NULL, 0);
}


void rear_eject_handler(struct work_struct *in)
{
	printk(KERN_ERR "%s: /usr/local/btn/rear_eject.sh\n", __FILE__);
	call_usermodehelper("/usr/local/btn/rear_eject.sh", NULL, NULL, 0);
}


////////////////////////////////////////////////////////////////////////////////

int isButtonPressed(struct _btn *btn)
{
	int ret = 0;

	if (btn->active == HIGH_ACTIVE) {

		if (readl(btn->reg_data) & btn->mask)
			ret = 1;
		else
			ret = 0;

	} else if (btn->active == LOW_ACTIVE) {

		if (readl(btn->reg_data) & btn->mask)
			ret = 0;
		else
			ret = 1;

	}

	return ret;
}

int isButtonReleased(struct _btn *btn)
{
	return (!isButtonPressed(btn));
}

/** Have to use active low level interupt generation, as otherwise might miss
 *  interrupts that arrive concurrently with a PCI interrupt, as PCI interrupts
 *  are generated via GPIO pins and std PCI drivers will not know that there
 *  may be other pending GPIO interrupt sources waiting to be serviced and will
 *  simply return IRQ_HANDLED if they see themselves as having generated the
 *  interrupt, thus preventing later chained handlers from being called
 */
static irqreturn_t ok_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

static irqreturn_t select_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

static irqreturn_t reset_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

static irqreturn_t eject_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

static irqreturn_t power_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

static irqreturn_t copy_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

static irqreturn_t front_eject_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

static irqreturn_t rear_eject_button_irq_handler(int irq, void* dev_id)
{
	struct _btn *btn = (struct _btn*) dev_id;
	int status = IRQ_NONE;
	unsigned int int_status = readl((volatile unsigned long *) btn->reg_irq_event);

	/* Is the interrupt for us? */
	if (int_status & btn->mask) {

		printk(KERN_INFO "%s\n", btn->name);

		/* Disable the power button GPIO line interrupt */
		spin_lock(&oxnas_gpio_spinlock);
		writel(readl(btn->reg_irq_enable) & ~(btn->mask), btn->reg_irq_enable);
		spin_unlock(&oxnas_gpio_spinlock);

		/* Start hold down timer with a timeout of 1/8 second */
		mod_timer(&btn->timer, jiffies);

		/* Only mark interrupt as serviced if no other unmasked GPIO interrupts
		are pending */
		if (!readl((volatile unsigned long *) btn->reg_irq_event)) {
			status = IRQ_HANDLED;
		}
	}

	return status;
}

////////////////////////////////////////////////////////////////////////////////

static void ok_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */
	static int isPressedHandled = 0;

	if (isButtonReleased(btn)) {
		/* button is released */

		isPressedHandled = 0;

		/* reset the counting of button pressed time */
		polling_time = 0;

		/* The h/w debounced power button has been released, so reenable the
		active low interrupt detection to trap the user's next attempt to
		power down */
		spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
		/* Clear the original interrupt */
		writel(btn->mask, btn->reg_irq_event);
		/* Enable falling edge interrupts */
		writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
		spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	} else {
		/* button is still pressed */

		if (isPressedHandled == 0) {

			printk(KERN_INFO "%s: button is pressed.\n", btn->name);

			isPressedHandled = 1;
			btn_pressed = btn->id;

			PREPARE_WORK(&LCDButton, ok_button_handler);
			queue_work(btn_workqueue, &LCDButton);
		}

		++polling_time;

		/* Restart timer */
		mod_timer(&btn->timer, jiffies + (JIFFIES_1_SEC >> 3));
	}
}

static void select_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */
	static int isPressedHandled = 0;

	if (isButtonReleased(btn)) {
		/* button is released */

		isPressedHandled = 0;

		/* reset the counting of button pressed time */
		polling_time = 0;

		/* The h/w debounced power button has been released, so reenable the
		active low interrupt detection to trap the user's next attempt to
		power down */
		spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
		/* Clear the original interrupt */
		writel(btn->mask, btn->reg_irq_event);
		/* Enable falling edge interrupts */
		writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
		spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	} else {
		/* button is still pressed */

		if (isPressedHandled == 0) {

			printk(KERN_INFO "%s: button is pressed.\n", btn->name);

			isPressedHandled = 1;
			btn_pressed = btn->id;

			PREPARE_WORK(&LCDButton, select_button_handler);
			queue_work(btn_workqueue, &LCDButton);
		}

		++polling_time;

		/* Restart timer */
		mod_timer(&btn->timer, jiffies + (JIFFIES_1_SEC >> 3));
	}
}

static void reset_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */
	static int isPressedHandled = 0;

	if (isButtonReleased(btn)) {
		/* button is released */

		isPressedHandled = 0;

		/* reset the counting of button pressed time */
		polling_time = 0;

		/* The h/w debounced power button has been released, so reenable the
		active low interrupt detection to trap the user's next attempt to
		power down */
		spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
		/* Clear the original interrupt */
		writel(btn->mask, btn->reg_irq_event);
		/* Enable falling edge interrupts */
		writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
		spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	} else {
		/* button is still pressed */

		if (isPressedHandled == 0) {

			printk(KERN_INFO "%s: button is pressed.\n", btn->name);

			isPressedHandled = 1;
			btn_pressed = btn->id;

			PREPARE_WORK(&LCDButton, reset_button_handler);
			queue_work(btn_workqueue, &LCDButton);
		}

		++polling_time;

		/* Restart timer */
		mod_timer(&btn->timer, jiffies + (JIFFIES_1_SEC >> 3));
	}
}

static void eject_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */
	static int isPressedHandled = 0;

	if (isButtonReleased(btn)) {
		/* button is released */

		isPressedHandled = 0;

		/* reset the counting of button pressed time */
		polling_time = 0;

		/* The h/w debounced power button has been released, so reenable the
		active low interrupt detection to trap the user's next attempt to
		power down */
		spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
		/* Clear the original interrupt */
		writel(btn->mask, btn->reg_irq_event);
		/* Enable falling edge interrupts */
		writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
		spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	} else {
		/* button is still pressed */

		if (isPressedHandled == 0) {

			printk(KERN_INFO "%s: button is pressed.\n", btn->name);

			isPressedHandled = 1;
			btn_pressed = btn->id;

			PREPARE_WORK(&LCDButton, eject_button_handler);
			queue_work(btn_workqueue, &LCDButton);
		}

		++polling_time;

		/* Restart timer */
		mod_timer(&btn->timer, jiffies + (JIFFIES_1_SEC >> 3));
	}
}

static void power_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */

	if (isButtonPressed(btn)) {
		/* button is still pressed */
		printk(KERN_INFO "%s: button is pressed, polling_time = %d.\n", btn->name, polling_time);

		++polling_time;

		if (polling_time == SOFT_POWER_OFF_TIME) Beep();
		if (polling_time == FORCE_POWER_OFF_TIME) Beep();

		/* Restart timer */
		mod_timer(&btn->timer, jiffies + JIFFIES_1_SEC);
	} else {
		/* button is released */

		if (atomic_read(&button_test_enable) && (atomic_read(&button_test_num) == POWER_BTN_NUM)) {
			/* HTP test */

			atomic_set(&button_test_enable, 0);
			PREPARE_WORK(&HTPTest, do_copy_handler);
			queue_work(btn_workqueue, &HTPTest);
			/* Why call do_copy_handler? Because it is original designer's design -- send SIGUSR1 to process.
			 * I guess the cause is the lack of free signal.
			 * There is a good solution to replace this stupid design but I don't want to break the in-use mechanism;
			 * it will be a big earthquake.
			 */

		} else {
			/* normal usage, not HTP test */

			printk(KERN_INFO "%s: button is released, polling_time = %d.\n", btn->name, polling_time);

			if ((polling_time >= SOFT_POWER_OFF_TIME) && (polling_time < FORCE_POWER_OFF_TIME)) {

				PREPARE_WORK(&SoftPowerOff, power_button_handler);
				queue_work(btn_workqueue, &SoftPowerOff);

			} else if (polling_time >= FORCE_POWER_OFF_TIME) {
				zyxel_power_off();
			}

			/* reset the counting of button pressed time */
			polling_time = 0;

			/* The h/w debounced power button has been released, so reenable the
			active low interrupt detection to trap the user's next attempt to
			power down */
			spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
			/* Clear the original interrupt */
			writel(btn->mask, btn->reg_irq_event);
			/* Enable falling edge interrupts */
			writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
			spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

		}

	}
}

static void copy_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */

	if (isButtonReleased(btn)) {
		/* button is released */

		if (atomic_read(&button_test_enable) && (atomic_read(&button_test_num) == COPY_BTN_NUM)) {
			/* HTP test */

			atomic_set(&button_test_enable, 0);
			PREPARE_WORK(&HTPTest, do_copy_handler);
			queue_work(btn_workqueue, &HTPTest);
			/* Why call do_copy_handler? Because it is original designer's design -- send SIGUSR1 to process.
			 * I guess the cause is the lack of free signal.
			 * There is a good solution to replace this stupid design but I don't want to break the in-use mechanism;
			 * it will be a big earthquake.
			 */

		} else {
			/* normal usage, not HTP test */

			printk(KERN_INFO "%s: button is released, polling_time = %d.\n", btn->name, polling_time);

			if ((btncpy_pid != 0) && (polling_time >= DO_COPY_TIME) && (polling_time < DO_SYNC_TIME)) {

				PREPARE_WORK(&DoCopy, do_copy_handler);
				queue_work(btn_workqueue, &DoCopy);

			} else if ((btncpy_pid != 0) && (polling_time >= DO_SYNC_TIME) && (polling_time < DO_DUMP_TIME)) {

				PREPARE_WORK(&DoSync, do_sync_handler);
				queue_work(btn_workqueue, &DoSync);

			} else if (polling_time >= DO_DUMP_TIME) {

				show_state();
				show_mem();

			}

			/* reset the counting of button pressed time */
			polling_time = 0;

			/* The h/w debounced power button has been released, so reenable the
			active low interrupt detection to trap the user's next attempt to
			power down */
			spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
			/* Clear the original interrupt */
			writel(btn->mask, btn->reg_irq_event);
			/* Enable falling edge interrupts */
			writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
			spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

		}

	} else {
		/* button is still pressed */
		printk(KERN_INFO "%s: button is pressed, polling_time = %d.\n", btn->name, polling_time);

		++polling_time;

#if defined(CONFIG_ZyXEL_STG100) || defined(CONFIG_ZyXEL_STG211)
		if (polling_time == DO_SYNC_TIME) Beep();
		if (polling_time == DO_DUMP_TIME) Beep();
#elif defined(CONFIG_ZyXEL_STG212)
		if (polling_time == DO_SYNC_TIME) Beep_stg212();
		if (polling_time == DO_DUMP_TIME) Beep_stg212();
#endif

		/* Restart timer */
		mod_timer(&btn->timer, jiffies + JIFFIES_1_SEC);
	}
}

/* Traditional Reset Button timer handler; for ZyXEL / MitraStar NAS */
static void traditional_reset_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */

	if (isButtonReleased(btn)) {
		/* button is released */

		if (atomic_read(&button_test_enable) && (atomic_read(&button_test_num) == RESET_BTN_NUM)) {
			/* HTP test */

			atomic_set(&button_test_enable, 0);
			PREPARE_WORK(&HTPTest, do_copy_handler);
			queue_work(btn_workqueue, &HTPTest);
			/* Why call do_copy_handler? Because it is original designer's design -- send SIGUSR1 to process.
			 * I guess the cause is the lack of free signal.
			 * There is a good solution to replace this stupid design but I don't want to break the in-use mechanism;
			 * it will be a big earthquake.
			 */

		} else {
			/* normal usage, not HTP test */

			printk(KERN_INFO "%s: button is released, polling_time = %d.\n", btn->name, polling_time);

			if (polling_time < RESET_USER_INFO_TIME) {

				/* do nothing */

			} else if ((polling_time >= RESET_USER_INFO_TIME) && (polling_time < RESET_TO_DEFAULT_TIME)) {

				PREPARE_WORK(&ResetUserInfo, reset_user_info_handler);
				queue_work(btn_workqueue, &ResetUserInfo);

			} else if (polling_time >= RESET_TO_DEFAULT_TIME) {

				PREPARE_WORK(&ResetToDefault, reset_to_default_handler);
				queue_work(btn_workqueue, &ResetToDefault);

			}

			/* reset the counting of button pressed time */
			polling_time = 0;

			/* The h/w debounced power button has been released, so reenable the
			active low interrupt detection to trap the user's next attempt to
			power down */
			spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
			/* Clear the original interrupt */
			writel(btn->mask, btn->reg_irq_event);
			/* Enable falling edge interrupts */
			writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
			spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

		}

	} else {
		/* button is still pressed */
		printk(KERN_INFO "%s: button is pressed, polling_time = %d.\n", btn->name, polling_time);

		++polling_time;

		if (polling_time == RESET_USER_INFO_TIME) {
#if defined(CONFIG_ZyXEL_STG100R3)
			led_blink_start(LED_SYS, GREEN, LED_BLINK_SLOW);
#endif

#if defined(CONFIG_ZyXEL_STG100) || defined(CONFIG_ZyXEL_STG211)
			Beep();
#elif defined(CONFIG_ZyXEL_STG212)
			Beep_stg212();
#endif
		}

		if (polling_time == RESET_TO_DEFAULT_TIME) {
#if defined(CONFIG_ZyXEL_STG100R3)
			led_blink_start(LED_SYS, GREEN, LED_BLINK_FAST);
#endif

#if defined(CONFIG_ZyXEL_STG100) || defined(CONFIG_ZyXEL_STG211)
			Beep();
#elif defined(CONFIG_ZyXEL_STG212)
			Beep_stg212();
#endif
		}

		/* Restart timer */
		mod_timer(&btn->timer, jiffies + JIFFIES_1_SEC);
	}
}

static void front_eject_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */

	if (isButtonReleased(btn)) {
		/* button is released */
		printk(KERN_INFO "%s: button is released, polling_time = %d.\n", btn->name, polling_time);

		PREPARE_WORK(&FrontEject, front_eject_handler);
		queue_work(btn_workqueue, &FrontEject);

		/* reset the counting of button pressed time */
		polling_time = 0;

		/* The h/w debounced power button has been released, so reenable the
		active low interrupt detection to trap the user's next attempt to
		power down */
		spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
		/* Clear the original interrupt */
		writel(btn->mask, btn->reg_irq_event);
		/* Enable falling edge interrupts */
		writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
		spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	} else {
		/* button is still pressed */
		printk(KERN_INFO "%s: button is pressed, polling_time = %d.\n", btn->name, polling_time);

		++polling_time;


		/* Restart timer */
		mod_timer(&btn->timer, jiffies + JIFFIES_1_SEC);
	}
}

static void rear_eject_button_timer_handler(unsigned long data)
{
	struct _btn *btn = (struct _btn*) data;
	unsigned long flags;
	static int polling_time = 0;	/* Unit should be second according to TIMER_INTERVAL_JIFFIES. */

	if (isButtonReleased(btn)) {
		/* button is released */
		printk(KERN_INFO "%s: button is released, polling_time = %d.\n", btn->name, polling_time);

		PREPARE_WORK(&RearEject, rear_eject_handler);
		queue_work(btn_workqueue, &RearEject);

		/* reset the counting of button pressed time */
		polling_time = 0;

		/* The h/w debounced power button has been released, so reenable the
		active low interrupt detection to trap the user's next attempt to
		power down */
		spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
		/* Clear the original interrupt */
		writel(btn->mask, btn->reg_irq_event);
		/* Enable falling edge interrupts */
		writel(readl(btn->reg_irq_enable) | btn->mask, btn->reg_irq_enable);
		spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	} else {
		/* button is still pressed */
		printk(KERN_INFO "%s: button is pressed, polling_time = %d.\n", btn->name, polling_time);

		++polling_time;


		/* Restart timer */
		mod_timer(&btn->timer, jiffies + JIFFIES_1_SEC);
	}
}

////////////////////////////////////////////////////////////////////////////////

void power_resume_set(void)
{
	unsigned long flags;

	/* Data == 1 : Power resume is enabled.
	 * Clock 1 -> 0 : Write data to D-flip-flop.
	 */

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
	writel(1 << PR_CLOCK_GPIO, PR_CLOCK_OUTPUT_SET);		// pull up clock
	writel(1 << PR_DATA_GPIO, PR_DATA_OUTPUT_SET);
	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	udelay(1000);

	/* Enable clock pin */
	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
	writel(1 << PR_CLOCK_GPIO, PR_CLOCK_OUTPUT_CLEAR);		// pull down clock
	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	udelay(1000);
}

void power_resume_clear(void)
{
	unsigned long flags;

	/* Data == 0 : Power resume is disabled.
	 * Clock 1 -> 0 : Write data to D-flip-flop.
	 */

	/* Clear clock & data pin; data pin is high active. (Should refine the code) */
	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
	writel(1 << PR_CLOCK_GPIO, PR_CLOCK_OUTPUT_SET);		// pull up clock
	writel(1 << PR_DATA_GPIO, PR_DATA_OUTPUT_CLEAR);
	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	udelay(1000);

	/* Enable clock pin */
	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
	writel(1 << PR_CLOCK_GPIO, PR_CLOCK_OUTPUT_CLEAR);		// pull down clock
	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);
}

void init_power_resume(void)
{
	unsigned long flags;

	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);

	printk(KERN_INFO "Initialize power resume\n");

	/* set Power Resume Data & Clock GPIO as output pin */
	writel((1UL << PR_DATA_GPIO), PR_DATA_OE_SET);
	writel((1UL << PR_CLOCK_GPIO), PR_CLOCK_OE_SET);

	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);
}


////////////////////////////////////////////////////////////////////////////////

static int __init nas_gpio_init(void)
{
	int major = 0, minor = 0;
	int err = 0;
	unsigned long flags;
	int i;

	printk(KERN_INFO "%s %s\n", DRIVER_NAME, DRIVER_VERSION);

	/* initialize the workqueue */
	btn_workqueue = create_workqueue("button controller");

	//-------------------------------------------------------------------------------//

	nas_model_entry = create_proc_entry("nas_model", 0644, NULL);

	if (nas_model_entry != NULL) {
		nas_model_entry->read_proc = nas_model_read;
		nas_model_entry->write_proc = NULL;
	}

	//-------------------------------------------------------------------------------//

	shutdown_status_entry = create_proc_entry("shutdownStatus", 0644, NULL);

	if (shutdown_status_entry != NULL) {
		shutdown_status_entry->read_proc = shutdown_status_read;
		shutdown_status_entry->write_proc = shutdown_status_write;
	}

	//-------------------------------------------------------------------------------//

#if defined(CONFIG_ZyXEL_STG100) || defined(CONFIG_ZyXEL_STG211)
	htp_status_entry = create_proc_entry("htp", 0644, NULL);

	if (htp_status_entry != NULL) {
		htp_status_entry->read_proc = htp_status_read;
		htp_status_entry->write_proc = NULL;
	}
#endif

	//-------------------------------------------------------------------------------//

	/* Setup GPIO and default value for LEDs */
	init_leds();
	turn_off_led_all(LED_SYS);
	turn_off_led_all(LED_HDD);
	turn_off_led_all(LED_USB);
	turn_off_led_all(LED_ESATA);
	turn_off_led_all(LED_COPY);

	turn_off_led_all(LED_QUOTA_1);
	turn_off_led_all(LED_QUOTA_2);
	turn_off_led_all(LED_QUOTA_3);
	turn_off_led_all(LED_QUOTA_4);

#if defined(CONFIG_ZyXEL_STG100) || defined(CONFIG_ZyXEL_STG211)
	led_blink_start(LED_SYS, GREEN, LED_BLINK_SLOW);
#elif defined(CONFIG_ZyXEL_STG212)
	led_blink_start(LED_SYS, BLUE, LED_BLINK_SLOW);
#endif

	//-------------------------------------------------------------------------------//

	/* Setup GPIO for buzzer */
#if defined(CONFIG_ZyXEL_STG211)
	init_buzzer();
#elif defined(CONFIG_ZyXEL_STG212)
	init_buzzer_stg212();
#endif

	//-------------------------------------------------------------------------------//

	/* Setup GPIO for power resume */
#if defined(CONFIG_ZyXEL_STG211)
	init_power_resume();
#endif


	//-------------------------------------------------------------------------------//

	/* Setup button IRQ */
	printk(KERN_INFO "Initialize buttons\n");
	for (i = 0; i < num_btns; i++) {
		init_timer(&Btn[i].timer);
		Btn[i].timer.data = (unsigned long) &Btn[i];	/* timer handler can get own Btn[i] */

		if (request_irq(Btn[i].irq, Btn[i].irq_handler, IRQF_SHARED, Btn[i].name, &Btn[i])) {
			printk(KERN_ERR "%s: cannot register IRQ %d\n", Btn[i].name, Btn[i].irq);
			del_timer_sync(&Btn[i].timer);
			return -EIO;
		}

		printk(KERN_INFO " o %s\n", Btn[i].name);
	}


	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
	/* Disable primary, secondary and teriary GPIO functions on switch lines */
	for (i = 0; i < num_btns; i++) {
		writel(readl(SYS_CTRL_SECONDARY_SEL)   & ~Btn[i].mask, SYS_CTRL_SECONDARY_SEL);
		writel(readl(SYS_CTRL_TERTIARY_SEL)    & ~Btn[i].mask, SYS_CTRL_TERTIARY_SEL);
		writel(readl(SYS_CTRL_QUATERNARY_SEL)  & ~Btn[i].mask, SYS_CTRL_QUATERNARY_SEL);
		writel(readl(SYS_CTRL_DEBUG_SEL)       & ~Btn[i].mask, SYS_CTRL_DEBUG_SEL);
		writel(readl(SYS_CTRL_ALTERNATIVE_SEL) & ~Btn[i].mask, SYS_CTRL_ALTERNATIVE_SEL);

		/* Enable GPIO input on switch line */
		writel(Btn[i].mask, Btn[i].reg_oe_clear);

		/* Set up the power button GPIO line for active low, debounced interrupt */
		writel(readl(Btn[i].reg_debounce) | Btn[i].mask, Btn[i].reg_debounce);
		writel(readl(Btn[i].reg_irq_enable) | Btn[i].mask, Btn[i].reg_irq_enable);
	}
	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	//-------------------------------------------------------------------------------//

	/* Register a char dev */
	err = alloc_chrdev_region(&lcd_dev, 0, lcd_nr_devs, "nas_gpio");
	if (err < 0) {
		printk(KERN_ERR "%s: failed to allocate char dev region\n", __FILE__);
		return -1;
	}

	major = MAJOR(lcd_dev);
	minor = MINOR(lcd_dev);
	printk(KERN_INFO "nas_gpio: Register a char device %d:%d\n", major, minor);

	lcd_cdev = cdev_alloc();
	lcd_cdev->ops = &lcd_fops;
	lcd_cdev->owner = THIS_MODULE;

	err = cdev_add(lcd_cdev, lcd_dev, 1);
	if (err) printk(KERN_INFO "Fail to add char device.\n");

	return 0;
}

static void __exit nas_gpio_exit(void)
{
	unsigned long flags;
	int i;

	destroy_workqueue(btn_workqueue);

	for (i = 0; i < num_btns; i++) {
		/* Deactive the timer */
		del_timer_sync(&Btn[i].timer);

		/* Remove the handler for the shared interrupt line */
		free_irq(Btn[i].irq, &Btn[i]);
	}

	/* Disable interrupt generation by the power button GPIO line */
	spin_lock_irqsave(&oxnas_gpio_spinlock, flags);
	for (i = 0; i < num_btns; i++) {
		writel(readl(Btn[i].reg_irq_enable) & ~Btn[i].mask, Btn[i].reg_irq_enable);
	}
	spin_unlock_irqrestore(&oxnas_gpio_spinlock, flags);

	/* Unregister char dev */
	unregister_chrdev_region(lcd_dev, lcd_nr_devs);

}

/**
 * macros to register intiialisation and exit functions with kernal
 */
module_init(nas_gpio_init);
module_exit(nas_gpio_exit);

