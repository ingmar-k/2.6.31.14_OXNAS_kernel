#ifndef _NAS_GPIO_H_
#define _NAS_GPIO_H_

#include <linux/timer.h>

#define JIFFIES_1_SEC		(HZ)		/* 1 second */

#define JIFFIES_TO_US(TIME)	((TIME) * (1000000 / HZ))

enum _gpio_active {
	LOW_ACTIVE = 0,
	HIGH_ACTIVE,
};


/***** System Model *****/
enum {
	MODEL_STG100R1,	/* NAS7820 + LCD panel */
	MODEL_STG100R2,	/* NAS7715 + LED + rear USB port */
	MODEL_STG100R3,	/* NAS7715 + LED + front USB port + rear USB port */
	MODEL_STG211R1,	/* NAS7821 */
	MODEL_STG211R2,	/* NAS7821 + USB 3.0 port + SD card slot */
	MODEL_STG212,
	MODEL_UNKNOWN = 65535,
};


/***** HTP *****/
#define BUTTON_NUM	3

enum BUTTON_NUMBER {
	RESET_BTN_NUM,
	COPY_BTN_NUM,
	POWER_BTN_NUM,
};


/***** LEDs *****/

enum _led_id {
	LED_SYS = 0,
	LED_HDD,
	LED_USB,
	LED_ESATA,
	LED_COPY,
	LED_LAN,
	LED_EJECT_READY,

	LED_QUOTA_1,		/* Indicate the used quota of internal volume */
	LED_QUOTA_2,
	LED_QUOTA_3,
	LED_QUOTA_4,

	LED_TOTAL,		/* must be the last one */
};

enum _led_color {
	LED_RED = 0,
	LED_GREEN,
	LED_YELLOW,
	LED_BLUE,

	LED_COLOR_TOTAL,	/* must be last one */
};

/* LED color flag */
enum _color {
	/* primal color */
	RED = 0x00000001,
	GREEN = 0x00000002,
	YELLOW = 0x00000004,
	BLUE = 0x0000008,

	/* mixed color */
	ORANGE = RED | GREEN,
};

#define JIFFIES_BLINK_SLOW	(JIFFIES_1_SEC / 2)
#define JIFFIES_BLINK_FAST	(JIFFIES_1_SEC / 10)

enum _led_state {
	LED_OFF,
	LED_ON,
	LED_BLINK_SLOW,
	LED_BLINK_FAST,
};

enum _timer_state {
	TIMER_SLEEPING,
	TIMER_RUNNING,			/* timer is running, or there is already a timer running */
};

struct _led {
	unsigned int gpio;
	unsigned int mask;
	unsigned int color;
	unsigned int reg_oe_set;
	unsigned int reg_output_set;	/* output set register (write only) */
	unsigned int reg_output_clear;	/* output clear register (write only) */
	unsigned short active;		/* LOW_ACTIVE, HIGH_ACTIVE */
	unsigned short state;		/* LED_OFF, LED_ON, LED_BLINK_SLOW, ... */

	unsigned short presence;	/* flag. 0: no such LED color */
};

struct _led_set {
	unsigned int id;			/* LED ID, LED type */
	char name[32];
	struct _led led[LED_TOTAL];

	struct timer_list timer;
	unsigned short timer_state;
	unsigned short blink_state;	/* Binary state, it must be 0 (off) or 1 (on) to present the blinking state */

	spinlock_t lock;

	unsigned short presence;	/* flag. 0: no such LED */
};

void turn_on_led(unsigned int id, unsigned int color);
void turn_off_led(unsigned int id, unsigned int color);
void turn_off_led_all(unsigned int id);
void led_blink_start(unsigned int id, unsigned int color, unsigned int state);
void led_blink_stop(unsigned int id);

static void led_timer_handler(unsigned long);

/* data structure for passing LED date */
typedef struct _led_ioctl {
	unsigned int type;	/* LED_SYS, LED_HDD, ... */
	unsigned int color;	/* RED, GREEN, ... */
	unsigned int state;	/* LED_ON, LED_OFF, ... */
} led_ioctl;



/***** Buzzer *****/

#if defined(CONFIG_ZyXEL_STG211)

#define BUZZER_GPIO		7
#define BUZZER_OE_SET		GPIO_B_OUTPUT_ENABLE_SET
#define BUZZER_OUTPUT_SET	GPIO_B_OUTPUT_SET
#define BUZZER_OUTPUT_CLEAR	GPIO_B_OUTPUT_CLEAR

#define BUZZER_FREQ		1000			/* default frequency to buzz */

#elif defined(CONFIG_ZyXEL_STG212)

#define BUZZER_ACTIVE		LOW_ACTIVE
#define BUZZER_GPIO		15
#define BUZZER_OUTPUT		GPIO_B_DATA
#define BUZZER_OE_SET		GPIO_B_OUTPUT_ENABLE_SET
#define BUZZER_OUTPUT_SET	GPIO_B_OUTPUT_SET
#define BUZZER_OUTPUT_CLEAR	GPIO_B_OUTPUT_CLEAR

#define BUZZER_FREQ		1000			/* default frequency to buzz */

#else

/* Default setting. this is for compilation, maybe there is no buzzer on board. */
#define BUZZER_GPIO		7
#define BUZZER_OE_SET		GPIO_B_OUTPUT_ENABLE_SET
#define BUZZER_OUTPUT_SET	GPIO_B_OUTPUT_SET
#define BUZZER_OUTPUT_CLEAR	GPIO_B_OUTPUT_CLEAR

#define BUZZER_FREQ		1000			/* default frequency to buzz */

#endif /* CONFIG_ZyXEL_STG211 */

enum _buzzer_cmd {
	BUZZER_OFF = 0,		/* turn off buzzer */
	BUZZER_ON,		/* turn of buzzer with specific time */
	BUZZER_KILL,		/* kill buzzer daemon, same as BUZZER_OFF */
	BUZZER_FOREVER,		/* keep buzzing forever */
};

typedef struct _buzzer_ioctl {
	long cmd;
	unsigned int freq;	/* sound frequency */
	unsigned int round;	/* round number to buzz */
	unsigned int buzz_time;	/* for each buzzing round, the time (millisecond) to buzz */
	unsigned int quiet_time;/* for each buzzing round, the time (millisecond) to be quiet */
} buzzer_ioctl;

static void buzzer_timer_handler(unsigned long);
int set_buzzer(struct _buzzer_ioctl*);
static void Beep(void);

static void buzzer_timer_handler_stg212(unsigned long);
int set_buzzer_stg212(struct _buzzer_ioctl*);
static void Beep_stg212(void);

/***** Buttons *****/

/* power button */
#define SOFT_POWER_OFF_TIME	3
#define FORCE_POWER_OFF_TIME	5

/* copy button */
#define DO_COPY_TIME		0

#if defined(CONFIG_ZyXEL_STG212)
#define DO_SYNC_TIME		3
#else
#define DO_SYNC_TIME		5
#endif

#define DO_DUMP_TIME		30

/* reset button */
#define RESET_USER_INFO_TIME	3
#define RESET_TO_DEFAULT_TIME	10

enum {
	BTN_OK = 0,
	BTN_SELECT,
	BTN_RESET,		/* reset to default */
	BTN_EJECT,		/* eject button, HDD remove button */

	BTN_EJECT_FRONT,	/* eject button for front USB */
	BTN_EJECT_REAR,		/* eject button for rear USB */

	BTN_POWER,
	BTN_COPY,

	BTN_WPS,		/* Wi-Fi Protected Setup */

	BTN_NONE = 65535,
};

struct _btn {
	int id;				/* button ID */
	char name[32];			/* button name */
	unsigned int gpio;		/* GPIO pin number */
	unsigned int mask;		/* GPIO mask; (1 << gpio) */
	unsigned int irq;		/* IRQ of the GPIO */
	unsigned int reg_irq_event;	/* GPIO IRQ event register */
	unsigned int reg_oe_clear;	/* GPIO OE clear register */
	unsigned int reg_debounce;	/* GPIO debounce register */
	unsigned int reg_irq_enable;	/* GPIO irq enable register; falling edge, rising edge */
	unsigned int reg_data;		/* data register (read only) */
	unsigned short active;		/* LOW_ACTIVE, HIGH_ACTIVE */

	struct timer_list timer;
	irqreturn_t (*irq_handler)(int, void*);
};

/* timer handlers */
static void ok_button_timer_handler(unsigned long);
static void select_button_timer_handler(unsigned long);
static void reset_button_timer_handler(unsigned long);
static void eject_button_timer_handler(unsigned long);
static void power_button_timer_handler(unsigned long);
static void copy_button_timer_handler(unsigned long);
static void traditional_reset_button_timer_handler(unsigned long);
static void front_eject_button_timer_handler(unsigned long);
static void rear_eject_button_timer_handler(unsigned long);

/* IRQ handlers */
static irqreturn_t ok_button_irq_handler(int, void*);
static irqreturn_t select_button_irq_handler(int, void*);
static irqreturn_t reset_button_irq_handler(int, void*);
static irqreturn_t eject_button_irq_handler(int, void*);
static irqreturn_t power_button_irq_handler(int, void*);
static irqreturn_t copy_button_irq_handler(int, void*);
static irqreturn_t front_eject_button_irq_handler(int, void*);
static irqreturn_t rear_eject_button_irq_handler(int, void*);


/***** Power Resume *****/

#define PR_DATA_GPIO		11			/* Power Resume Data GPIO */
#define PR_DATA_OE_SET		GPIO_B_OUTPUT_ENABLE_SET
#define PR_DATA_OUTPUT_SET	GPIO_B_OUTPUT_SET
#define PR_DATA_OUTPUT_CLEAR	GPIO_B_OUTPUT_CLEAR

#define PR_CLOCK_GPIO		12			/* Power Resume Clock GPIO */
#define PR_CLOCK_OE_SET		GPIO_B_OUTPUT_ENABLE_SET
#define PR_CLOCK_OUTPUT_SET	GPIO_B_OUTPUT_SET
#define PR_CLOCK_OUTPUT_CLEAR	GPIO_B_OUTPUT_CLEAR

void power_resume_set(void);
void power_resume_clear(void);


/***** I/O Control *****/

/* ioctl magic number for LED, buzzer */
#define NAS_IOC_MAGIC			'g'
#define NAS_IOC_SET_BTNCPY_PID		_IO(NAS_IOC_MAGIC, 1)
#define NAS_IOC_SET_LED			_IOW(NAS_IOC_MAGIC, 2, led_ioctl)
#define NAS_IOC_GET_LED			_IOR(NAS_IOC_MAGIC, 3, led_ioctl)

#define NAS_IOC_SET_BUZZER		_IOW(NAS_IOC_MAGIC, 4, buzzer_ioctl)

#define NAS_IOC_BUTTON_TEST_IN		_IO(NAS_IOC_MAGIC, 9)
#define NAS_IOC_BUTTON_TEST_OUT		_IO(NAS_IOC_MAGIC, 10)


#define NAS_IOC_SET_POWER_RESUME	_IO(NAS_IOC_MAGIC, 32)
#define NAS_IOC_CLR_POWER_RESUME	_IO(NAS_IOC_MAGIC, 33)



/* ioctl magic number for LCD buttons */
#define LCD_IOC_MAGIC			'k'
#define LCD_IOC_GET_MODEL		_IOR(LCD_IOC_MAGIC, 0, unsigned long)

#define LCD_IOC_SET_PID			_IOW(LCD_IOC_MAGIC, 1, unsigned long)

#define LCD_IOC_SET_BACKLIGHT		_IOW(LCD_IOC_MAGIC, 5, unsigned long)

#define LCD_IOC_GET_BTN			_IOR(LCD_IOC_MAGIC, 10, unsigned long)

#define LCD_IOC_BTN_MENU		_IO(LCD_IOC_MAGIC, 11)
#define LCD_IOC_BTN_ESC			_IO(LCD_IOC_MAGIC, 12)
#define LCD_IOC_BTN_UP			_IO(LCD_IOC_MAGIC, 13)
#define LCD_IOC_BTN_DOWN		_IO(LCD_IOC_MAGIC, 14)
#define LCD_IOC_BTN_LEFT		_IO(LCD_IOC_MAGIC, 15)
#define LCD_IOC_BTN_RIGHT		_IO(LCD_IOC_MAGIC, 16)



/***** Miscellaneous *****/

void zyxel_power_off(void);

extern void kernel_power_off(void);
extern void show_mem(void);

#endif

