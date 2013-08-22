/* linux/include/asm-arm/arch-oxnas/timex.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#ifndef __ASM_ARCH_TIMEX_H
#define __ASM_ARCH_TIMEX_H

#define TIMER_PRESCALE_BIT      2
#define TIMER_PRESCALE_1        0
#define TIMER_PRESCALE_16       1
#define TIMER_PRESCALE_256      2

#define TIMER_INPUT_CLOCK      CONFIG_NOMINAL_RPSCLK_FREQ

#define TIMER_1_MODE           TIMER_MODE_PERIODIC
#define TIMER_1_PRESCALE_ENUM  TIMER_PRESCALE_1
#define TIMER_1_PRESCALE_VALUE (1 << (TIMER_1_PRESCALE_ENUM * 4))
#define TIMER_1_PRESCALED_CLK  (TIMER_INPUT_CLOCK / TIMER_1_PRESCALE_VALUE)
#define CLOCK_TICK_RATE        (TIMER_1_PRESCALED_CLK)
#define TIMER_1_LOAD_VALUE     ((CLOCK_TICK_RATE) / HZ)

#define TIMER_2_MODE           TIMER_MODE_FREE_RUNNING
#define TIMER_2_PRESCALE_ENUM  TIMER_PRESCALE_16
#define TIMER_2_PRESCALE_VALUE (1 << (TIMER_2_PRESCALE_ENUM * 4))
#define TIMER_2_PRESCALED_CLK  (TIMER_INPUT_CLOCK / TIMER_2_PRESCALE_VALUE)
#define TIMER_2_LOAD_VALUE     (0xffffff)

#endif // __ASM_ARCH_TIMEX_H
