/*
 *	Oxford Semiconductor Ltd 2005
 *
 *	Created: John Larkworthy 10 April 2008
 *
 *	Title  : relocate.S
 *
 *	Description:
 *		This module relocates the following block to high memory before jumping into the main entry point.
 *
 *	Modifications:
 */	

working_location=0x5801f800


.section .init
.org 0

start:
	sub    r0, pc, #8
	ldr    r1, =working_location
	add    r2, r0, #0x3fc

copy_loop:
	ldmia	r0!, {r3-r10}	/* copy from source address [r0] */
	stmia	r1!, {r3-r10}	/* copy to   target address [r1] */
	cmp	r0, r2				/* until source end addreee [r2] */
	ble	copy_loop

	ldr     pc, =main

