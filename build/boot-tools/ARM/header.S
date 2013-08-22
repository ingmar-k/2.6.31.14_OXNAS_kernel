/*
 *	Oxford Semiconductor Ltd 2005
 *
 *	Created: John Larkworthy 28 July 2005
 *
 *	Title  : start.s
 *
 *	Description:
 *		This is a header prefixed to the loaded code. It provides the structure and 
 *		entry point for the loaded software.
 *
 *	Modifications:
 *      JJL: 08/08/07   Restructured to provide space for boot loader validation
 *      JJL: 09/04/08   Change to possition independent code may be used to prefix any module requiring validation
 */	
.section .init
.org 0
	add pc,pc,#header_crc

.org 0x30 
image_length: .word 0
image_crc: .word 0
header_crc: .word 0

/* end of header so start code here
 */
 /* allow room for a small stack and offset by 4 for nop instruction */
start:
	nop
/* The working image is appended here. It should start with an executable 
 * instruction so that the nop 'rolls' into the instruction.
 */
