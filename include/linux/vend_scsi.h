/* vend-scsi.h - header describing the ioctl interface used to control the
 * operation of the VSC handler module in the kernel.
 * 
 * Copyright (C) 2010 J Larkworthy PLX Technology Inc
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the above-listed copyright holders may not be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* vendor scsi ioctl definitions */


#define VEND_IORESET  0x5390
#define VEND_IOSCMD   0x5391
#define VEND_IOSRPLY  0x5392
#define VEND_IOSTRT   0x5393
#define VEND_IOSTOP   0x5394

#define LENGTH_TYPE_FIXED       0
#define LENGTH_TYPE_VARIABLE    1

#define BULK_DATA_DIR_TO_HOST   1
#define BULK_DATA_DIR_FROM_HOST 0

struct scsi_control {
	union {
		struct {
			char scsi_cmd ; // byte 0 of command for comparison
			char scsi_sub_cmd; // byte 1 of command for comparison.
			char cmd_length;
			char data_direction; // 0=from host, 1=to host
			char length_type ; // 0= fixed, 1= variable
			char length_msb ; // msb for fixed, index for byte of msb in command.
			char length_lsb ;
		} cmd_format;
		struct {
			__u32  sense_data; 
			__u32 sense_data_info; 
		} set_sense_data;
	} option;
};

