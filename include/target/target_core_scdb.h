/*******************************************************************************
 * Filename:  target_core_scdb.h
 *
 * This file contains the iSCSI Transport Split CDB related definitions.
 *
 * Copyright (c) 2004-2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
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


#ifndef TARGET_CORE_SCDB_H
#define TARGET_CORE_SCDB_H

extern void split_cdb_XX_6(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_6(unsigned long long, u32 *, unsigned char *, int);
extern void split_cdb_XX_10(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_10(unsigned long long, u32 *, unsigned char *, int);
extern void split_cdb_XX_12(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_12(unsigned long long, u32 *, unsigned char *, int);
extern void split_cdb_XX_16(unsigned long long, u32 *, unsigned char *);
extern void split_cdb_RW_16(unsigned long long, u32 *, unsigned char *, int);

#endif /* TARGET_CORE_SCDB_H */
