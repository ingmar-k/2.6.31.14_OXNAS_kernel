/*
 * arch/arm/plat-oxnas/include/mach/fast_open_filter.h
 *
 * Copyright (C) 2010 Oxford Semiconductor Ltd
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
#ifndef FAST_OPEN_FILTER_H
#define FAST_OPEN_FILTER_H

extern int fast_open_filter(struct file *file, struct inode *inode);
extern void fast_close_filter(struct file* file);
extern int non_fast_access_denied(struct file *file);
extern int begin_truncate(struct inode *inode);
extern void end_truncate(struct inode *inode);

#endif        //  #ifndef FAST_OPEN_FILTER_H


