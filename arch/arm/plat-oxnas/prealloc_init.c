/*
 * arch/arm/plat-oxnas/prealloc_init.c
 *
 * Copyright (C) 2008, 2009, 2010 Oxford Semiconductor Ltd
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
#include <mach/prealloc_init.h>

/*
 * writer filemap semaphore should be held around calls to this function
 */
void do_prealloc_init(
	struct inode *inode,
	struct file  *file)
{
	if (unlikely(!inode->prealloc_initialised)) {
		int use_prealloc = file->f_flags & O_PREALLOC;
		int use_fast     = file->f_flags & O_FAST;
		int fast_capable = supports_fast_mode(file, inode);

		inode->prealloc_initialised = 1;

		WARN_ON(use_prealloc && !file->f_op->preallocate);
		WARN_ON(use_fast && !fast_capable);
		WARN_ON(use_fast && !use_prealloc);

		if (use_prealloc) {
			inode->prealloc_size = i_size_read(inode);

			inode->do_space_reserve = 1;

			if (!strncmp(inode->i_sb->s_type->name, "ext4", 4)) {
				// Implies preallocate space gets reset on truncate
				inode->truncate_space_reset = 1;
			} else {
				inode->truncate_space_reset = 0;
			}
		} else {
			inode->do_space_reserve = 0;
			inode->prealloc_size = 0;
			inode->truncate_space_reset = 0;
		}
	}
}
