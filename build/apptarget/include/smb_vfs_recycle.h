/* 
 *	SAMBA VFS MODULE RECYCLE BIN MANAGEMENT HEADER FILE
 *	Used by ZySH and SAMBA's vfs_recycle.c
 *	Version: 0.1 (2008/01/30) By Chorus
 * 	Revision History:
 *		0.1: Initial Version
*/

#ifndef _SMB_VFS_RECYCLE_H
#define _SMB_VFS_RECYCLE_H

#define SMB_VFS_RECYCLE_FN	".THIS_IS_RECYCLE_BIN"	/* for vfs_recycle.c to generate file in recycle bin */
#define SMB_VFS_RECYCLE_RBM_FN	".RBM"			/* for storing time of oldest file */
#define SMB_VFS_RECYCLE_DIR	"recycle"	/* for zysh to generate smb.conf */
#define SMB_VFS_RECYCLE_DIR_LEN	7

/* .RBM file structure (to store info of Recycle-Bin Manager (chorus) */
/* .RBM file is the file stored in the first level of recycle-bin directory */
/* Every time the RBM run, it will read .RBM to get previous info and update it when it finish */
typedef struct rbm_info
{
	time_t of_t;		/* Oldest file access time */
	time_t lock_t;		/* Lock time of calling RBM from ZySH: when RBM is called in this recycle-bin, it store the run time, when it finished, it store 0 */
	pid_t pid;		/* Process ID of current running RBM */
}rbm_info_t;

#define RBM_TIMEOUT_SECONDS	38400	/* Timeout to wait previous RBM to finish in this recycle-bin */
#define RBM_ONE_DAY_IN_SECONDS	86400	/* One day is 86400 seconds, define this for easy debugging */
//#define RBM_ONE_DAY_IN_SECONDS	10	/* One day is 10 seconds for debugging */

#endif /* _SMB_VFS_RECYCLE_H */
