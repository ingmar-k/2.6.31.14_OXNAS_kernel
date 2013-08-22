/*********************************************************************************
 * Filename:  iscsi_auth_chap.h
 *
 * This file contains definitions related to iSCSI CHAP Authenication.
 *
 * Copyright (c) 2006-2007 SBE, Inc.  All Rights Reserved.
 * Copyright (c) 2007-2009 Linux-iSCSI.org
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * For further information, contact via email: support@sbei.com
 * SBE, Inc.  San Ramon, California  U.S.A.
 *********************************************************************************/


#ifndef _ISCSI_CHAP_H_
#define _ISCSI_CHAP_H_

#define CHAP_DIGEST_MD5		5
#define CHAP_DIGEST_SHA		6

#define CHAP_CHALLENGE_LENGTH	16
#define CHAP_CHALLENGE_STR_LEN	4096
#define MAX_RESPONSE_LENGTH	64	/* sufficient for MD5 */
#define	MAX_CHAP_N_SIZE		512

#define MD5_SIGNATURE_SIZE	16	/* 16 bytes in a MD5 message digest */

#define CHAP_STAGE_CLIENT_A	1
#define CHAP_STAGE_SERVER_AIC	2
#define CHAP_STAGE_CLIENT_NR	3
#define CHAP_STAGE_CLIENT_NRIC	4
#define CHAP_STAGE_SERVER_NR	5

extern int chap_gen_challenge(iscsi_conn_t *, int, char *, unsigned int *);
extern u32 chap_main_loop(iscsi_conn_t *, iscsi_node_auth_t *, char *, char *,
				int *, int *);

typedef struct iscsi_chap_s {
	unsigned char	digest_type;
	unsigned char	id;
	unsigned char	challenge[CHAP_CHALLENGE_LENGTH];
	unsigned int	challenge_len;
	unsigned int	authenticate_target;
	unsigned int	chap_state;
} iscsi_chap_t;	

#endif   /*** _ISCSI_CHAP_H_ ***/
