/*********************************************************************************
 * Filename:  iscsi_auth_chap.c
 *
 * This file houses the main functions for the iSCSI Chap support
 *
 * Copyright (c) 2002, 2003, 2004, 2005 PyX Technologies, Inc.
 * Copyright (c) 2005, 2006, 2007 SBE, Inc.
 * Copyright (c) 2007-2009 Linux-iSCSI.org
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
 *********************************************************************************/

#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/random.h>

#include <iscsi_linux_os.h>
#include <iscsi_linux_defs.h>
#include <iscsi_protocol.h>
#include <iscsi_target_core.h>
#include <iscsi_auth.h>
#include <iscsi_auth_chap.h>

#ifdef DEBUG_CHAP
#define PRINT(x...)		printk(KERN_INFO x)
#else
#define PRINT(x...)
#endif 
		
unsigned char chap_asciihex_to_binaryhex(unsigned char val[2])
{
	unsigned char result = 0;
	/*
	 * MSB
	 */
	if ((val[0] >= 'a') && (val[0] <= 'f'))
		result = ((val[0] - 'a' + 10) & 0xf) << 4;
	else
		if ((val[0] >= 'A') && (val[0] <= 'F'))
			result = ((val[0] - 'A' + 10) & 0xf) << 4;
		else // digit
			result = ((val[0] - '0') & 0xf) << 4;
	/*
	 * LSB
	 */
	if ((val[1] >= 'a') && (val[1] <= 'f'))
		result |= ((val[1] - 'a' + 10) & 0xf);
	else
		if ((val[1] >= 'A') && (val[1] <= 'F'))
			result |= ((val[1] - 'A' + 10) & 0xf);
       		else // digit
			result |= ((val[1] - '0') & 0xf);	

	return result;
}

int chap_string_to_hex(unsigned char *dst, unsigned char *src, int len)
{
	int i = 0, j = 0;

	for (i = 0; i < len; i += 2)
		dst[j++] = (unsigned char) chap_asciihex_to_binaryhex(&src[i]);
	
	dst[j] = '\0';
	return j;
}	

void chap_binaryhex_to_asciihex(char *dst, char *src, int src_len)
{
	int i;

	for (i = 0; i < src_len; i++)
		sprintf(&dst[i*2], "%02x", (int) src[i] & 0xff);
}

void chap_set_random(char *data, int length)
{
	long r;
	unsigned n;

	while (length > 0) {

		get_random_bytes(&r, sizeof(long));
		r = r ^ (r >> 8);
		r = r ^ (r >> 4);
		n = r & 0x7;

		get_random_bytes(&r, sizeof(long));
		r = r ^ (r >> 8);
		r = r ^ (r >> 5);
		n = (n << 3) | (r & 0x7);

		get_random_bytes(&r, sizeof(long));
		r = r ^ (r >> 8);
		r = r ^ (r >> 5);
		n = (n << 2) | (r & 0x3);

		*data++ = n;
		 length--;
	}
}
	
int chap_gen_challenge(iscsi_conn_t *, int, char *, unsigned int *);

static iscsi_chap_t *chap_server_open(
	iscsi_conn_t *conn,
	iscsi_node_auth_t *auth,
	const char *A_str,
	char *AIC_str,
	unsigned int *AIC_len)
{
	iscsi_chap_t *chap;
	int ret;

	if (!(auth->naf_flags & NAF_USERID_SET) ||
	    !(auth->naf_flags & NAF_PASSWORD_SET)) {
		printk(KERN_ERR "CHAP user or password not set for"
				" Initiator ACL\n");
		return NULL;
	}

	conn->auth_protocol = kzalloc(sizeof(iscsi_chap_t), GFP_KERNEL);
	if (!(conn->auth_protocol))
		return NULL;

	chap = (iscsi_chap_t *) conn->auth_protocol;
	/*
	 * We only support MD5 MDA presently.
	 */
	if (strncmp(A_str, "CHAP_A=5", 8)) {
		printk(KERN_ERR "CHAP_A is not MD5.\n");
		return NULL;
	}
	PRINT("[server] Got CHAP_A=5\n");
	/*
	 * Send back CHAP_A set to MD5.
	 */
	*AIC_len = sprintf(AIC_str, "CHAP_A=5");
	*AIC_len += 1;
	chap->digest_type = CHAP_DIGEST_MD5;
	PRINT("[server] Sending CHAP_A=%d\n", chap->digest_type);
	/*
	 * Set Identifier.
	 */
	chap->id = ISCSI_TPG_C(conn)->tpg_chap_id++;
	*AIC_len += sprintf(AIC_str+*AIC_len, "CHAP_I=%d", chap->id);
	*AIC_len += 1;
	PRINT("[server] Sending CHAP_I=%d\n", chap->id);
	/*
	 * Generate Challenge.
	 */
	ret = chap_gen_challenge(conn, 1, AIC_str, AIC_len);
	if (ret < 0)
		return NULL;

	return chap;
}

void chap_close(iscsi_conn_t *conn)
{
	kfree(conn->auth_protocol);
	conn->auth_protocol = NULL;
}

int chap_gen_challenge(
	iscsi_conn_t *conn,
	int caller,
	char *C_str,
	unsigned int *C_len)
{
	unsigned char challenge_asciihex[CHAP_CHALLENGE_LENGTH * 2 + 1];
	iscsi_chap_t *chap = (iscsi_chap_t *) conn->auth_protocol;

	memset(challenge_asciihex, 0, CHAP_CHALLENGE_LENGTH * 2 + 1);
	
	chap_set_random(chap->challenge, CHAP_CHALLENGE_LENGTH);
	chap_binaryhex_to_asciihex(challenge_asciihex, chap->challenge,
					CHAP_CHALLENGE_LENGTH);
	/*
	 * Set CHAP_C, and copy the generated challenge into C_str.
	 */
	*C_len += sprintf(C_str+*C_len, "CHAP_C=0x%s", challenge_asciihex);
	*C_len += 1;

	PRINT("[%s] Sending CHAP_C=0x%s\n\n", (caller) ? "server" : "client",
			challenge_asciihex);
	return 0;
}

int chap_server_compute_md5(
	iscsi_conn_t *conn,
	iscsi_node_auth_t *auth,
	char *NR_in_ptr,
	char *NR_out_ptr,
	unsigned int *NR_out_len)
{
	char *endptr;
	unsigned char id;
	unsigned char type, response[MD5_SIGNATURE_SIZE * 2 + 2], digest[MD5_SIGNATURE_SIZE];
	unsigned char identifier[10], *challenge, *challenge_binhex;
	unsigned char client_digest[MD5_SIGNATURE_SIZE], server_digest[MD5_SIGNATURE_SIZE];
	unsigned char chap_n[MAX_CHAP_N_SIZE], chap_r[MAX_RESPONSE_LENGTH];
	iscsi_chap_t *chap = (iscsi_chap_t *) conn->auth_protocol;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19)
	struct crypto_hash *tfm;
	struct hash_desc desc;
#else
	struct crypto_tfm *tfm;
#endif
	struct scatterlist sg;
	int auth_ret = -1, ret, challenge_len;
	
	memset(identifier, 0, 10);
	memset(chap_n, 0, MAX_CHAP_N_SIZE);
	memset(chap_r, 0, MAX_RESPONSE_LENGTH);
	memset(digest, 0, MD5_SIGNATURE_SIZE);
	memset(response, 0, MD5_SIGNATURE_SIZE * 2 + 2);
	memset(client_digest, 0, MD5_SIGNATURE_SIZE);
	memset(server_digest, 0, MD5_SIGNATURE_SIZE);

	challenge = kzalloc(CHAP_CHALLENGE_STR_LEN, GFP_KERNEL);
	if (!(challenge)) {
		printk(KERN_ERR "Unable to allocate challenge buffer\n");
		return -1;
	}

	challenge_binhex = kzalloc(CHAP_CHALLENGE_STR_LEN, GFP_KERNEL);
	if (!(challenge_binhex)) {
		printk(KERN_ERR "Unable to allocate challenge_binhex buffer\n");
		kfree(challenge);
		return -1;
	}
	/*
	 * Extract CHAP_N.
	 */
	if (extract_param(NR_in_ptr, "CHAP_N", MAX_CHAP_N_SIZE, chap_n,
				&type) < 0) {
		printk(KERN_ERR "Could not find CHAP_N.\n");
		goto out;
	}
	if (type == HEX) {
		printk(KERN_ERR "Could not find CHAP_N.\n");
		goto out;
	}

	if (memcmp(chap_n, auth->userid, strlen(auth->userid)) != 0) {
		printk(KERN_ERR "CHAP_N values do not match!\n");
		goto out;
	}
	PRINT("[server] Got CHAP_N=%s\n", chap_n);
	/*
	 * Extract CHAP_R.
	 */
	if (extract_param(NR_in_ptr, "CHAP_R", MAX_RESPONSE_LENGTH, chap_r,
				&type) < 0) {
		printk(KERN_ERR "Could not find CHAP_R.\n");
		goto out;
	}
	if (type != HEX) {
		printk(KERN_ERR "Could not find CHAP_R.\n");
		goto out;
	}

	PRINT("[server] Got CHAP_R=%s\n", chap_r);
	chap_string_to_hex(client_digest, chap_r, strlen(chap_r));

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19)
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "Unable to allocate struct crypto_hash\n");
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	ret = crypto_hash_init(&desc);
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_init() failed\n");
		crypto_free_hash(tfm);
		goto out;
	}

	sg_init_one(&sg, (void *)&chap->id, 1);
	ret = crypto_hash_update(&desc, &sg, 1);
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_update() failed for id\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	sg_init_one(&sg, (void *)&auth->password, strlen(auth->password));
	ret = crypto_hash_update(&desc, &sg, strlen(auth->password));
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_update() failed for password\n");
		crypto_free_hash(tfm);
		goto out;
	}

	sg_init_one(&sg, (void *)chap->challenge, strlen(chap->challenge));
	ret = crypto_hash_update(&desc, &sg, strlen(chap->challenge));
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_update() failed for challenge\n");
		crypto_free_hash(tfm);
		goto out;
	}

	ret = crypto_hash_final(&desc, server_digest);
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_final() failed for server digest\n");
		crypto_free_hash(tfm);
		goto out;
	}
	crypto_free_hash(tfm);
#else
	tfm = crypto_alloc_tfm("md5", 0);
	if (!(tfm)) {
		printk(KERN_ERR "crypto_alloc_tfm() failed for md5\n");
		goto out;
	}

	crypto_digest_init(tfm);

	sg_init_one(&sg, (void *)&chap->id, 1);
	crypto_digest_update(tfm, &sg, 1);

	sg_init_one(&sg, (void *)&auth->password, strlen(auth->password));
	crypto_digest_update(tfm, &sg, 1);

	sg_init_one(&sg, (void *)chap->challenge, strlen(chap->challenge));
	crypto_digest_update(tfm, &sg, 1);

	crypto_digest_final(tfm, server_digest);
	crypto_free_tfm(tfm);
#endif
	chap_binaryhex_to_asciihex(response, server_digest, MD5_SIGNATURE_SIZE);
	PRINT("[server] MD5 Server Digest: %s\n", response);

	if (memcmp(server_digest, client_digest, MD5_SIGNATURE_SIZE) != 0) {
		PRINT("[server] MD5 Digests do not match!\n\n");
		goto out;
	} else
		PRINT("[server] MD5 Digests match, CHAP connetication successful.\n\n");
	/*
	 * One way authentication has succeeded, return now if mutual authentication
	 * is not enabled.
	 */
	if (!auth->authenticate_target) {
		kfree(challenge);
		kfree(challenge_binhex);
		return 0;
	}
	/*
	 * Get CHAP_I.
	 */
	if (extract_param(NR_in_ptr, "CHAP_I", 10, identifier, &type) < 0) {
		printk(KERN_ERR "Could not find CHAP_I.\n");
		goto out;
	}

	if (type == HEX)
		id = (unsigned char) simple_strtoul((char *)&identifier[2],
					&endptr, 0);
	else
		id = (unsigned char ) simple_strtoul(identifier, &endptr, 0);
	/*
	 * RFC 1994 says Identifier is no more than octet (8 bits).
	 */
	PRINT("[server] Got CHAP_I=%d\n", id);
	/*
	 * Get CHAP_C.
	 */
	if (extract_param(NR_in_ptr, "CHAP_C", CHAP_CHALLENGE_STR_LEN,
			challenge, &type) < 0) {
		printk(KERN_ERR "Could not find CHAP_C.\n");
		goto out;
	}

	if (type != HEX) {
		printk(KERN_ERR "Could not find CHAP_C.\n");
		goto out;
	}
	PRINT("[server] Got CHAP_C=%s\n", challenge);
	challenge_len = chap_string_to_hex(challenge_binhex, challenge,
				strlen(challenge));
	if (!(challenge_len)) {
		printk(KERN_ERR "Unable to convert incoming challenge\n");
		goto out;
	}
	/*
	 * Generate CHAP_N and CHAP_R for mutual authentication.
	 */
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,19)
	tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		printk(KERN_ERR "Unable to allocate struct crypto_hash\n");
		goto out;
	}
	desc.tfm = tfm;
	desc.flags = 0;

	ret = crypto_hash_init(&desc);
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_init() failed\n");
		crypto_free_hash(tfm);
		goto out;
	}

	sg_init_one(&sg, (void *)&id, 1);
	ret = crypto_hash_update(&desc, &sg, 1);
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_update() failed for id\n");
		crypto_free_hash(tfm);
		goto out;
	}
	
	sg_init_one(&sg, (void *)auth->password_mutual, strlen(auth->password_mutual));
	ret = crypto_hash_update(&desc, &sg, strlen(auth->password_mutual));
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_update() failed for password_mutual\n");		
		crypto_free_hash(tfm);
		goto out;
	}
	/*
	 * Convert received challenge to binary hex.
	 */
	sg_init_one(&sg, (void *)challenge_binhex, challenge_len);
	ret = crypto_hash_update(&desc, &sg, challenge_len);
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_update() failed for ma challenge\n");
		crypto_free_hash(tfm);
		goto out;
	}

	ret = crypto_hash_final(&desc, digest);
	if (ret < 0) {
		printk(KERN_ERR "crypto_hash_final() failed for ma digest\n");
		crypto_free_hash(tfm);
		goto out;
	}
	crypto_free_hash(tfm);
#else
	tfm = crypto_alloc_tfm("md5", 0);
	if (!(tfm)) {
		printk(KERN_ERR "crypto_alloc_tfm() failed for md5\n");
		goto out;
	}

	crypto_digest_init(tfm);

	sg_init_one(&sg, (void *)&id, 1);
	crypto_digest_update(tfm, &sg, 1);
	
	sg_init_one(&sg, (void *)auth->password_mutual, strlen(auth->password_mutual));
	crypto_digest_update(tfm, &sg, 1);

	sg_init_one(&sg, (void *)challenge_binhex, challenge_len);
	crypto_digest_update(tfm, &sg, 1);
	
	crypto_digest_final(tfm, digest);
	crypto_free_tfm(tfm);
#endif
	/*
	 * Generate CHAP_N and CHAP_R.
	 */
	*NR_out_len = sprintf(NR_out_ptr, "CHAP_N=%s", auth->userid_mutual);
	*NR_out_len += 1;
	PRINT("[server] Sending CHAP_N=%s\n", auth->userid_mutual);
	/*
	 * Convert response from binary hex to ascii hext.
	 */
	chap_binaryhex_to_asciihex(response, digest, MD5_SIGNATURE_SIZE);
	*NR_out_len += sprintf(NR_out_ptr+*NR_out_len, "CHAP_R=0x%s", response);
	*NR_out_len += 1;
	PRINT("[server] Sending CHAP_R=0x%s\n", response);
	auth_ret = 0;
out:
	kfree(challenge);
	kfree(challenge_binhex);
	return auth_ret;	
}

int chap_got_response(
	iscsi_conn_t *conn,
	iscsi_node_auth_t *auth,
	char *NR_in_ptr,
	char *NR_out_ptr,
	unsigned int *NR_out_len)
{
	iscsi_chap_t *chap = (iscsi_chap_t *) conn->auth_protocol;

	switch (chap->digest_type) {
	case CHAP_DIGEST_MD5:
		if (chap_server_compute_md5(conn, auth, NR_in_ptr,
				NR_out_ptr, NR_out_len) < 0)
			return -1;
		break;		
	default:
		printk(KERN_ERR "Unknown CHAP digest type %d!\n",
				chap->digest_type);
		return -1;
	}
	
	return 0;
}

u32 chap_main_loop(
	iscsi_conn_t *conn,
	iscsi_node_auth_t *auth,
	char *in_text,
	char *out_text,
	int *in_len,
	int *out_len)
{
	iscsi_chap_t *chap = (iscsi_chap_t *) conn->auth_protocol;

	if (!(chap)) {
		chap = chap_server_open(conn, auth, in_text, out_text, out_len);
		if (!(chap))
			return 2;
		chap->chap_state = CHAP_STAGE_SERVER_AIC;
		return 0;
	} else if (chap->chap_state == CHAP_STAGE_SERVER_AIC) {
		convert_null_to_semi(in_text, *in_len);
		if (chap_got_response(conn, auth, in_text, out_text,
				out_len) < 0) {
			chap_close(conn);
			return 2;
		}
		if (auth->authenticate_target)
			chap->chap_state = CHAP_STAGE_SERVER_NR;
		else
			*out_len = 0;
		chap_close(conn);
		return 1;
	}

	return 2;
}
