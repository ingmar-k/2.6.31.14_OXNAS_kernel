#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <getopt.h>

#include <mtd/mtd-user.h>


unsigned int ecc_size, ecc_byte, page_size, oob_size;

static struct nand_oobinfo oob_layout = {
	.useecc = MTD_NANDECC_AUTOPLACE,
	.eccbytes = 24,
	.eccpos = {
		40, 41, 42, 43, 44, 45, 46, 47,
		48, 49, 50, 51, 52, 53, 54, 55,
		56, 57, 58, 59, 60, 61, 62, 63},
	.oobfree = { {2, 38} }
};


/*
 *  * Pre-calculated 256-way 1 byte column parity
 *   */
static const u_char nand_ecc_precalc_table[] = {
	0x00, 0x55, 0x56, 0x03, 0x59, 0x0c, 0x0f, 0x5a, 0x5a, 0x0f, 0x0c, 0x59, 0x03, 0x56, 0x55, 0x00,
	0x65, 0x30, 0x33, 0x66, 0x3c, 0x69, 0x6a, 0x3f, 0x3f, 0x6a, 0x69, 0x3c, 0x66, 0x33, 0x30, 0x65,
	0x66, 0x33, 0x30, 0x65, 0x3f, 0x6a, 0x69, 0x3c, 0x3c, 0x69, 0x6a, 0x3f, 0x65, 0x30, 0x33, 0x66,
	0x03, 0x56, 0x55, 0x00, 0x5a, 0x0f, 0x0c, 0x59, 0x59, 0x0c, 0x0f, 0x5a, 0x00, 0x55, 0x56, 0x03,
	0x69, 0x3c, 0x3f, 0x6a, 0x30, 0x65, 0x66, 0x33, 0x33, 0x66, 0x65, 0x30, 0x6a, 0x3f, 0x3c, 0x69,
	0x0c, 0x59, 0x5a, 0x0f, 0x55, 0x00, 0x03, 0x56, 0x56, 0x03, 0x00, 0x55, 0x0f, 0x5a, 0x59, 0x0c,
	0x0f, 0x5a, 0x59, 0x0c, 0x56, 0x03, 0x00, 0x55, 0x55, 0x00, 0x03, 0x56, 0x0c, 0x59, 0x5a, 0x0f,
	0x6a, 0x3f, 0x3c, 0x69, 0x33, 0x66, 0x65, 0x30, 0x30, 0x65, 0x66, 0x33, 0x69, 0x3c, 0x3f, 0x6a,
	0x6a, 0x3f, 0x3c, 0x69, 0x33, 0x66, 0x65, 0x30, 0x30, 0x65, 0x66, 0x33, 0x69, 0x3c, 0x3f, 0x6a,
	0x0f, 0x5a, 0x59, 0x0c, 0x56, 0x03, 0x00, 0x55, 0x55, 0x00, 0x03, 0x56, 0x0c, 0x59, 0x5a, 0x0f,
	0x0c, 0x59, 0x5a, 0x0f, 0x55, 0x00, 0x03, 0x56, 0x56, 0x03, 0x00, 0x55, 0x0f, 0x5a, 0x59, 0x0c,
	0x69, 0x3c, 0x3f, 0x6a, 0x30, 0x65, 0x66, 0x33, 0x33, 0x66, 0x65, 0x30, 0x6a, 0x3f, 0x3c, 0x69,
	0x03, 0x56, 0x55, 0x00, 0x5a, 0x0f, 0x0c, 0x59, 0x59, 0x0c, 0x0f, 0x5a, 0x00, 0x55, 0x56, 0x03,
	0x66, 0x33, 0x30, 0x65, 0x3f, 0x6a, 0x69, 0x3c, 0x3c, 0x69, 0x6a, 0x3f, 0x65, 0x30, 0x33, 0x66,
	0x65, 0x30, 0x33, 0x66, 0x3c, 0x69, 0x6a, 0x3f, 0x3f, 0x6a, 0x69, 0x3c, 0x66, 0x33, 0x30, 0x65,
	0x00, 0x55, 0x56, 0x03, 0x59, 0x0c, 0x0f, 0x5a, 0x5a, 0x0f, 0x0c, 0x59, 0x03, 0x56, 0x55, 0x00
};


int nand_calculate_ecc(const unsigned char *dat,
			  unsigned char *ecc_code)
{
	uint8_t idx, reg1, reg2, reg3, tmp1, tmp2;
	int i;

	/* Initialize variables */
	reg1 = reg2 = reg3 = 0;

	/* Build up column parity */
	for(i = 0; i < 256; i++) {
		/* Get CP0 - CP5 from table */
		idx = nand_ecc_precalc_table[*dat++];
		reg1 ^= (idx & 0x3f);

		/* All bit XOR = 1 ? */
		if (idx & 0x40) {
			reg3 ^= (uint8_t) i;
			reg2 ^= ~((uint8_t) i);
		}
	}

	/* Create non-inverted ECC code from line parity */
	tmp1  = (reg3 & 0x80) >> 0; /* B7 -> B7 */
	tmp1 |= (reg2 & 0x80) >> 1; /* B7 -> B6 */
	tmp1 |= (reg3 & 0x40) >> 1; /* B6 -> B5 */
	tmp1 |= (reg2 & 0x40) >> 2; /* B6 -> B4 */
	tmp1 |= (reg3 & 0x20) >> 2; /* B5 -> B3 */
	tmp1 |= (reg2 & 0x20) >> 3; /* B5 -> B2 */
	tmp1 |= (reg3 & 0x10) >> 3; /* B4 -> B1 */
	tmp1 |= (reg2 & 0x10) >> 4; /* B4 -> B0 */

	tmp2  = (reg3 & 0x08) << 4; /* B3 -> B7 */
	tmp2 |= (reg2 & 0x08) << 3; /* B3 -> B6 */
	tmp2 |= (reg3 & 0x04) << 3; /* B2 -> B5 */
	tmp2 |= (reg2 & 0x04) << 2; /* B2 -> B4 */
	tmp2 |= (reg3 & 0x02) << 2; /* B1 -> B3 */
	tmp2 |= (reg2 & 0x02) << 1; /* B1 -> B2 */
	tmp2 |= (reg3 & 0x01) << 1; /* B0 -> B1 */
	tmp2 |= (reg2 & 0x01) << 0; /* B7 -> B0 */

	/* Calculate final ECC code */
#ifdef CONFIG_MTD_NAND_ECC_SMC
	ecc_code[0] = ~tmp2;
	ecc_code[1] = ~tmp1;
#else
	ecc_code[0] = ~tmp1;
	ecc_code[1] = ~tmp2;
#endif
	ecc_code[2] = ((~reg1) << 2) | 0x03;

	return 0;

}



void usage()
{
	fprintf(stderr, "mknandimg_ecc [img_path] [oob size = 64] [ecc size = 256] [ecc byte = 3] [page size = 2048]\n");
	
}



static void nand_page_ecc(
			char* buf, char* oob, 
			unsigned int eccsize, 
			unsigned int eccbytes, 
			unsigned int page_size)
{
	int eccsteps, i;
	int *eccpos = oob_layout.eccpos;
	char *ecc_calc;

	eccsteps = page_size / eccsize;
	ecc_calc = (char *)malloc(oob_layout.eccbytes + 1);
	memset(ecc_calc, 0xff, oob_layout.eccbytes + 1);

	/* Software ecc calculation */
	for (i = 0; eccsteps; eccsteps--, i += eccbytes, buf += eccsize)
		nand_calculate_ecc(buf, &ecc_calc[i]);
	
	for (i = 0; i < oob_layout.eccbytes; i++)
		oob[eccpos[i]] = ecc_calc[i];

	free(ecc_calc);

}

int main(int argc, char *argv[])
{
	int in_fd = -1, out_fd = -1;
	unsigned long long file_size;
	struct stat sb;
	char	*page_buf = NULL, *out_file_name = NULL, *oob_buf = NULL;
	

	if(argc != 6)
	{
		usage();
		return -1;
	}

	oob_size = strtoul(argv[2], NULL, 10);
	ecc_size = strtoul(argv[3], NULL, 10);
	ecc_byte = strtoul(argv[4], NULL, 10);
	page_size = strtoul(argv[5], NULL, 10);

	if(page_size % ecc_size != 0)
	{
		fprintf(stderr, "Page size is not aligned to ecc size\n");
		goto RET;
	}


	if((in_fd = open(argv[1], O_RDONLY)) < 0)
	{
		fprintf(stderr, "Can not open %s to read image. \n", argv[1]);
		goto RET;
	}

	out_file_name = (char *)malloc(strlen(argv[1]) + 10);
	sprintf(out_file_name, "%s.ecc.img", argv[1]);
	out_fd = open(out_file_name, O_RDWR | O_CREAT);

	stat(argv[1], &sb);
	file_size = sb.st_size;

	if((page_buf = (char *)malloc(page_size)) == NULL)
	{
		fprintf(stderr, "Can not alloc memory for page\n");
		goto RET;
	}

	oob_buf = (char *)malloc(oob_size);
	
	while(file_size > 0)
	{
		unsigned long read_size, rev;;
	
		read_size = (file_size > page_size)? page_size : file_size;
		memset(page_buf, 0xff, page_size);

		rev = read(in_fd, page_buf, read_size);
		if(rev < 0)
		{
			fprintf(stderr, "Read size error\n");
			goto RET;
		}

		memset(oob_buf, 0xff, oob_size);
		nand_page_ecc(page_buf, oob_buf, ecc_size, ecc_byte, page_size);
		file_size -= read_size;
		write(out_fd, page_buf, page_size);
		write(out_fd, oob_buf, oob_size);		
	}



	
RET:
	if(in_fd > 0)
		close(in_fd);

	if(out_fd > 0)
		close(out_fd);

	if(page_buf != NULL)
		free(page_buf);

	if(out_file_name != NULL)
	 	free(out_file_name);
		
	if(oob_buf != NULL)
		free(oob_buf);
	


	return 0;
}
