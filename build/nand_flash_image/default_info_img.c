#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CONFIG_ENV_SIZE 131072
#define ENV_SIZE (CONFIG_ENV_SIZE - sizeof(long))

#define ADDR_VALUE_SIZE	23
#define INFO_OUT_IMG_NAME	"info.bin"


unsigned long  crc_table[256];

struct env_image_single {
	unsigned long   crc;    /* CRC32 over data bytes    */
	char            data[];
};


struct env_name_value
{
	char	*name;
	char	*val;
};

enum{
	KER_ADDR1 = 0,	// 0
	KER_MTD1, 	// 1	
	SYSIMG_MTD1,	// 2
	KER_ADDR2,	// 3
	KER_MTD2,	// 4
	SYSIMG_MTD2, 	// 5
	FW_VERSION1,	// 6
	REVERSION1,	// 7
	MODEL_ID1,	// 8
	CORE_CHKSUM1, 	// 9
	ZLD_CHKSUM1,	// 10
	ROM_CHKSUM1, 	// 11
	IMG_CHKSUM1,	// 12
	FW_VERSION2,	// 13
	REVERSION2,	// 14
	MODEL_ID2,	// 15
	CORE_CHKSUM2, 	// 16 
	ZLD_CHKSUM2,	// 17
	ROM_CHKSUM2, 	// 18
	IMG_CHKSUM2,	// 19
	NEXT_BOOT,	// 20
	CURR_BOOT,	// 21
	TOTAL_ENV
};

struct env_name_value	all_default_envs[] = {
	{"kernel_addr_1", NULL},		// 0
	{"kernel_mtd_1", NULL},			// 1
	{"sysimg_mtd_1", NULL},			// 2
	{"kernel_addr_2", NULL},		// 3
	{"kernel_mtd_2", NULL},			// 4
	{"sysimg_mtd_2", NULL},			// 5
	{"fwversion_1", NULL},			// 6
	{"revision_1", NULL},			// 7
	{"modelid_1", NULL},			// 8
	{"core_checksum_1", NULL},		// 9 
	{"zld_checksum_1", NULL},		// 10
	{"romfile_checksum_1", NULL},		// 11
	{"img_checksum_1", NULL},		// 12
	{"fwversion_2", NULL},			// 13
	{"revision_2", NULL},			// 14
	{"modelid_2", NULL},			// 15
	{"core_checksum_2", NULL},		// 16 
	{"zld_checksum_2", NULL},		// 17
	{"romfile_checksum_2", NULL},		// 18
	{"img_checksum_2", NULL},		// 19
	{"next_bootfrom", NULL},		// 20
	{"curr_bootfrom", NULL},		// 21
};


void usage()
{
	fprintf(stderr, "infoImg [kernel_1 addr] [kernel_1 mtd num] [sysimg_1 mtd num] [kernel_2 addr] [kernel_2 mtd num] [sysimg_2 mtd num] [fw file path]\n");
}

void make_crc_table()
{
	unsigned long c;
	int n, k;
	unsigned long  poly;            /* polynomial exclusive-or pattern */
	/* terms of polynomial defining this crc (except x^32): */
	static const char p[] = {0,1,2,4,5,7,8,10,11,12,16,22,23,26};

	/* make exclusive-or pattern from polynomial (0xedb88320L) */
	poly = 0L;
	for (n = 0; n < sizeof(p)/sizeof(char); n++)
		poly |= 1L << (31 - p[n]);

	for (n = 0; n < 256; n++)
	{
		c = (unsigned long)n;
		for (k = 0; k < 8; k++)
			c = c & 1 ? poly ^ (c >> 1) : c >> 1;
		crc_table[n] = c;
	}
}

/* ========================================================================= */
#define DO1(buf) crc = crc_table[((int)crc ^ (*buf++)) & 0xff] ^ (crc >> 8);
#define DO2(buf)  DO1(buf); DO1(buf);
#define DO4(buf)  DO2(buf); DO2(buf);
#define DO8(buf)  DO4(buf); DO4(buf);

/* ========================================================================= */
unsigned long crc32(crc, buf, len)
	unsigned long  crc;
	const char *buf;
	unsigned int  len;
{
	make_crc_table();
	crc = crc ^ 0xffffffffL;
	while (len >= 8)
	{
		DO8(buf);
		len -= 8;
	}
	if (len) do {
		DO1(buf);
	} while (--len);
	return crc ^ 0xffffffffL;
}






int main(int argc, char *argv[])
{
	unsigned long kernel_1_addr, kernel_1_mtd, sys1_mtd_num;
	unsigned long kernel_2_addr, kernel_2_mtd, sys2_mtd_num;
	char *fw_path, *img_data, *val_ptr;
	FILE*	fptr;
	int	i, out_fd;

	char *line = NULL;
	size_t len = 0;
	ssize_t read_size;
	struct env_image_single *env_img = NULL;


	if(argc != 8)
	{
		usage();
		return 0;
	}

	kernel_1_addr = strtoul(argv[1], NULL, 16);
	kernel_1_mtd = strtoul(argv[2], NULL, 10);
	sys1_mtd_num = strtoul(argv[3], NULL, 10);

	kernel_2_addr = strtoul(argv[4], NULL, 16);
	kernel_2_mtd = strtoul(argv[5], NULL, 10);
	sys2_mtd_num = strtoul(argv[6], NULL, 10);
	
	fw_path = argv[7];

	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "0x%x", kernel_1_addr);
	all_default_envs[KER_ADDR1].val = val_ptr;	

	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "%d", kernel_1_mtd);
	all_default_envs[KER_MTD1].val = val_ptr;

	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "%d", sys1_mtd_num);
	all_default_envs[SYSIMG_MTD1].val = val_ptr;


	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "0x%x", kernel_2_addr);
	all_default_envs[KER_ADDR2].val = val_ptr;	

	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "%d", kernel_2_mtd);
	all_default_envs[KER_MTD2].val = val_ptr;

	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "%d", sys2_mtd_num);
	all_default_envs[SYSIMG_MTD2].val = val_ptr;

	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "1");
	all_default_envs[NEXT_BOOT].val = val_ptr;

	val_ptr = (char *)malloc(ADDR_VALUE_SIZE);
	memset(val_ptr, 0, ADDR_VALUE_SIZE);
	sprintf(val_ptr, "1");
	all_default_envs[CURR_BOOT].val = val_ptr;

	fptr = fopen(fw_path, "r");
	if(fptr == NULL)
	{
		fprintf(stderr, "Can not open %s to read\n", fw_path);
		return -1;
	}

	while ((read_size = getline(&line, &len, fptr)) != -1)
	{
		char *v_ptr, *val = NULL, *value;
		int s_len, index1, index2;

		if((v_ptr = strstr(line, "value")) == NULL)
			continue;

		v_ptr += (strlen("value") + 1);

		for( ; *v_ptr == ' ' ; v_ptr++);
		
		if(strstr(line, "VERSION"))	
		{
			index1 = FW_VERSION1;
			index2 = FW_VERSION2;
		}
		else if(strstr(line, "REVISION"))
		{
			index1 = REVERSION1;
			index2 = REVERSION2;
		}
		else if(strstr(line, "MODEL1"))
		{
			index1 = MODEL_ID1;
			index2 = MODEL_ID2;
		}
		else if(strstr(line, "CORE_CHECKSUM"))
		{
			index1 = CORE_CHKSUM1;
			index2 = CORE_CHKSUM2;
		}
		else if(strstr(line, "ZLD_CHECKSUM"))
		{
			index1 =  ZLD_CHKSUM1;
			index2 =  ZLD_CHKSUM2;
		}
		else if(strstr(line, "ROM_CHECKSUM"))
		{
			index1 =  ROM_CHKSUM1;
			index2 =  ROM_CHKSUM2;
		}
		else if(strstr(line, "IMG_CHECKSUM"))
		{
			index1 =  IMG_CHKSUM1;
			index2 =  IMG_CHKSUM2;
		}
		else
		{
			continue;
		}
			

		s_len = strlen(v_ptr);
		value = (char *)malloc(s_len + 1);
		memcpy(value, v_ptr, s_len);

		all_default_envs[index1].val = value;
		all_default_envs[index2].val = value;
	}

	
	env_img = calloc(1, CONFIG_ENV_SIZE);
	img_data = env_img->data;

	
	
	for(i = 0 ; i < TOTAL_ENV ; i++)
	{	
		char *this_name, *this_val;
		int  t_len1, t_len2;

		this_name = all_default_envs[i].name;
		this_val = all_default_envs[i].val;

		t_len1 = strlen(this_name);
		t_len2 = strlen(this_val);
		
		while(isspace(*(this_name + t_len1 -1)) && t_len1 > 0) t_len1--;	
		while(isspace(*(this_val + t_len2 -1)) && t_len2 > 0) t_len2--;

		sprintf(img_data, "%s=%s", this_name, this_val);
		img_data += (t_len1 + t_len2 + 1);
		*img_data = 0;
		img_data++;
	}
	
	env_img->crc = crc32(0, (unsigned char *) env_img->data, ENV_SIZE);

	fprintf(stderr, "crc = %x\n", env_img->crc);

	out_fd = open(INFO_OUT_IMG_NAME, O_RDWR | O_CREAT);
	if(out_fd < 0)
	{
		fprintf(stderr, "Can not open %s for info image\n", INFO_OUT_IMG_NAME);
		goto RET;
	}

	write(out_fd, env_img, CONFIG_ENV_SIZE);
	close(out_fd);

RET:	
	if(env_img)
	{
		free(env_img);
		env_img = NULL;
	}

	for(i = 0 ; i < TOTAL_ENV ; i++)
	{
		if(all_default_envs[i].val)
		{
			free(all_default_envs[i].val);			
			all_default_envs[i].val = NULL;

                        if(i >= FW_VERSION1 && i <= IMG_CHKSUM1)
				all_default_envs[i + (IMG_CHKSUM1 - FW_VERSION1) + 1].val = NULL;

		}
	}

}
