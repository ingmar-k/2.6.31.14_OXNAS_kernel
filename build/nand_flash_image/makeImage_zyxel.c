#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#define DEFAULT_PAGE_SIZE 	2048	/* Byte */
#define DEFAULT_OOB_SIZE 	64	/* Byte */
#define DEFAULT_BLOCK_SIZE	128	/* KB */
#define MAX_FIB_NUM	200

#define MAX_PART_NUM	100

char	**part_img_name;

unsigned int	good_block_need[MAX_PART_NUM];

#if 0
int good_block_need(int part_block, int img_block)
{
	int need_block;

	fprintf(stderr, "part block = %d, img block = %d\n", 
		part_block, img_block);

	if(img_block + 1 > part_block)
	{
		fprintf(stderr, "Partition is too small\n");
		return -1;
	}

	if(img_block == 0)
	{
		if(part_block < 4) 
			return part_block;
		else if(part_block < 8)
			return part_block -1;
		else 
			return part_block - part_block / 8;
	}
		


	if(img_block + 3 > part_block)
		return part_block;
	else
		return img_block + 3;
	


}
#endif


struct nand_data
{
	unsigned long block_size;
	unsigned long part_num;
	char	**part_name;
	off_t *part_start_addr;
	off_t *part_space;

};

typedef struct hdrNandInfo_s {
	unsigned long pageSize;		/* byte */
	unsigned short oobSize;		/* byte */
	unsigned short blockSize;	/* kbyte */
	unsigned long reserved;
} hdrNandInfo_t;

typedef struct hdrPartInfo_s {
	unsigned long addr;
	unsigned long partSize;		/* kbyte */
	unsigned long imgSize;		/* kbyte */
	unsigned long imgVersion;
	unsigned char  reserve_p;
	unsigned char  error_bit;
	unsigned short Good_blocks;
} hdrPartInfo_t;

typedef struct hdrNandHeader_s {
	hdrNandInfo_t nand;
	char productVersion[32];
	unsigned char reserve[4];
	unsigned short CGBP0;
	unsigned char Bad_block0;
	unsigned char Reserve_Area[3];
	unsigned char swap_flag;
	unsigned char partQTY;
}hdrNandHeader_t ;


void createHeader(int img_fd, struct nand_data *nd)
{
	hdrNandInfo_t	*nand_info_ptr;
	hdrPartInfo_t	*parts_info;
	hdrNandHeader_t	head_info;
	
	int part;


	nand_info_ptr = &(head_info.nand);

	/* Setup nand info */
	memset(nand_info_ptr, 0xFF, sizeof(hdrNandInfo_t));
	nand_info_ptr->pageSize = DEFAULT_PAGE_SIZE;
	nand_info_ptr->oobSize = DEFAULT_OOB_SIZE;
	nand_info_ptr->blockSize = DEFAULT_BLOCK_SIZE;
	

	/* Setup partition information*/
	parts_info = (hdrPartInfo_t* )malloc(sizeof(hdrPartInfo_t) * (nd->part_num));
	for(part = 0 ; part < nd->part_num ; part++)
	{
		struct stat s_buf;
		int img_no_oob_size, img_block;

		
		parts_info[part].addr = nd->part_start_addr[part];
		parts_info[part].partSize = nd->part_space[part] / 1024; /* KB */
		parts_info[part].imgVersion = 0xff;
		parts_info[part].reserve_p = 0xff;
		//parts_info[part].error_bit = 0; // Setting error_bit as 0 makes the fail rate of NAND much higher.
		parts_info[part].error_bit = 1;

		if(strcmp(part_img_name[part], "NA") == 0 )
			parts_info[part].imgSize = 0;
		else
		{
			stat(part_img_name[part], &s_buf);
			parts_info[part].imgSize = s_buf.st_size;
		}

#if 1
		img_no_oob_size = (parts_info[part].imgSize/(DEFAULT_PAGE_SIZE  + DEFAULT_OOB_SIZE))*DEFAULT_PAGE_SIZE;
		parts_info[part].imgSize = img_no_oob_size / 1024; /* KB */
#else
		if ((parts_info[part].imgSize & (DEFAULT_PAGE_SIZE - 1)) != 0) {
			img_no_oob_size = DEFAULT_PAGE_SIZE * ((parts_info[part].imgSize / DEFAULT_PAGE_SIZE) + 1);			
		} else {
			img_no_oob_size = DEFAULT_PAGE_SIZE * (parts_info[part].imgSize / DEFAULT_PAGE_SIZE);
		}
			fprintf(stdout, "Result of &:%d\n", parts_info[part].imgSize & (DEFAULT_PAGE_SIZE - 1));
		parts_info[part].imgSize = img_no_oob_size / 1024; /* KB */
#endif
		img_block = img_no_oob_size/(DEFAULT_BLOCK_SIZE * 1024);

		img_block = (img_no_oob_size % (DEFAULT_BLOCK_SIZE*1024) > 0)?(img_block + 1):(img_block);
				

		parts_info[part].Good_blocks = good_block_need[part];
				//	nd->part_space[part] / (DEFAULT_BLOCK_SIZE*1024), 
				//	img_block);

		fprintf(stdout, "partion %d, number of good blocks required = %d, number_of_block_of_img = %d\n", part, parts_info[part].Good_blocks, img_block);
	}
	
	/* Setup head info */
	/* Ignore version number */
	memset(&(head_info.productVersion), 0xff, sizeof(head_info.productVersion));
	/* Ignore reverve */
	memset(&(head_info.reserve), 0xff, sizeof(head_info.reserve));

	head_info.CGBP0 = 1;
	head_info.Bad_block0 = 0;
	memset(&(head_info.Reserve_Area), 0xff, sizeof(head_info.Reserve_Area));
	head_info.swap_flag = 0;
	head_info.partQTY = nd->part_num;

	/* Write the header to image */

	write(img_fd, &(head_info), sizeof(hdrNandHeader_t));
	
	/* Write partition information to image */
	for(part = 0; part < nd->part_num ; part++)
		write(img_fd, &parts_info[part], sizeof(hdrPartInfo_t));
	

	
	free(parts_info);


}


int main(int argc, char *argv[])
{
	struct stat sb;
	int	i, j,  ret = 0;
	//unsigned long file_size, read_size, len, part_num;
	unsigned long file_size, read_size, part_num;
	size_t len;
	char *line = NULL; 
	FILE	*fp, *out_fp;
	int 	img_in_fd, img_out_fd;
	struct nand_data nd;
		
	char	*buf = NULL;
	unsigned long page_size, oob_size ;
	char	gfd_id[16], tail_buf[16];

	nd.block_size = 0;
	nd.part_num = 0;
	part_num = 0;

	nd.part_name = NULL;
	nd.part_start_addr = NULL;
	nd.part_space = NULL;

	if(argc < 2)
	{
		fprintf(stderr, "Usage: %s <partiton pathname>\n", argv[0]);
		return -1;
	}

	part_img_name = (char **)malloc(sizeof(char *) * argc);

	for(i = 0 ; i < argc - 1 ; i++)
		part_img_name[i] = argv[i + 1];



	/* Parse Nand data file */
	fp = fopen("flash_partition_data", "r");
	if(fp == NULL)
	{
		fprintf(stderr, "No flash data\n");
		ret = -1;
		goto RET;
	}


	while ((read_size = getline(&line, &len, fp)) != -1) 
	{
		if(line[0] == '#')
			continue;
		
		if(strncmp(line, "Block Size", strlen("Block Size")) == 0)
		{
			read_size = getline(&line, &len, fp);
			
			if(read_size < 0)
			{
				fprintf(stderr, "Fail to parse flash data. \n");
				ret = read_size;
				goto RET;
			}
			
			nd.block_size = strtoul(line, NULL, 10);
		}		
		else if(strncmp(line, "Partition Number", strlen("Partition Number")) == 0)
		{
			int part;

			read_size = getline(&line, &len, fp);
			if(read_size < 0)
			{
				fprintf(stderr, "Fail to parse flash data. \n");
				ret = read_size;
				goto RET;
			}

			nd.part_num = strtoul(line, NULL, 10);

			nd.part_name = (char **)malloc(sizeof(char **) * nd.part_num);
			nd.part_start_addr = (off_t *)malloc(sizeof(off_t) * nd.part_num);
			nd.part_space =   (off_t *)malloc(sizeof(off_t) * nd.part_num);

			for(part = 0 ; part < nd.part_num ; part++)
				nd.part_name[part] = NULL;	
		}
		else if(strncmp(line, "Page Size", strlen("Page Size")) == 0)
		{
			read_size = getline(&line, &len, fp);
			
			if(read_size < 0)
			{
				fprintf(stderr, "Fail tp get page size \n");
				ret = read_size;
				goto RET;
			}

			page_size = strtoul(line, NULL, 10);	
		}
		else if(strncmp(line, "Oob Size", strlen("Oob Size")) == 0)
		{
			read_size = getline(&line, &len, fp);
			
			if(read_size < 0)
			{
				fprintf(stderr, "Fail tp get oobe size \n");
				ret = read_size;
				goto RET;
			}

			oob_size = strtoul(line, NULL, 10);	
		}
		else
		{
			
			nd.part_name[part_num] = (char *)malloc(sizeof(char) * (strlen(line) + 1));
			strcpy(nd.part_name[part_num], line);
			
			read_size = getline(&line, &len, fp);
			if(read_size < 0 || line[0] == '*')
			{
				fprintf(stderr, "Can not get start address for partition %s\n", 
					nd.part_name[part_num]);
				ret = read_size;
				goto RET;
			}
			nd.part_start_addr[part_num] = strtoul(line, NULL, 16);

			
			read_size = getline(&line, &len, fp);
			if(read_size < 0 || line[0] == '*')
			{
				fprintf(stderr, "Can not get end address for partition %s\n", 
					nd.part_name[part_num]);
				ret = read_size;
				goto RET;
			}
			nd.part_space[part_num] = strtoul(line, NULL, 16);


			read_size = getline(&line, &len, fp);
			if(read_size < 0 || line[0] == '*')
			{
				fprintf(stderr, "Can not get good block number for partition %s\n", 
					nd.part_name[part_num]);
				ret = read_size;
				goto RET;
			}
			good_block_need[part_num] = strtoul(line, NULL, 10);


			part_num++;			
		}		
	}

	if(nd.part_num != (argc - 1))
	{
		fprintf(stderr, "argument number does not match\n");
		return -1;
	}


	img_out_fd = open("NSA_NAND_IMG_ZYXEL", O_RDWR | O_CREAT);	
	buf = (char *)malloc(sizeof(char) * (page_size + oob_size));
	
	/* Create the header of image */
	createHeader(img_out_fd, &nd);


	for(i = 0 ; i < nd.part_num ; i++)
	{
		off_t free_part_size;
		off_t w_size;
		int page_num;

		free_part_size = nd.part_space[i];
		if(free_part_size % page_size != 0)
		{
			fprintf(stderr, "partition %s is not page alignment", nd.part_name[i]);
			goto RET;
		}
		
		page_num = free_part_size / page_size;
				
		if(strncmp(argv[i+1], "NA", 2) == 0)
		{
			/* Write ff to all pages */
			/* We do not need to write 0xff in ZyXEL */
		}
		else
		{	
			off_t f_size;
			int dummy_page_num, write_page_num;

			stat(argv[i+1], &sb);
			f_size = sb.st_size;
			if(f_size % (page_size + oob_size) != 0)
			{
				fprintf(stderr, "file %s is not alignmented\n", argv[i+1]);
				goto RET;
			}

			write_page_num = f_size / (page_size + oob_size);
			dummy_page_num = page_num - write_page_num;

			img_in_fd = open(argv[i+1], O_RDONLY);
			for(j = 0 ; j < write_page_num ; j++)
			{
				read_size = read(img_in_fd, buf, page_size + oob_size);
				write(img_out_fd, buf, read_size);
			}
			
			/* We do not need dummy image */
			#if 0
			memset(buf, 0xff, page_size + oob_size);
			for(j = 0 ; j < dummy_page_num ; j++)
				write(img_out_fd, buf, page_size + oob_size);
			#endif
			close(img_in_fd);
		}
	}

	close(img_out_fd);


RET:

	for(i = 0 ; i < nd.part_num ; i++)
		if(nd.part_name[i] != NULL)
			free(nd.part_name[i]);
	
	if(nd.part_name != NULL)
		free(nd.part_name);
	
	if(nd.part_start_addr != NULL)
		free(nd.part_start_addr);
	
	if(nd.part_space != NULL)
		free(nd.part_space);

	if(buf != NULL)
		free(buf);

	free(part_img_name);

	return ret;
}
