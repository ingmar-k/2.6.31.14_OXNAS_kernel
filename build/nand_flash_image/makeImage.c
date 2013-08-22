#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>


struct nand_data
{
	unsigned long block_size;
	unsigned long part_num;
	char	**part_name;
	off_t *part_start_addr;
	off_t *part_space;

};

int main(int argc, char *argv[])
{
	struct stat sb;
	int	i, j,  ret = 0;
	unsigned long file_size, read_size, len, part_num;
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

			part_num++;			
		}		
	}

	if(nd.part_num != (argc - 1))
	{
		fprintf(stderr, "argument number does not match\n");
		return -1;
	}

	out_fp = fopen("nand_group_defined", "w+");

	/* group define file id */
	gfd_id[0] = 0x47;
	gfd_id[1] = 0x52;
	gfd_id[2] = 0x4f;
	gfd_id[3] = 0x55;
	gfd_id[4] = 0x50;
	gfd_id[5] = 0x20;
	gfd_id[6] = 0x44;
	gfd_id[7] = 0x45;
	gfd_id[8] = 0x46;
	gfd_id[9] = 0x49;
	gfd_id[10] = 0x4e;
	gfd_id[11] = 0x45;
	gfd_id[12] = 0x32;
	gfd_id[13] = 0x0;
	gfd_id[14] = 0x0;
	gfd_id[15] = 0x0;


	fwrite(gfd_id, sizeof(char), 16, out_fp);

	for(i = 0 ; i < nd.part_num ; i++)
	{
		unsigned long start_block, end_block, write_block_num;
		unsigned long head = 0x1;
		
		if(strncmp(argv[i + 1], "NA", 2) == 0)
			continue;

		fwrite(&head, sizeof(unsigned long), 1, out_fp);

		start_block = (nd.part_start_addr[i]) / (nd.block_size);
		end_block = (nd.part_start_addr[i] + nd.part_space[i]) / (nd.block_size) -1;

		printf("%s --> \n", nd.part_name[i]);

		fwrite(&start_block, sizeof(unsigned long), 1 , out_fp);
		printf("start block %x\n", start_block);

		fwrite(&end_block, sizeof(unsigned long), 1 , out_fp);
		printf("end block %x\n", end_block);

		stat(argv[i+1], &sb);
		write_block_num = sb.st_size / (nd.block_size + 64 * 64);
		write_block_num = (sb.st_size %  (nd.block_size + 64 * 64)) ? (write_block_num + 1) : write_block_num;
		fwrite(&write_block_num, sizeof(unsigned long), 1 , out_fp);
		printf("write block num = %x\n", write_block_num);
	}

	memset(tail_buf, 0xff, 16);
	fwrite(tail_buf, sizeof(char), 16, out_fp);

	fclose(out_fp);
	fclose(fp);

	img_out_fd = open("Nsa310_NAND_IMG", O_RDWR | O_CREAT);	
	buf = (char *)malloc(sizeof(char) * (page_size + oob_size));

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
			memset(buf, 0xff, page_size + oob_size);

			for(j = 0 ; j < page_num ; j++)
				write(img_out_fd, buf, page_size + oob_size);
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
			
			memset(buf, 0xff, page_size + oob_size);
			for(j = 0 ; j < dummy_page_num ; j++)
				write(img_out_fd, buf, page_size + oob_size);

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

	return ret;
}
