/* shim program to accelerate the loading of programs on slow responding disk drives.  *
 * This program corrects an error in the 810 boot loader which results in slow booting */
#include "types.h"

/* macros to make reading and writing hardware easier */
#define readb(p)  (*(volatile u8 *)(p))
#define readl(p)  (*(volatile u32 *)(p))
#define writeb(v, p) (*(volatile u8 *)(p)= (v))
#define writel(v, p) (*(volatile u32*)(p)=(v))

/* critical hardware addresses */
#define C_SYSCTRL_RSTEN_SET_ADDR 0X4500002C
#define C_SYSCTRL_RSTEN_CLR_ADDR 0X45000030
#define C_SYSCTRL_RSTEN_STAT_ADDR 0x4500028
#define DMA_RESET        (1<< 8)
#define SATA_RESET       (1<<11)
#define SATA_LNK_RESET   (1<<12)
#define SATA_PHY_RESET   (1<<13)
#define DDR_RESET        ((1<<10) | (1<<25))

#define DDR_CTRL   0x45800000


/* active disk mask */
#define DISK_STATUS_ADDRESS ((u32 *) 0x5801fff8)
#define DISK_READ        (1<< 0)


/* sata disk image format for checking */
#define SATA_IMAGE_LENGTH_OFFSET  	0x30
#define SATA_IMAGE_CRC_OFFSET     	0x34
#define HEADER_CRC_OFFSET    		0x38
#define HEADER_SIZE          		(HEADER_CRC_OFFSET)
#define SATA_IMAGE_START     		(HEADER_CRC_OFFSET + 4)


#define START_OF_SRAM (u32)0X58000000
#define LOADED_IMAGE_SIZE  (116*1024)

#define BLOCK_SIZE 512
/* shim size is defined as sectors on disk) */
#define primary_location   36
#define secondary_location 57090
#define primary_length     ((LOADED_IMAGE_SIZE+BLOCK_SIZE)/BLOCK_SIZE)

#if LOADED_IMAGE_SIZE > 125*1024
#error "image too large for space available on 810"
#endif

#define crc32(a,b,c)  ((unsigned long (*)(unsigned long, const unsigned char *, unsigned int)) 0x400000e0) (a,b,c)
#define ide_read(a,b,c,d) ((u32 (*)(int, u32, u32, u32* )) 0x400019d8) (a,b,c,d)
#define get_MBR(disk) (((u32 (*)(unsigned int)) 0x40001b74) (disk))

void init_uart ();
void put_char(char);

 
void main ()
{
	u32 header_crc = (START_OF_SRAM + HEADER_CRC_OFFSET);
	u32 start_image_adr = (START_OF_SRAM + SATA_IMAGE_START);
	u32 image_length = (START_OF_SRAM + SATA_IMAGE_LENGTH_OFFSET);
	u32 image_crc = (START_OF_SRAM + SATA_IMAGE_CRC_OFFSET);
	u32 disk;
	int x;
	volatile u32 *disk_status = DISK_STATUS_ADDRESS ;

	/* reset sata and DMA hardware and ensure DDR is in reset */
    	writel((DMA_RESET | SATA_RESET | SATA_LNK_RESET | SATA_PHY_RESET | DDR_RESET),
                         C_SYSCTRL_RSTEN_SET_ADDR); 
	for (x=0; x< 0x54; x+=4 ) {
		writel(0, (DDR_CTRL+x));
	}
	/* wait for DDR to reset */
	disk = disk_status[1] & DISK_READ ? 1 : 0 ; /* get active disk */
	/* check if disk status is being reported correctly 
 	 * give up if not consistent. */
	if (disk_status[disk] & DISK_READ != 1) return;
	/* enable sata and dma hardware */	

    	writel(SATA_PHY_RESET, C_SYSCTRL_RSTEN_CLR_ADDR);
    	writel(SATA_LNK_RESET | SATA_RESET, C_SYSCTRL_RSTEN_CLR_ADDR );
	writel(DMA_RESET, C_SYSCTRL_RSTEN_CLR_ADDR);

	get_MBR(disk);

#if 1
	ide_read(0, primary_location, primary_length, ((u32 *) START_OF_SRAM));
	((void (*)(void)) START_OF_SRAM) ();
#else
	/* load first image */
	if ( 0 < ide_read(0, primary_location, primary_length, ((u32 *) START_OF_SRAM)))
	/* validate image */
	/* if valid execute */
	{ 
		if (
			(crc32(0, (void *) START_OF_SRAM, HEADER_SIZE) == *(u32 *) header_crc) && 
	                (crc32(0, (void *) start_image_adr, *(u32 *) image_length) == *(u32 *) image_crc) 
 		   )
		{
			((void (*)(void)) START_OF_SRAM) ();
		}
	}
	/* load second image */
	if ( 0 < ide_read(0, secondary_location, primary_length, ((u32 *) START_OF_SRAM)))
	/* validate image */
	/* if valid execute */
	{
		if (
			(crc32(0, (void *) START_OF_SRAM, HEADER_SIZE) == *(u32 *) header_crc) && 
	                (crc32(0, (void *) start_image_adr, *(u32 *) image_length) == *(u32 *) image_crc) 
 		   )
		{
			((void (*)(void)) START_OF_SRAM) ();
		}
	}
	/* else give up */
#endif

	return;

}
