CC=gcc
MTD_INCLUDE=../../sysapps/mtd-utils-1.0.0/include/
all: infoImg mknandimg_ecc makeImage makeImage_zyxel

infoImg: default_info_img.c
	$(CC) $^ -o $@

mknandimg_ecc: nand_ecc_image.c
	$(CC) -I$(MTD_INCLUDE) $^ -o $@

makeImage: makeImage.c
	$(CC) $^ -o $@

makeImage_zyxel: makeImage_zyxel.c
	$(CC) $^ -o $@
	

	
