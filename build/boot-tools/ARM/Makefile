# Initial Makefile to create the boot tools from sources stored in SRC directory
# J J Larkworthy 08 August 2007
# Initial design - fairly nieve approach to start.
#
# The elements of the tool set are compiled for the ARM. 
# Other parts are compiled to run on the workstation.
# This make file creates the ARM components by calling make in that directory. 
# The rest of this builds the tools for the workstation.
#

# architecture set up options.



ARCH		?= arm
CROSS_COMPILE	?= /opt/montavista/pro/devkit/arm/v5t_le/bin/arm_v5t_le-

# now for the commands needed.

AS		= $(CROSS_COMPILE)as
LD		= $(CROSS_COMPILE)ld
CC		= $(CROSS_COMPILE)gcc
CPP		= $(CC) -E
AR		= $(CROSS_COMPILE)ar
NM		= $(CROSS_COMPILE)nm
STRIP		= $(CROSS_COMPILE)strip
OBJCOPY		= $(CROSS_COMPILE)objcopy
OBJDUMP		= $(CROSS_COMPILE)objdump
AWK		= awk
GENKSYMS	= scripts/genksyms/genksyms
DEPMOD		= /sbin/depmod
KALLSYMS	= scripts/kallsyms
PERL		= perl
CHECK		= sparse
CHECKFLAGS     := -D__linux__ -Dlinux -D__STDC__ -Dunix -D__unix__
MODFLAGS	= -DMODULE
#CFLAGS_MODULE   = $(MODFLAGS)
#AFLAGS_MODULE   = $(MODFLAGS)
LDFLAGS_MODULE  = -r
#ASFLAGS         = -mapcs-32 -mfpu=softfpa
ASFLAGS         = 
CFLAGS_KERNEL	= 
AFLAGS_KERNEL	=
INCLUDE         = -Iinclude
LDOPTS          = -M
CCOPTS          = $(INCLUDE) -ffreestanding -c -g -O0 -nostdlib -Os
OBJCOPYFLAGS    = -O binary -j .text -j .dtcp_text -S


ASSEMBLER=/usr/local/



OBJECTS = $(AOBJECTS)

COBJECTS =  

BOOT_OBJECTS = 

TEST_OBJECTS = 

AOBJECTS = header.o 

.SUFFIXES:
.SUFFIXES: .c .S .o
all : header.bin stage1.bin

header.bin : header.elf
	$(OBJCOPY) -O binary $< $@ 
     
header.elf : header.o header.ln
	$(LD) $(LDOPTS) -T header.ln $< -o $@ > $@.map
	
stage1.bin : stage1.elf
	$(OBJCOPY) -O binary $< $@
	
stage1.elf : relocate.o stage1.o Makefile
	$(LD) $(LDOPTS) -T stage1.ln relocate.o stage1.o -o $@ >$@.map
	
%.o : %.c
	$(CC) $(CCOPTS) $< -o $@
	
%.o : %.S
	$(CC) $(CCOPTS) $< -o $@


clean :
	@rm -f header.bin header.elf* *.o header stage1.bin stage1.elf*
