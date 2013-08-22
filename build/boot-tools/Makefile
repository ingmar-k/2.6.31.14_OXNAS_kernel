# Make file to create the host programs.

# use the compiler GCC as a linker and search all default libraries to form
# a working executable. 
# - Not trying to be clever and create a stand alone system so the 
# installed compiler system should work.



.phony : all

all : stage1.wrapped


stage1.wrapped: ARM/stage1.bin ARM/header.bin src/update_header
	cat ARM/header.bin > stage1.wrapped
	cat ARM/stage1.bin >> stage1.wrapped
	src/update_header stage1.wrapped
	mv stage1.wrapped stage1_SATA.wrapped

ARM/header.bin:
	(cd ARM ; $(MAKE) header.bin)

ARM/stage1.bin:
	(cd ARM ; $(MAKE) stage1.bin)

src/update_header:
	(cd src ; $(MAKE) update_header)
	
	
clean:
	(cd ARM ; $(MAKE) clean )
	(cd src ; $(MAKE) clean )
	#rm stage1_SATA.wrapped

