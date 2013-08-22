
# infrastructure
obj-y	+= xhci.o
obj-y	+= xhci-dbg.o
obj-y	+= xhci-hub.o
obj-y	+= xhci-pci.o
obj-y	+= xhci-mem.o
obj-y	+= xhci-ring.o

ccflags-$(CONFIG_USB_DEBUG)	+= -DDEBUG
ccflags-$(CONFIG_USB_GADGET_DEBUG) += -DDEBUG

