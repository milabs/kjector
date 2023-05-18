KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C kj_ldr
	$(MAKE) -C kj_lib
	$(MAKE) -C $(KDIR) M=$$PWD/kj_mod

clean:
	$(MAKE) -C $(KDIR) M=$$PWD/kj_mod clean
	$(MAKE) -C kj_lib clean
	$(MAKE) -C kj_ldr clean
