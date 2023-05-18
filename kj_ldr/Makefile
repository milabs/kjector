ifeq ($(DEBUG),)
cc-flags += -DNDEBUG
endif

cc-flags += -std=gnu99 -Werror -O3 -fomit-frame-pointer
cc-flags += -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables

ld-flags += -pie -nostdlib -nostartfiles -nodefaultlibs
ld-flags += -Wl,--script=ld.script -Wl,--as-needed -Wl,--no-undefined -Wl,--hash-style=both -Wl,--noinhibit-exec

.PHONY: loader
loader:
	@echo ">> Building loader"
	gcc $(cc-flags) -fPIE -o loader_c.o -c src/loader.c
	gcc $(cc-flags) -fPIE -o loader_s.o -c src/loader.s
	gcc $(ld-flags) loader_c.o loader_s.o -o loader.elf
	@echo ">> Building loader payload"
	objcopy --dump-section .text=payload loader.elf && \
		xxd --include payload >payload.c
	gcc $(cc-flags) -fPIC -o loader.o -c payload.c

.PHONY: loader-test
loader-test: loader
	@echo ">> Building loader test files"
	gcc $(cc-flags) _t/test1.c loader_c.o -o test1
	gcc $(cc-flags) _t/test2.c loader.o -no-pie -o test2

clean: force
	rm -f loader.elf loader_c.o loader_s.o loader.o payload payload.c test1 test2

force:
