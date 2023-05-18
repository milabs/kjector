ifeq ($(DEBUG),)
cc-flags += -DNDEBUG
endif

cc-flags += -std=gnu99 -Werror -O3 -fomit-frame-pointer
cc-flags += -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables

.PHONY: lib
lib:
	@echo ">> Building library"
	gcc $(cc-flags) -fPIC -o lib.o -c src/lib.c
	gcc -shared -fPIC -o libkjector.so lib.o -lc

clean: force
	@rm -rf *.o *.so

force:
