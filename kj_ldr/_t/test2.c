#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>

unsigned char __attribute__((weak)) loader[] = {
#ifdef __x86_64__
	0xcc, // int3
#else
# error NOT IMPLEMENTED
#endif
};

unsigned __attribute__((weak)) loader_size = sizeof(loader);

int main(int argc, char *argv[]) {
	const char *lib = (argc > 1) ? argv[1] : "libz.so";
	const size_t alloc_size = loader_size + strlen(lib) + 1;
	char *ptr = mmap(0, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	assert(ptr);
	memcpy(ptr, loader, loader_size);
	memcpy(ptr + loader_size, lib, strlen(lib) + 1);
	mprotect(ptr, alloc_size, PROT_EXEC);

	printf("LOADER payload size = %u (lib:%s)\n", loader_size, lib);

#ifdef __x86_64__
	asm volatile (
		"movq $1f, %%rax	\n"
		"shlq $8, %%rax		\n"
		"pushq %0		\n"
		"ret			\n"
		"1:			\n"
		:: "m"(ptr)
	);
#else
# error NOT IMPLEMENTED
#endif

	return 0;
}
