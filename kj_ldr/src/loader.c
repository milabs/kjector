#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>

#include "loader.h"

#define STATE_MAGIC0 0x11111111
#define STATE_MAGIC1 0x22222222

typedef struct {
	volatile unsigned magic0;
	int logfd;
	volatile unsigned magic1;
} state_t;

static inline state_t *state(void) {
	state_t *s = (void *)&s;
	while (s->magic0 != STATE_MAGIC0 &&
	       s->magic1 != STATE_MAGIC1) s = (void *)s + 1;
	return s;
}

////////////////////////////////////////////////////////////////////////////////

#ifndef NDEBUG
# define PRINTF_DISABLE_SUPPORT_FLOAT
# define PRINTF_DISABLE_SUPPORT_EXPONENTIAL
# define PRINTF_DISABLE_SUPPORT_LONG_LONG
# define PRINTF_DISABLE_SUPPORT_PTRDIFF_T
# include "debug/printf.h"
void _putchar(char c) {
	state_t *s = state();
	if (s->logfd == -1) return;
	__syscall3(__NR_write, s->logfd, (long)&c, sizeof(c));
}
# include "debug/printf.c"
# define pr_debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
# define pr_debug(fmt, ...) ({})
#endif

////////////////////////////////////////////////////////////////////////////////

static inline bool loader_may_read(const void *ptr, size_t len) {
	if (!len) return true;
	long addr = (long)ptr & PAGE_MASK;
	long length = ((long)ptr % PAGE_SIZE + PAGE_SIZE + len) & PAGE_MASK;
	return __syscall3(__NR_msync, addr, length, 0) ? false : true;
}

static inline bool loader_ehdr_valid(const ElfW(Ehdr) *ehdr, int readcheck) {
	if (readcheck && !loader_may_read(ehdr, sizeof(ElfW(Ehdr))))
		return false;
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
	    ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
	    ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
	    ehdr->e_ident[EI_MAG3] != ELFMAG3)
		return false;
#if ( BITS_PER_LONG == 32 )
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32)
		return false;
#else
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64)
		return false;
#endif
	return true;
}

static inline ElfW(Ehdr) *loader_ehdr_locate(unsigned long addr) {
	unsigned long pc = (addr ? addr : get_pc()) & PAGE_MASK;
	for (;;) {
		ElfW(Ehdr) *head = (ElfW(Ehdr) *)pc;
		if (!loader_may_read(head, sizeof(ElfW(Ehdr))))
			return NULL;
		if (!loader_ehdr_valid(head, 0)) {
			pc -= PAGE_SIZE;
			continue;
		}
		return head;
	}
}

static bool loader_ehdr_phdr_valid(const ElfW(Ehdr) *ehdr, int readcheck) {
	if (!ehdr || !ehdr->e_phnum || !ehdr->e_phoff ||
	    ehdr->e_phentsize != sizeof(ElfW(Phdr)))
		return false;
	const ElfW(Phdr) *phdr = (void *)ehdr + ehdr->e_phoff;
	if (readcheck && !loader_may_read(phdr, ehdr->e_phnum * ehdr->e_phentsize))
		return false;
	return true;
}

static inline ElfW(Phdr) *loader_ehdr_phdr_locate(const ElfW(Ehdr) *ehdr) {
	return loader_ehdr_phdr_valid(ehdr, 1) ? (ElfW(Phdr) *)((void *)ehdr + ehdr->e_phoff) : NULL;
}

static inline bool loader_match_libc(const char *s) {
	const char *p = s;

	if (!s || !s[0]) return false;

	pr_debug("matching %s against libc.so ...\n", s);

#define SLEN(x) (sizeof(x) - 1)
	while (*p != 0) p = p + 1; // end
	if (p - s < (long)SLEN("libc.so.X")) return false;
	s = p - SLEN("libc.so.X");
# undef SLEN

	// match string with "libc.so.[567]\x00"
#define V567(v) ((v) == '5' || (v) == '6' || (v) == '7')
	if (s[0] == 'l' && s[1] == 'i' && s[2] == 'b' && s[3] == 'c' &&
	    s[4] == '.' && s[5] == 's' && s[6] == 'o' && s[7] == '.' && V567(s[8]) &&
	    s[9] == 0) return true;
# undef V567

	return false;
}

// match string with "__libc_dlsym\x00"
#define MATCH_LIBC_DLSYM(p)							\
	(p[ 0] == '_' && p[ 1] == '_' && p[ 2] == 'l' && p[ 3] == 'i' &&	\
	 p[ 4] == 'b' && p[ 5] == 'c' && p[ 6] == '_' && p[ 7] == 'd' &&	\
	 p[ 8] == 'l' && p[ 9] == 's' && p[10] == 'y' && p[11] == 'm' &&	\
	 p[12] == 0)

// match string with "__libc_dlopen_mode\x00"
#define MATCH_LIBC_DLOPEN(p)							\
	(p[ 0] == '_' && p[ 1] == '_' && p[ 2] == 'l' && p[ 3] == 'i' &&	\
	 p[ 4] == 'b' && p[ 5] == 'c' && p[ 6] == '_' && p[ 7] == 'd' &&	\
	 p[ 8] == 'l' && p[ 9] == 'o' && p[10] == 'p' && p[11] == 'e' &&	\
	 p[12] == 'n' && p[13] == '_' && p[14] == 'm' && p[15] == 'o' &&	\
	 p[16] == 'd' && p[17] == 'e' &&					\
	 p[18] == 0)

// match string with "__libc_dlclose\x00"
#define MATCH_LIBC_DLCLOSE(p)							\
	(p[ 0] == '_' && p[ 1] == '_' && p[ 2] == 'l' && p[ 3] == 'i' &&	\
	 p[ 4] == 'b' && p[ 5] == 'c' && p[ 6] == '_' && p[ 7] == 'd' &&	\
	 p[ 8] == 'l' && p[ 9] == 'c' && p[10] == 'l' && p[11] == 'o' &&	\
	 p[12] == 's' && p[13] == 'e' &&					\
	 p[14] == 0)

static int loader_try_libc(const char *lib, const ElfW(Dyn) *dyna, long bias) {
	size_t strsz = 0;
	const char *strtab = NULL;
	const void *symtab = NULL;

	pr_debug("LIBC (dyna=%p bias=%p)\n", dyna, bias);

	for (int i = 0; dyna[i].d_tag != DT_NULL; i++) {
		if (dyna[i].d_tag == DT_STRSZ) {
			strsz = dyna[i].d_un.d_val;
		} else if (dyna[i].d_tag == DT_STRTAB) {
			strtab = (void *)dyna[i].d_un.d_ptr;
		} else if (dyna[i].d_tag == DT_SYMTAB) {
			symtab = (void *)dyna[i].d_un.d_ptr;
		}
	}

	if (!(strsz && strtab && symtab))
		return -1;

	typeof(dlsym) *dlsymp = NULL;
	typeof(dlopen) *dlopenp = NULL;
	typeof(dlclose) *dlclosep = NULL;

	for (const ElfW(Sym) *sym = symtab; (char *)sym < strtab; sym++) {

		// FIXME: add more sym heuristics
		if (sym->st_name >= strsz) break;
		if (sym->st_shndx == SHN_UNDEF) continue;
		if ((sym->st_info & 0xf) != STT_FUNC) continue;

		const char *name = strtab + sym->st_name;
//		pr_debug("sym = %s (val:%p shndx:%u)\n", name, sym->st_value, sym->st_shndx);

		if (MATCH_LIBC_DLSYM(name)) {
			dlsymp = (void *)((long)sym->st_value + bias);
		} else if (MATCH_LIBC_DLOPEN(name)) {
			dlopenp = (void *)((long)sym->st_value + bias);
		} else if (MATCH_LIBC_DLCLOSE(name)) {
			dlclosep = (void *)((long)sym->st_value + bias);
		}

		if (dlsymp && dlopenp && dlclosep)
			break;
	}

	pr_debug("dlsym = %p\n", dlsymp);
	pr_debug("dlopen = %p\n", dlopenp);
	pr_debug("dlclose = %p\n", dlclosep);

	if (dlsymp && dlopenp && dlclosep) {
		void *handle = dlopenp(lib, RTLD_NOW);
		if (handle) {
			long (*init)(long) = dlsymp(handle, "init");
			pr_debug("%s:init = %p\n", lib, init);
			if (init && !init(0)) return 0; // DONE
			dlclosep(handle);
		}
	}

	return -1;
}

static long loader_try_lib(unsigned long addr, const char *lib) {
	pr_debug("TRY %p (%s)\n", addr, lib);
	const ElfW(Ehdr) *ehdr = loader_ehdr_locate(addr);
	const ElfW(Phdr) *phdr = loader_ehdr_phdr_locate(ehdr);

	pr_debug("ELF ehdr=%p phdr=%p\n", ehdr, phdr);
	if (!ehdr || !phdr) return -1;

	const ElfW(Dyn) *dyna = NULL;
	size_t offset = 0, addr_min = SIZE_MAX, addr_max = 0;

	for (int i = 0; i < ehdr->e_phnum; i++) {
		const ElfW(Phdr) *ph = &phdr[i];

//		pr_debug("phdr -- p_type=%p p_vaddr=%p p_paddr=%p p_offet=%p\n",
//			ph->p_type, ph->p_vaddr, ph->p_paddr, ph->p_offset);

		if (ph->p_type == PT_DYNAMIC) {
			dyna = (void *)ph->p_vaddr;
		} else if (ph->p_type == PT_LOAD) {
			if (ph->p_vaddr < addr_min) {
				offset = ph->p_offset & PAGE_MASK;
				addr_min = ph->p_vaddr & PAGE_MASK;
			}
			if (ph->p_vaddr + ph->p_memsz > addr_max) {
				addr_max = ph->p_vaddr + ph->p_memsz;
				addr_max = (addr_max + PAGE_SIZE - 1) & PAGE_MASK;
			}
		}
	}

	pr_debug("LOAD (min=%p max=%p off=%p)\n", addr_min, addr_max, offset);
	if (!dyna || offset || (addr_min == SIZE_MAX && addr_max == 0))
		return -1;

	long load_bias = (long)ehdr - (long)addr_min;
	dyna = (void *)dyna + load_bias;

	//
	// There are 2 ways to find link_map:
	//
	//   1) Using PT_DEBUG:
	//      If filled it points to r_debug{}
	//
	//   2) Using PT_PLTGOT; first three GOT address are reserved:
	//      GOT[0] - points to the dynamic segment of the executable
	//      GOT[1] - points to the link_map structure
	//      GOT[2] - points to _dl_runtime_resolve()
	//
	//  https://gist.github.com/DhavalKapil/2243db1b732b211d0c16fd5d9140ab0b
	//  https://0x00sec.org/t/linux-internals-the-art-of-symbol-resolution/1488
	//

#define PR_LINK_MAP(p)						\
	pr_debug("- link_map   %p\n", p);			\
	pr_debug("  | l_addr = %p\n", (p)->l_addr);		\
	pr_debug("  |   l_ld = %p (.dynamic)\n", (p)->l_ld);	\
	pr_debug("  | l_name = %s\n", (p)->l_name);		\
	pr_debug("  | l_prev = %p\n", (p)->l_prev);		\
	pr_debug("  | l_next = %p\n", (p)->l_next)

	const struct link_map *link_map = NULL;
	const char *soname = NULL, *strtab = NULL, *symtab = NULL;

	pr_debug("DYNAMIC %p (load_bias=%p)\n", dyna, load_bias);

	for (int i = 0; dyna[i].d_tag != DT_NULL; i++) {
		const void *p = (void *)dyna[i].d_un.d_ptr;

//		pr_debug("d_tag=%p d_ptr=%p\n", dyna[i].d_tag, p);

		if (dyna[i].d_tag == DT_DEBUG && !link_map) {
			link_map = (void *)((struct r_debug *)p)->r_map;
			pr_debug("DT_DEBUG link_map = %p\n", link_map);
		} else if (dyna[i].d_tag == DT_PLTGOT && !link_map) {
			const void **got = (const void **)p;
			// GOT[2] is NULL for RELRO libraries (no link_map)
			if (got[0] && got[1] && got[2]) {
				if ((got[0] == (void *)dyna) ||
				    ((got[0] + load_bias) == (void *)dyna))
					link_map = (void *)got[1];
			}
			pr_debug("DT_PLTGOT (%p %p %p) link_map = %p\n", got[0], got[1], got[2], link_map);
		} else if (dyna[i].d_tag == DT_SYMTAB) {
			symtab = (void *)dyna[i].d_un.d_ptr;
			pr_debug("DT_SYMTAB (symtab=%p)\n", symtab);
		} else if (dyna[i].d_tag == DT_STRTAB) {
			strtab = (void *)dyna[i].d_un.d_ptr;
			pr_debug("DT_STRTAB (strtab=%p:%s...)\n", strtab, strtab + 1);
		} else if (dyna[i].d_tag == DT_SONAME) {
			soname = (void *)dyna[i].d_un.d_val;
		}
	}

#ifdef __x86_64__
	// workaround the problem with wrong vDSO load base
	if (((unsigned long)strtab >= 0x0000800000000000lu) ||
	    ((unsigned long)symtab >= 0x0000800000000000lu)) {
		pr_debug("vDSO workaround triggered\n");
		return -1;
	}
#endif

	if (symtab && strtab) {
		if (loader_match_libc(strtab + (long)soname))
			return loader_try_libc(lib, dyna, load_bias);
	}

	if (link_map && loader_may_read(link_map, 64)) {
		const struct link_map *lms = link_map;
		while (lms->l_prev) lms = lms->l_prev;
#ifndef NDEBUG
		for (const struct link_map *p = lms; p != NULL; p = p->l_next) {
			PR_LINK_MAP(p);
		}
#endif
		for (const struct link_map *p = lms; p != NULL; p = p->l_next) {
			if (loader_match_libc(p->l_name))
				return loader_try_libc(lib, p->l_ld, p->l_addr);
		}
	}

	pr_debug("FAILED\n\n");

	return -1;
}

long loader_try(unsigned long addr, const char *lib) {
	state_t s = {
		.magic0 = STATE_MAGIC0,
		.logfd = -1,
		.magic1 = STATE_MAGIC1
	};

#ifndef NDEBUG
	char filename[ 64 ];
	snprintf(filename, sizeof(filename), "/tmp/kjector-%u", (unsigned)__syscall0(__NR_gettid));
	s.logfd = __syscall3(__NR_open, (long)filename, O_CREAT | O_APPEND | O_WRONLY, 0644);
#endif

	long res = -1;
	if (__syscall2(__NR_access, (long)lib, R_OK)) {
		pr_debug("no such library %s\n", lib), res = 0; // not an error
	} else {
		res = loader_try_lib(addr, lib);
	}

	return __syscall1(__NR_close, s.logfd), res;
}

////////////////////////////////////////////////////////////////////////////////

void loader(unsigned long addr) {
	long ret = loader_try(addr, (char *)__loader_end);
	__syscall1(__NR_close, ret ? KJECTOR_ACK_REDO : KJECTOR_ACK_DONE);
}
