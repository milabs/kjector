#pragma once

#include <elf.h>
#include <link.h>
#include <syscall.h>

#ifndef KJECTOR_ACK_DONE
#define KJECTOR_ACK_DONE	((unsigned)0xc1c1c1c1)
#endif

#ifndef KJECTOR_ACK_REDO
#define KJECTOR_ACK_REDO	((unsigned)0xc2c2c2c2)
#endif

// provided by the linker
extern unsigned char __loader[];
extern unsigned char __loader_end[];

#ifdef __x86_64__

#ifndef PAGE_SIZE
#define PAGE_SIZE	(1UL << 12)
#define PAGE_MASK	(~(PAGE_SIZE-1))
#endif

static inline unsigned long get_pc(void) {
	unsigned long pc;
	asm volatile ("lea (%%rip), %0;": "=r"(pc));
	return pc;
}

static inline long __syscall0(long n) {
	unsigned long ret;
	asm volatile ( "syscall" : "=a"(ret) : "a"(n) : "rcx", "r11", "memory");
	return ret;
}

static inline long __syscall1(long n, long a1) {
	unsigned long ret;
	asm volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1) : "rcx", "r11", "memory");
	return ret;
}

static inline long __syscall2(long n, long a1, long a2) {
	unsigned long ret;
	asm volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2) : "rcx", "r11", "memory");
	return ret;
}

static inline long __syscall3(long n, long a1, long a2, long a3) {
	unsigned long ret;
	asm volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx", "r11", "memory");
	return ret;
}

static inline long __syscall4(long n, long a1, long a2, long a3, long a4) {
	unsigned long ret;
	register long ra4 asm ("r10") = a4;
	asm volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(ra4) : "rcx", "r11", "memory");
	return ret;
}

static inline long __syscall5(long n, long a1, long a2, long a3, long a4, long a5) {
	unsigned long ret;
	register long ra4 asm ("r10") = a4;
	register long ra5 asm  ("r8") = a5;
	asm volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(ra4), "r"(ra5) : "rcx", "r11", "memory");
	return ret;
}

static inline long __syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
	unsigned long ret;
	register long ra4 asm ("r10") = a4;
	register long ra5 asm  ("r8") = a5;
	register long ra6 asm  ("r9") = a6;
	asm volatile ( "syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(ra4), "r"(ra5), "r"(ra6) : "rcx", "r11", "memory");
	return ret;
}

#else
# error NOT IMPLEMENTED
#endif
