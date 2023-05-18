#include <syscall.h>

.section .text.startup

.globl ENTRY

#ifdef __x86_64__
ENTRY:
	pushfq
	movq	%rax, %rcx
	shrq	$8, %rcx
	andq	$0xff, %rax
	negq	%rax

	//
	// Save the full state no matter of the ABI used.
	//

	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
	pushq	%rdi
	pushq	%rsi
	pushq	%rbp
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15

	//
	// Align the stack to 16 byte boundary before calling the entry and
	// pass the %RCX (ADDR) as an argument to the _start function.
	//

	pushq	%rbp
	movq	%rsp, %rbp
	and	$0xfffffffffffffff0, %rsp
	movq	%rcx, %rdi
	callq	loader
	movq	%rbp, %rsp
	pop	%rbp

	//
	// Restore the full state & jump back.
	//

	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rbp
	popq	%rsi
	popq	%rdi
	popq	%rdx
	popq	%rcx
	popq	%rbx
	popq	%rax
	popfq

	jmpq	*%rcx

#else
# error !!! NOT IMPLEMENTED !!!
#endif
