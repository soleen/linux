/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/linkage.h>
#include <asm/asm.h>
#include <asm/bitsperlong.h>
#include <asm/nospec-branch.h>
#include "caretaker.h"
#include "../caretaker_asm.h"

.section .text.cpu_preserved, "ax"

/**
 * svm_caretaker_enter - Low-level transition to SVM guest mode and back
 * @csp: Pointer to struct caretaker_svm_page (%rdi)
 */
SYM_FUNC_START(svm_caretaker_enter)
	ENDBR
	CARETAKER_PUSH_HOST_REGS
	movq %cr3, %rax
	pushq %rax                  /* saved_cr3 */

	clgi

	/* 0. Save host VMCB state (FS, GS, TR, LDTR) to host save area */
	movq CXP_HSAVE_PA(%rdi), %rax
	testq %rax, %rax
	jz 10f
	vmsave %rax
10:

	/* 1. Load guest VMCB state (FS, GS, TR, LDTR) */
	movq CXP_VMCB_PA(%rdi), %rax
	vmload %rax

	/* 2. Restore guest GPRs */
	CARETAKER_RESTORE_GPRS_NO_RAX %rdi
	incq CXP_VMRUN_ENTRIES(%rdi)

	/* 3. Run guest */
	pushq %rdi
	movq CXP_REG_RDI(%rdi), %rdi
	movq (%rsp), %rax
	movq CXP_VMCB_PA(%rax), %rax
	vmrun %rax

	/* 4. Guest exited: Save guest GPRs */
	xchgq %rdi, (%rsp)          /* rdi = csp, stack = guest rdi */
	popq CXP_REG_RDI(%rdi)

	CARETAKER_SAVE_GPRS_NO_RAX %rdi

	/* 5. Save guest state to VMCB */
	movq CXP_VMCB_PA(%rdi), %rax
	vmsave %rax
	leaq CSP_VMCB_OFFSET(%rdi), %rax
	movq 0x5f8(%rax), %rbx      /* save.rax */
	movq %rbx, CXP_REG_RAX(%rdi)

	/* 5a. Restore host VMCB state (FS, GS, TR, LDTR) from HSAVE */
	movq CXP_HSAVE_PA(%rdi), %rax
	testq %rax, %rax
	jz 40f
	vmload %rax
40:

	/* 5b. Restore host CR3 if clobbered */
	popq %rbx                   /* saved_cr3 */
	movq %cr3, %rcx
	cmpq %rbx, %rcx
	je 50f
	movq %rbx, %cr3
50:
	stgi

	/* 6. Restore host callee-saved registers & return to C */
	CARETAKER_POP_HOST_REGS
	xorq %rax, %rax
	ret
SYM_FUNC_END(svm_caretaker_enter)
