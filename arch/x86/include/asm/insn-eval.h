#ifndef _ASM_X86_INSN_EVAL_H
#define _ASM_X86_INSN_EVAL_H
/*
 * A collection of utility functions for x86 instruction analysis to be
 * used in a kernel context. Useful when, for instance, making sense
 * of the registers indicated by operands.
 */

#include <linux/compiler.h>
#include <linux/bug.h>
#include <linux/err.h>
#include <asm/insn.h>
#include <asm/ptrace.h>

#include <uapi/asm-generic/errno.h>

#define INSN_CODE_SEG_ADDR_SZ(params) ((params >> 4) & 0xf)
#define INSN_CODE_SEG_OPND_SZ(params) (params & 0xf)
#define INSN_CODE_SEG_PARAMS(oper_sz, addr_sz) (oper_sz | (addr_sz << 4))

static inline int pt_regs_offset(struct pt_regs *regs, int regno)
{
	switch (regno) {
	case 0: return offsetof(struct pt_regs, ax);
	case 1: return offsetof(struct pt_regs, cx);
	case 2: return offsetof(struct pt_regs, dx);
	case 3: return offsetof(struct pt_regs, bx);
	case 4: return offsetof(struct pt_regs, sp);
	case 5: return offsetof(struct pt_regs, bp);
	case 6: return offsetof(struct pt_regs, si);
	case 7: return offsetof(struct pt_regs, di);
#ifdef CONFIG_X86_64
	case 8: return offsetof(struct pt_regs, r8);
	case 9: return offsetof(struct pt_regs, r9);
	case 10: return offsetof(struct pt_regs, r10);
	case 11: return offsetof(struct pt_regs, r11);
	case 12: return offsetof(struct pt_regs, r12);
	case 13: return offsetof(struct pt_regs, r13);
	case 14: return offsetof(struct pt_regs, r14);
	case 15: return offsetof(struct pt_regs, r15);
#else
	case 8: return offsetof(struct pt_regs, ds);
	case 9: return offsetof(struct pt_regs, es);
	case 10: return offsetof(struct pt_regs, fs);
	case 11: return offsetof(struct pt_regs, gs);
#endif
	default:
		return -EDOM;
	}
}

bool insn_has_rep_prefix(struct insn *insn);
void __user *insn_get_addr_ref(struct insn *insn, struct pt_regs *regs);
int insn_get_modrm_rm_off(struct insn *insn, struct pt_regs *regs);
int insn_get_modrm_reg_off(struct insn *insn, struct pt_regs *regs);
unsigned long *insn_get_modrm_reg_ptr(struct insn *insn, struct pt_regs *regs);
unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx);
int insn_get_code_seg_params(struct pt_regs *regs);
int insn_get_effective_ip(struct pt_regs *regs, unsigned long *ip);
int insn_fetch_from_user(struct pt_regs *regs,
			 unsigned char buf[MAX_INSN_SIZE]);
int insn_fetch_from_user_inatomic(struct pt_regs *regs,
				  unsigned char buf[MAX_INSN_SIZE]);
bool insn_decode_from_regs(struct insn *insn, struct pt_regs *regs,
			   unsigned char buf[MAX_INSN_SIZE], int buf_size);

enum insn_mmio_type {
	INSN_MMIO_DECODE_FAILED,
	INSN_MMIO_WRITE,
	INSN_MMIO_WRITE_IMM,
	INSN_MMIO_READ,
	INSN_MMIO_READ_ZERO_EXTEND,
	INSN_MMIO_READ_SIGN_EXTEND,
	INSN_MMIO_MOVS,
};

enum insn_mmio_type insn_decode_mmio(struct insn *insn, int *bytes);

bool insn_is_nop(struct insn *insn);

/*
 * Write @val into *@reg following the x86 rules for writes to
 * general-purpose registers (Intel SDM Vol. 1, "General-Purpose
 * Registers in 64-Bit Mode"): an 8- or 16-bit write leaves the rest of
 * the register untouched, a 32-bit write zero-extends the result into
 * the upper 32 bits, and a 64-bit write replaces the whole register.
 *
 * @bytes is the width of the write, not a property of the instruction:
 * an instruction that, say, sign-extends a 32-bit immediate into a
 * 64-bit register does a 64-bit write here.
 *
 * @reg need not be 8-byte aligned: KVM's instruction emulator offsets
 * the pointer by one byte to address the high-byte registers (AH, CH,
 * DH, BH).  Use narrow stores for the sub-word cases so the access
 * width matches @bytes and the adjacent bytes are left alone.
 */
static inline void insn_assign_reg(unsigned long *reg, u64 val, int bytes)
{
	switch (bytes) {
	case 1:
		*(u8 *)reg = (u8)val;
		break;
	case 2:
		*(u16 *)reg = (u16)val;
		break;
	case 4:
		/* A 32-bit write zero-extends into the upper 32 bits. */
		*reg = (u32)val;
		break;
	case 8:
		*reg = val;
		break;
	}
}

#include <asm/extable.h>

static __always_inline unsigned long *pt_regs_nr(struct pt_regs *regs, int nr)
{
	int reg_offset = pt_regs_offset(regs, nr);

	if (unlikely(reg_offset < 0)) {
#ifndef __CPU_PRESERVED_RUNTIME__
		static unsigned long __dummy;

		WARN_ON_ONCE(1);
		return &__dummy;
#else
		return &regs->ax;
#endif
	}

	return (unsigned long *)((unsigned long)regs + reg_offset);
}

static __always_inline bool
ex_handler_default(const struct exception_table_entry *e, struct pt_regs *regs)
{
	if (e->data & EX_FLAG_CLEAR_AX)
		regs->ax = 0;
	if (e->data & EX_FLAG_CLEAR_DX)
		regs->dx = 0;

	regs->ip = ex_fixup_addr(e);
	return true;
}

static __always_inline bool
ex_handler_fault(const struct exception_table_entry *fixup,
		 struct pt_regs *regs, int trapnr)
{
	regs->ax = trapnr;
	return ex_handler_default(fixup, regs);
}

static __always_inline bool
ex_handler_imm_reg(const struct exception_table_entry *fixup,
		   struct pt_regs *regs, int reg, int imm)
{
	*pt_regs_nr(regs, reg) = (long)imm;
	return ex_handler_default(fixup, regs);
}

static __always_inline bool
ex_handler_msr_common(const struct exception_table_entry *fixup,
		      struct pt_regs *regs, bool wrmsr, bool safe, int reg)
{
	if (!wrmsr) {
		/* Pretend that the read succeeded and returned 0. */
		regs->ax = 0;
		regs->dx = 0;
	}

	if (safe)
		*pt_regs_nr(regs, reg) = -EIO;

	return ex_handler_default(fixup, regs);
}

static __always_inline bool
ex_fixup_basic(const struct exception_table_entry *e, struct pt_regs *regs,
	       int type, int trapnr, int reg, int imm)
{
	switch (type) {
	case EX_TYPE_DEFAULT:
	case EX_TYPE_DEFAULT_MCE_SAFE:
		return ex_handler_default(e, regs);
	case EX_TYPE_FAULT:
	case EX_TYPE_FAULT_MCE_SAFE:
		return ex_handler_fault(e, regs, trapnr);
	case EX_TYPE_POP_REG:
		regs->sp += sizeof(long);
		fallthrough;
	case EX_TYPE_IMM_REG:
		return ex_handler_imm_reg(e, regs, reg, imm);
	default:
		return false;
	}
}

#endif /* _ASM_X86_INSN_EVAL_H */
