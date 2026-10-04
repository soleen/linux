/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linker script used for partial linking of cpu_preserved runtime object files.
 * Moves all code and data sections into .cpu_preserved.* sections before
 * symbol prefixing via objcopy --prefix-symbols=__cpu_preserved_.
 *
 * The link uses --orphan-handling=error: a section that is not listed here,
 * such as __jump_table, .static_call_sites or __bug_table, would have the host
 * patch or interpret the runtime, and fails the build.
 */
#include <asm-generic/vmlinux.lds.h>

SECTIONS {
	.cpu_preserved.text : {
		*(.cpu_preserved.text .cpu_preserved.text.*)
		*(.text .text.* .noinstr.text .entry.text .cpuidle.text .sched.text .spinlock.text)
	}

	/* Mapped read-only in the isolated address space */
	.cpu_preserved.rodata : {
		*(.cpu_preserved.rodata .cpu_preserved.rodata.*)
		*(.rodata .rodata.* .data..ro_after_init)
	}

	.cpu_preserved.data : {
		*(.cpu_preserved.data .cpu_preserved.data.*)
		*(.data .data.* .data..read_mostly)
	}

	.cpu_preserved.ex_table : ALIGN(4) {
		*(__ex_table)
	}

	.cpu_preserved.bss : {
		*(.cpu_preserved.bss .cpu_preserved.bss.*)
		*(.bss .bss.* COMMON)
	}

	/* Applied to the kernel image at boot, before the runtime is copied */
	.altinstructions : { *(.altinstructions) }
	.altinstr_replacement : { *(.altinstr_replacement) }

	/* Annotations for objtool, which checks vmlinux.o */
	.discard.addressable : { *(.discard.addressable) }
	.discard.annotate_data : { *(.discard.annotate_data) }
	.discard.annotate_insn : { *(.discard.annotate_insn) }
	.discard.func_stack_frame_non_standard : { *(.discard.func_stack_frame_non_standard) }
	.discard.ibt_endbr_noseal : { *(.discard.ibt_endbr_noseal) }
	.discard.unwind_hints : { *(.discard.unwind_hints) }

	DWARF_DEBUG
	STABS_DEBUG
	ELF_DETAILS
	.note.GNU-stack 0 : { *(.note.GNU-stack) }

	/DISCARD/ : {
		*(__patchable_function_entries)
		*(.note.gnu.property)
		*(.llvm_addrsig)
	}
}
