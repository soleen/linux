/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Linker script used for partial linking of cpu_preserved runtime object files.
 * Moves all code and data sections into .cpu_preserved.* sections before
 * symbol prefixing via objcopy --prefix-symbols=__cpu_preserved_.
 */

SECTIONS {
	.cpu_preserved.text : {
		*(.cpu_preserved.text .cpu_preserved.text.*)
		*(.text .text.* .noinstr.text .entry.text .cpuidle.text .sched.text .spinlock.text)
	}

	.cpu_preserved.data : {
		*(.cpu_preserved.data .cpu_preserved.data.*)
		*(.data .data.* .data..ro_after_init .data..read_mostly)
		*(.rodata .rodata.*)
	}

	.cpu_preserved.ex_table : ALIGN(4) {
		*(__ex_table)
	}

	.cpu_preserved.bss : {
		*(.cpu_preserved.bss .cpu_preserved.bss.*)
		*(.bss .bss.* COMMON)
	}

	/DISCARD/ : {
		*(__patchable_function_entries)
	}
}
