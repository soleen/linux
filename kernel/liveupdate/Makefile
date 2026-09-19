# SPDX-License-Identifier: GPL-2.0

KASAN_SANITIZE_cpu_preserve.o := n
KCSAN_SANITIZE_cpu_preserve.o := n
UBSAN_SANITIZE_cpu_preserve.o := n
KCOV_INSTRUMENT_cpu_preserve.o := n
KASAN_SANITIZE_oncore.o := n
KCSAN_SANITIZE_oncore.o := n
UBSAN_SANITIZE_oncore.o := n
KCOV_INSTRUMENT_oncore.o := n
CFLAGS_REMOVE_cpu_preserve.o = $(CC_FLAGS_FTRACE)
CFLAGS_REMOVE_oncore.o = $(CC_FLAGS_FTRACE)
CFLAGS_cpu_preserve.o += $(call cc-option,-mbranch-protection=none) -fno-stack-protector $(call cc-option,-ftrivial-auto-var-init=uninitialized) $(call cc-option,-fno-jump-tables)
CFLAGS_oncore.o       += $(call cc-option,-mbranch-protection=none) -fno-stack-protector $(call cc-option,-ftrivial-auto-var-init=uninitialized) $(call cc-option,-fno-jump-tables)

luo-y :=								\
		kho_block.o						\
		luo_core.o						\
		luo_file.o						\
		luo_flb.o						\
		luo_session.o

obj-$(CONFIG_KEXEC_HANDOVER)		+= kexec_handover.o
obj-$(CONFIG_KEXEC_HANDOVER_DEBUGFS)	+= kexec_handover_debugfs.o

obj-$(CONFIG_LIVEUPDATE)		+= luo.o
obj-$(CONFIG_LIVEUPDATE_CPU)		+= cpu_preserve.o
obj-$(CONFIG_LIVEUPDATE_ONCORE)		+= oncore.o
