# SPDX-License-Identifier: GPL-2.0

UBSAN_SANITIZE_cpu_preserve.o := n
GCOV_PROFILE_cpu_preserve.o := n
KMSAN_SANITIZE_cpu_preserve.o := n
CFLAGS_cpu_preserve.o += $(call cc-option,-mbranch-protection=none) $(DISABLE_KSTACK_ERASE) -DDISABLE_BRANCH_PROFILING $(call cc-option,-ftrivial-auto-var-init=uninitialized) $(call cc-option,-fno-jump-tables)
UBSAN_SANITIZE_oncore.o := n
GCOV_PROFILE_oncore.o := n
KMSAN_SANITIZE_oncore.o := n
CFLAGS_oncore.o       += $(call cc-option,-mbranch-protection=none) $(DISABLE_KSTACK_ERASE) -DDISABLE_BRANCH_PROFILING $(call cc-option,-ftrivial-auto-var-init=uninitialized) $(call cc-option,-fno-jump-tables)

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
