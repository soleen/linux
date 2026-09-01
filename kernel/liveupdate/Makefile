# SPDX-License-Identifier: GPL-2.0

CFLAGS_cpu_preserve.o += $(call cc-option,-mbranch-protection=none) -fno-stack-protector

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
