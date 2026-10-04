// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 *
 * KVM Caretaker selftest across intra-kernel preserve/cancel loops (including
 * vCPU oversubscription on a preserved physical CPU) and kexec Live Updates
 * using regular memfd-backed guest memory.
 *
 * Stage 1:
 *   1. Pins the test runner to CPU 0 and locates an online non-boot physical
 *      CPU to preserve.
 *   2. Creates a 2-vCPU VM with Slot 0 backed by a regular memfd.
 *   3. Runs a 2-iteration Caretaker preserve/cancel loop without kexec,
 *      multiplexing 2 vCPUs onto 1 preserved physical CPU (oversubscription),
 *      verifying that both vCPUs' guest counters advance while running on-core
 *      under Caretaker, and verifying clean reclamation and normal KVM_RUN
 *      execution after cancelling the session.
 *   4. Preserves the physical CPU, VM fd, memfd, and vCPU fds in a LUO
 *      session, waits for both vCPUs to advance on-core under Caretaker,
 *      records pre_kexec_counter, and daemonizes awaiting kexec.
 *
 * Stage 2 (after kexec):
 *   1. Retrieves the preserved memfd first (before detaching Caretaker via VM
 *      retrieval) and verifies that both vCPUs' counters advanced during kexec
 *      and are still actively advancing on-core in Stage 2.
 *   2. Retrieves the VM fd, vCPU fds, and preserved CPU fd, detaching the
 *      vCPUs from Caretaker into post-kexec KVM.
 *   3. Validates Caretaker debugfs telemetry (runs >= 1, stalls == 0).
 *   4. Resumes both vCPUs in normal KVM_RUN, verifies UCALL_SYNC and clean
 *      exit via GUEST_DONE(), and finishes the LUO session.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/sizes.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"
#include "../kselftest.h"

#ifdef __x86_64__
#include "apic.h"
#elif defined(__aarch64__)
#include "arch_timer.h"
#include "gic.h"
#include "gic_v3.h"
#include "vgic.h"
#endif

#include <libliveupdate.h>

#define NR_TEST_VCPUS		2
#define NR_CANCEL_ITERS		2
#define NR_SLOT0_PAGES		2048ULL /* 8 MB for Slot 0 */
#define MIN_CARETAKER_DELTA	1000ULL
#define POLL_TIMEOUT_MS		5000ULL

#define CARETAKER_TEST_MAGIC	0x4341524554414b52ULL /* "CARETAKR" */

#define SESSION_NAME		"caretaker_kexec_session"
#define CANCEL_SESSION_NAME	"caretaker_cancel_session"
#define STATE_SESSION_NAME	"caretaker_state_session"

#define STATE_TOKEN		0x999
#define CPU_TOKEN_BASE		0x3000
#define VM_TOKEN		0x3010
#define MEMFD_TOKEN		0x3020
#define VCPU_TOKEN_BASE		0x3100

/* Stored at Page 0 of Slot 0 memfd (GPA 0, unused by kvm_util since KVM_UTIL_MIN_PFN == 2). */
struct caretaker_meta {
	uint64_t magic;
	uint64_t slot0_hva;
	uint64_t slot0_size;
	uint64_t ucall_mmio_gpa;
	uint64_t ucalls_offset;
	uint64_t sh_gpa;
	int32_t  target_cpu;
	uint32_t has_gic;
};

struct caretaker_vcpu_slot {
	uint64_t counter;
	uint64_t pre_kexec_counter;
	uint32_t sync_requested;
	uint32_t stop_requested;
	uint64_t sync_seq;
	uint32_t resumed_ok;
	uint32_t pad;
} __aligned(64);

struct caretaker_shared {
	uint64_t magic;
	struct ucall uc[NR_TEST_VCPUS];
	struct caretaker_vcpu_slot vcpu[NR_TEST_VCPUS];
};

static inline uint64_t host_load_u64(const volatile uint64_t *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void host_store_u64(volatile uint64_t *p, uint64_t v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static inline uint32_t host_load_u32(const volatile uint32_t *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void host_store_u32(volatile uint32_t *p, uint32_t v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static uint64_t monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static void pin_to_cpu0(void)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(0, &set);
	TEST_ASSERT_EQ(sched_setaffinity(0, sizeof(set), &set), 0);
}

static int read_cpu_online(int cpu)
{
	char path[128], buf[16];
	int fd, val = -1;

	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", cpu);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, buf, sizeof(buf) - 1) > 0)
		val = atoi(buf);
	close(fd);
	return val;
}

static int find_target_cpu(void)
{
	char path[128];
	int cpu;

	for (cpu = 1; cpu < 256; cpu++) {
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/preserve", cpu);
		if (access(path, R_OK) == 0 && read_cpu_online(cpu) == 1)
			return cpu;
	}
	return -1;
}

static int preserve_cpu_fd(int session_fd, int cpu, uint64_t token)
{
	char path[128];
	int cpu_fd, ret;

	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/preserve", cpu);
	cpu_fd = open(path, O_RDONLY);
	if (cpu_fd < 0)
		return -1;

	ret = luo_session_preserve_fd(session_fd, cpu_fd, token);
	close(cpu_fd);
	return ret;
}

/*
 * Perform a ucall using the pre-allocated per-vCPU ucall struct inside
 * struct caretaker_shared so returning from ucall after vcpu_run_complete_io()
 * does not touch ucall_pool->in_use while running under Caretaker.
 */
static noinline void guest_do_sync(struct caretaker_shared *sh,
				   uint32_t vcpu_id, uint64_t seq)
{
	struct ucall *uc = &sh->uc[vcpu_id];

	memset(uc->args, 0, sizeof(uc->args));
	WRITE_ONCE(uc->cmd, UCALL_SYNC);
	WRITE_ONCE(uc->args[0], vcpu_id);
	WRITE_ONCE(uc->args[1], seq);
	ucall_arch_do_ucall((gva_t)READ_ONCE(uc->hva));
}

static void guest_caretaker_code(uint32_t vcpu_id, struct caretaker_shared *sh)
{
	struct caretaker_vcpu_slot *slot = &sh->vcpu[vcpu_id];

	__GUEST_ASSERT(sh->magic == CARETAKER_TEST_MAGIC,
		       "Unexpected magic in caretaker_shared: 0x%lx", sh->magic);

	/*
	 * Initial sync via standard ucall pool so the host can record
	 * ucalls_offset in Page 0 metadata.
	 */
	GUEST_SYNC(0);

	while (!READ_ONCE(slot->stop_requested)) {
		uint64_t c = READ_ONCE(slot->counter) + 1;

		WRITE_ONCE(slot->counter, c);

		if (unlikely(READ_ONCE(slot->sync_requested))) {
			uint64_t seq = READ_ONCE(slot->sync_seq) + 1;

			WRITE_ONCE(slot->sync_seq, seq);
			WRITE_ONCE(slot->sync_requested, 0);
			guest_do_sync(sh, vcpu_id, seq);
		}
		if ((c & 0xff) == 0)
			cpu_relax();
	}

	WRITE_ONCE(slot->resumed_ok, 1);
	GUEST_DONE();
}

static void relocate_ucall_hvas(void *slot0_hva, const struct caretaker_meta *meta,
				struct caretaker_shared *sh)
{
	struct ucall *pool_ucalls;
	int i;

	for (i = 0; i < NR_TEST_VCPUS; i++)
		sh->uc[i].hva = &sh->uc[i];

	if (meta->ucalls_offset &&
	    meta->ucalls_offset + sizeof(struct ucall) * KVM_MAX_VCPUS <= meta->slot0_size) {
		pool_ucalls = (struct ucall *)((uintptr_t)slot0_hva + meta->ucalls_offset);
		for (i = 0; i < KVM_MAX_VCPUS; i++)
			pool_ucalls[i].hva = &pool_ucalls[i];
	}
}

static struct kvm_vm *create_vm_with_shared_slot0(struct kvm_vcpu *vcpus[],
						  int target_cpu,
						  int *out_memfd,
						  struct caretaker_meta **out_meta,
						  struct caretaker_shared **out_sh)
{
	struct userspace_mem_region *slot0;
	struct caretaker_shared *sh;
	struct caretaker_meta *meta;
	struct kvm_vm *vm;
	gva_t sh_gva;
	int i;

	vm = ____vm_create(VM_SHAPE_DEFAULT);
	vm_userspace_mem_region_add(vm, VM_MEM_SRC_SHMEM, 0, 0, NR_SLOT0_PAGES, 0);
	for (i = 0; i < NR_MEM_REGIONS; i++)
		vm->memslots[i] = 0;

	kvm_vm_elf_load(vm, program_invocation_name);

	slot0 = memslot2region(vm, 0);
	ucall_init(vm, slot0->region.guest_phys_addr + slot0->region.memory_size);
	kvm_arch_vm_post_create(vm, NR_TEST_VCPUS);

	sh_gva = vm_alloc_pages(vm, 2);
	sh = addr_gva2hva(vm, sh_gva);
	memset(sh, 0, sizeof(*sh));
	sh->magic = CARETAKER_TEST_MAGIC;
	for (i = 0; i < NR_TEST_VCPUS; i++)
		sh->uc[i].hva = &sh->uc[i];

	meta = (struct caretaker_meta *)slot0->host_mem;
	memset(meta, 0, sizeof(*meta));
	meta->magic = CARETAKER_TEST_MAGIC;
	meta->slot0_hva = (uintptr_t)slot0->host_mem;
	meta->slot0_size = slot0->region.memory_size;
	meta->ucall_mmio_gpa = slot0->region.guest_phys_addr + slot0->region.memory_size;
	meta->sh_gpa = (uintptr_t)sh - (uintptr_t)slot0->host_mem;
	meta->target_cpu = target_cpu;
#ifdef __aarch64__
	meta->has_gic = vm->arch.has_gic ? 1 : 0;
#endif

	for (i = 0; i < NR_TEST_VCPUS; i++) {
		vcpus[i] = vm_vcpu_add(vm, i, guest_caretaker_code);
		vcpu_args_set(vcpus[i], 2, i, sh_gva);
	}
	kvm_arch_vm_finalize_vcpus(vm);

	*out_memfd = slot0->fd;
	*out_meta = meta;
	*out_sh = sh;
	return vm;
}

/*
 * Request a synchronous UCALL_SYNC from inside the guest's Caretaker loop and
 * run the vCPU until it hits that sync point. Calling this after memfd_luo_preserve()
 * has pinned all memfd folios guarantees that every code, stack, page-table,
 * and shared-data page needed by the guest loop is faulted into KVM's Stage-2 /
 * TDP MMU before Caretaker takes over the vCPU.
 */
static void prefault_and_sync_vcpu(struct kvm_vcpu *vcpu,
				   struct caretaker_shared *sh,
				   uint32_t vcpu_id)
{
	uint64_t prev_seq = host_load_u64(&sh->vcpu[vcpu_id].sync_seq);
	struct ucall uc;

	host_store_u32(&sh->vcpu[vcpu_id].sync_requested, 1);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
	TEST_ASSERT_EQ(uc.args[0], vcpu_id);
	TEST_ASSERT_EQ(uc.args[1], prev_seq + 1);
	TEST_ASSERT_EQ(host_load_u32(&sh->vcpu[vcpu_id].sync_requested), 0);
}

static void wait_for_vcpu_counter_advance(struct caretaker_shared *sh,
					  uint32_t vcpu_id,
					  uint64_t baseline,
					  uint64_t min_delta)
{
	uint64_t deadline = monotonic_ms() + POLL_TIMEOUT_MS;
	uint64_t cur;

	for (;;) {
		cur = host_load_u64(&sh->vcpu[vcpu_id].counter);
		if (cur >= baseline + min_delta)
			return;
		TEST_ASSERT(monotonic_ms() <= deadline,
			    "Timed out waiting for Caretaker vCPU %u counter to advance: baseline=%lu cur=%lu",
			    vcpu_id, (unsigned long)baseline, (unsigned long)cur);
		usleep(1000);
	}
}

static void verify_caretaker_telemetry(const char *phase)
{
	char dir_prefix[32], path[512], buf[512];
	struct dirent *de;
	DIR *dir;
	int i;

	dir = opendir("/sys/kernel/debug/kvm");
	if (!dir) {
		ksft_print_msg("[%s] /sys/kernel/debug/kvm not accessible; skipping telemetry check\n",
			       phase);
		return;
	}

	snprintf(dir_prefix, sizeof(dir_prefix), "%d-", getpid());
	while ((de = readdir(dir)) != NULL) {
		if (strncmp(de->d_name, dir_prefix, strlen(dir_prefix)) != 0)
			continue;

		for (i = 0; i < NR_TEST_VCPUS; i++) {
			unsigned long long runs = 0, exits = 0, stalls = 0;
			ssize_t n;
			int fd, parsed;

			snprintf(path, sizeof(path),
				 "/sys/kernel/debug/kvm/%s/vcpu%d/caretaker_telemetry",
				 de->d_name, i);
			fd = open(path, O_RDONLY);
			if (fd < 0)
				continue;

			n = read(fd, buf, sizeof(buf) - 1);
			close(fd);
			TEST_ASSERT(n > 0, "Failed to read %s", path);
			buf[n] = '\0';

			parsed = sscanf(buf, "runs: %llu\nexits: %llu\nstalls: %llu",
					&runs, &exits, &stalls);
			TEST_ASSERT_EQ(parsed, 3);
			ksft_print_msg("[%s] vCPU %d telemetry: runs=%llu exits=%llu stalls=%llu\n",
				       phase, i, runs, exits, stalls);
			TEST_ASSERT(runs >= 1,
				    "[%s] Expected vCPU %d Caretaker runs >= 1, got %llu",
				    phase, i, runs);
			TEST_ASSERT_EQ(stalls, 0ULL);
		}
		break;
	}

	closedir(dir);
}

static void run_stage_1(int luo_fd)
{
	struct kvm_vcpu *vcpus[NR_TEST_VCPUS];
	struct caretaker_shared *sh;
	struct caretaker_meta *meta;
	int memfd, session_fd, target_cpu, i, iter;
	int pipefd[2], status;
	struct kvm_vm *vm;
	struct ucall uc;
	char ready = 0;
	pid_t pid;

	pin_to_cpu0();
	target_cpu = find_target_cpu();
	if (target_cpu < 0) {
		ksft_print_msg("[STAGE 1] No preservable non-boot CPU found; skipping\n");
		ksft_exit_skip("No preservable non-boot CPU available\n");
	}

	/*
	 * Fork the persistent background process BEFORE calling KVM_CREATE_VM.
	 * KVM binds kvm->mm to the process that creates the VM; if the VM
	 * creator exits (as in standard post-preserve fork/exit daemonization),
	 * exit_mm() fires mmu_notifier_release() and zaps the TDP / Stage-2
	 * page tables while Caretaker is actively running the vCPUs.
	 */
	TEST_ASSERT_EQ(pipe(pipefd), 0);
	pid = fork();
	TEST_ASSERT(pid >= 0, "fork failed");
	if (pid > 0) {
		close(pipefd[1]);
		close(luo_fd);
		if (read(pipefd[0], &ready, 1) == 1 && ready == 'R') {
			close(pipefd[0]);
			ksft_print_msg("[STAGE 1] Child PID %d holding VM mm and LUO sessions; ready for kexec.\n",
				       pid);
			exit(EXIT_SUCCESS);
		}
		close(pipefd[0]);
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
		if (WIFEXITED(status))
			exit(WEXITSTATUS(status));
		exit(EXIT_FAILURE);
	}
	close(pipefd[0]);

	ksft_print_msg("[STAGE 1] Using physical CPU %d for Caretaker (%d vCPUs)...\n",
		       target_cpu, NR_TEST_VCPUS);

	vm = create_vm_with_shared_slot0(vcpus, target_cpu, &memfd, &meta, &sh);

	/* Step each vCPU to initial GUEST_SYNC(0) and record ucalls_offset. */
	for (i = 0; i < NR_TEST_VCPUS; i++) {
		vcpu_run(vcpus[i]);
		if (i == 0) {
			void *uc0 = ucall_arch_get_ucall(vcpus[0]);

			TEST_ASSERT(uc0 != NULL, "Failed to get ucall0 HVA");
			meta->ucalls_offset = (uintptr_t)uc0 - meta->slot0_hva;
		}
		TEST_ASSERT_EQ(get_ucall(vcpus[i], &uc), UCALL_SYNC);
		TEST_ASSERT_EQ(uc.args[1], 0);
	}

	/*
	 * Subtest 1: Caretaker preserve/cancel loop without kexec, multiplexing
	 * NR_TEST_VCPUS (2) vCPUs onto 1 preserved physical CPU (oversubscription).
	 */
	ksft_print_msg("[STAGE 1] Running %d-iteration Caretaker preserve/cancel loop (M=%d vCPUs on N=1 CPU)...\n",
		       NR_CANCEL_ITERS, NR_TEST_VCPUS);

	for (iter = 0; iter < NR_CANCEL_ITERS; iter++) {
		uint64_t c_before[NR_TEST_VCPUS];
		int cancel_fd = luo_create_session(luo_fd, CANCEL_SESSION_NAME);

		TEST_ASSERT(cancel_fd >= 0, "Failed to create cancel session");
		TEST_ASSERT_EQ(preserve_cpu_fd(cancel_fd, target_cpu, CPU_TOKEN_BASE), 0);
		TEST_ASSERT_EQ(luo_session_preserve_fd(cancel_fd, vm->fd, VM_TOKEN), 0);
		TEST_ASSERT_EQ(luo_session_preserve_fd(cancel_fd, memfd, MEMFD_TOKEN), 0);

		/*
		 * Pre-fault all guest loop pages into Stage-2 / TDP MMU now
		 * that memfd_pin_folios() has pinned Slot 0's folios.
		 */
		for (i = 0; i < NR_TEST_VCPUS; i++) {
			prefault_and_sync_vcpu(vcpus[i], sh, i);
			c_before[i] = host_load_u64(&sh->vcpu[i].counter);
		}

		for (i = 0; i < NR_TEST_VCPUS; i++) {
			int ret = luo_session_preserve_fd(cancel_fd, vcpus[i]->fd,
							  VCPU_TOKEN_BASE + i);
			if (ret < 0 && errno == EOPNOTSUPP) {
				close(cancel_fd);
				ksft_exit_skip("KVM Caretaker not supported on this CPU/config (EOPNOTSUPP)\n");
			}
			TEST_ASSERT_EQ(ret, 0);
		}

		/*
		 * Both vCPUs are now actively scheduled on target_cpu by the
		 * On-Core scheduler under Caretaker. Wait for both counters to
		 * advance in shared memfd memory.
		 */
		for (i = 0; i < NR_TEST_VCPUS; i++)
			wait_for_vcpu_counter_advance(sh, i, c_before[i], MIN_CARETAKER_DELTA);

		/*
		 * Cancel the session by closing cancel_fd. LIFO unpreserve
		 * detaches both vCPUs from Caretaker, synchronizes their live
		 * register state back into host KVM, and returns target_cpu
		 * online.
		 */
		close(cancel_fd);
		TEST_ASSERT_EQ(read_cpu_online(target_cpu), 1);

		verify_caretaker_telemetry("STAGE 1 CANCEL");

		/* Verify normal host KVM takeover via KVM_RUN + UCALL_SYNC. */
		for (i = 0; i < NR_TEST_VCPUS; i++)
			prefault_and_sync_vcpu(vcpus[i], sh, i);

		ksft_print_msg("[STAGE 1] Caretaker preserve/cancel iteration %d/%d PASSED (vcpu0=%lu vcpu1=%lu)\n",
			       iter + 1, NR_CANCEL_ITERS,
			       (unsigned long)host_load_u64(&sh->vcpu[0].counter),
			       (unsigned long)host_load_u64(&sh->vcpu[1].counter));
	}

	/*
	 * Subtest 2: Cross-kexec Caretaker preservation.
	 */
	ksft_print_msg("[STAGE 1] Preserving physical CPU %d, VM, memfd, and %d vCPUs for kexec...\n",
		       target_cpu, NR_TEST_VCPUS);
	create_state_file(luo_fd, STATE_SESSION_NAME, STATE_TOKEN, 2);

	session_fd = luo_create_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "Failed to create LUO session");

	TEST_ASSERT_EQ(preserve_cpu_fd(session_fd, target_cpu, CPU_TOKEN_BASE), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd, VM_TOKEN), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, memfd, MEMFD_TOKEN), 0);

	/* Pre-fault guest loop pages after memfd_pin_folios(). */
	for (i = 0; i < NR_TEST_VCPUS; i++)
		prefault_and_sync_vcpu(vcpus[i], sh, i);

	for (i = 0; i < NR_TEST_VCPUS; i++) {
		TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vcpus[i]->fd,
						       VCPU_TOKEN_BASE + i), 0);
	}

	/* Wait for both vCPUs to actively advance under Caretaker, then record baseline. */
	for (i = 0; i < NR_TEST_VCPUS; i++) {
		uint64_t base = host_load_u64(&sh->vcpu[i].counter);

		wait_for_vcpu_counter_advance(sh, i, base, MIN_CARETAKER_DELTA);
	}
	for (i = 0; i < NR_TEST_VCPUS; i++) {
		host_store_u64(&sh->vcpu[i].pre_kexec_counter,
			       host_load_u64(&sh->vcpu[i].counter));
		ksft_print_msg("[STAGE 1] vCPU %d active on Caretaker: pre_kexec_counter=%lu\n",
			       i, (unsigned long)host_load_u64(&sh->vcpu[i].pre_kexec_counter));
	}

	ksft_print_msg("[STAGE 1] Caretaker active; signaling parent for kexec...\n");
	close(luo_fd);
	ready = 'R';
	TEST_ASSERT_EQ(write(pipefd[1], &ready, 1), 1);
	close(pipefd[1]);
	setsid();
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	if (chdir("/") < 0)
		_exit(EXIT_FAILURE);
	for (;;)
		sleep(60);
}

static void setup_retrieved_irqchip(struct kvm_vm *vm, const struct caretaker_meta *meta)
{
#ifdef __x86_64__
	vm_create_irqchip(vm);
#elif defined(__aarch64__)
	if (meta->has_gic) {
		uint32_t nr_irqs = 64;
		uint64_t attr;
		int gic_fd;

		gic_fd = __kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3);
		TEST_ASSERT(gic_fd >= 0, "Failed to create VGICv3 on retrieved VM");

		kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr_irqs);
		attr = GICD_BASE_GPA;
		kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				    KVM_VGIC_V3_ADDR_TYPE_DIST, &attr);
		attr = REDIST_REGION_ATTR_ADDR(NR_TEST_VCPUS, GICR_BASE_GPA, 0, 0);
		kvm_device_attr_set(gic_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				    KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &attr);

		vm->arch.gic_fd = gic_fd;
		vm->arch.has_gic = true;
	}
#endif
}

static void run_stage_2(int luo_fd, int state_session_fd)
{
	int retrieved_vm_fd, retrieved_memfd, retrieved_cpu_fd;
	int vcpu_fds[NR_TEST_VCPUS];
	uint64_t c1[NR_TEST_VCPUS], c2[NR_TEST_VCPUS];
	struct kvm_vcpu *vcpus[NR_TEST_VCPUS];
	struct caretaker_meta meta_snap, *meta;
	struct caretaker_shared *sh;
	int session_fd, stage, i;
	struct kvm_vm *vm;
	void *slot0_hva;

	pin_to_cpu0();
	ksft_print_msg("[STAGE 2] Starting post-kexec Caretaker verification...\n");

	restore_and_read_stage(state_session_fd, STATE_TOKEN, &stage);
	TEST_ASSERT_EQ(stage, 2);

	session_fd = luo_retrieve_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "Failed to retrieve LUO session '%s'", SESSION_NAME);

	/*
	 * Retrieve memfd FIRST, before retrieving VM_TOKEN (which calls
	 * kvm_caretaker_vm_pre_retrieve() to detach preserved CPUs), so we can
	 * observe the vCPUs still actively executing under Caretaker in Stage 2!
	 */
	retrieved_memfd = luo_session_retrieve_fd(session_fd, MEMFD_TOKEN);
	TEST_ASSERT(retrieved_memfd >= 0, "Failed to retrieve Slot 0 memfd");

	TEST_ASSERT_EQ(pread(retrieved_memfd, &meta_snap, sizeof(meta_snap), 0),
		       (ssize_t)sizeof(meta_snap));
	TEST_ASSERT_EQ(meta_snap.magic, CARETAKER_TEST_MAGIC);

	slot0_hva = mmap((void *)(uintptr_t)meta_snap.slot0_hva, meta_snap.slot0_size,
			 PROT_READ | PROT_WRITE, MAP_SHARED, retrieved_memfd, 0);
	TEST_ASSERT(slot0_hva != MAP_FAILED, "Failed to mmap retrieved Slot 0 memfd");

	meta = (struct caretaker_meta *)slot0_hva;
	sh = (struct caretaker_shared *)((uintptr_t)slot0_hva + meta->sh_gpa);
	TEST_ASSERT_EQ(sh->magic, CARETAKER_TEST_MAGIC);
	relocate_ucall_hvas(slot0_hva, meta, sh);

	/*
	 * Verify that both vCPUs' counters advanced during kexec AND are still
	 * actively advancing live in Stage 2 while Caretaker owns the CPU.
	 */
	for (i = 0; i < NR_TEST_VCPUS; i++)
		c1[i] = host_load_u64(&sh->vcpu[i].counter);

	usleep(50000);

	for (i = 0; i < NR_TEST_VCPUS; i++) {
		uint64_t pre = host_load_u64(&sh->vcpu[i].pre_kexec_counter);

		c2[i] = host_load_u64(&sh->vcpu[i].counter);
		ksft_print_msg("[STAGE 2] vCPU %d counter: pre_kexec=%lu post_c1=%lu post_c2=%lu\n",
			       i, (unsigned long)pre, (unsigned long)c1[i], (unsigned long)c2[i]);
		TEST_ASSERT(c1[i] > pre,
			    "vCPU %d counter did not advance across kexec (pre=%lu, c1=%lu)",
			    i, (unsigned long)pre, (unsigned long)c1[i]);
		TEST_ASSERT(c2[i] > c1[i],
			    "vCPU %d counter did not advance live in Stage 2 (c1=%lu, c2=%lu)",
			    i, (unsigned long)c1[i], (unsigned long)c2[i]);
	}

	/* Now retrieve VM, vCPUs, and physical CPU to transition back to normal KVM. */
	retrieved_vm_fd = luo_session_retrieve_fd(session_fd, VM_TOKEN);
	TEST_ASSERT(retrieved_vm_fd >= 0, "Failed to retrieve VM fd");

	vm = vm_create_from_fd(retrieved_vm_fd, VM_SHAPE_DEFAULT);
	vm->ucall_mmio_addr = meta->ucall_mmio_gpa;
	vm_set_user_memory_region(vm, 0, 0, 0, meta->slot0_size, slot0_hva);
	setup_retrieved_irqchip(vm, meta);

	for (i = 0; i < NR_TEST_VCPUS; i++) {
		vcpu_fds[i] = luo_session_retrieve_fd(session_fd, VCPU_TOKEN_BASE + i);
		TEST_ASSERT(vcpu_fds[i] >= 0, "Failed to retrieve vCPU %d fd", i);
		vcpus[i] = vm_vcpu_add_from_fd(vm, i, vcpu_fds[i]);
	}
	kvm_arch_vm_finalize_vcpus(vm);

	retrieved_cpu_fd = luo_session_retrieve_fd(session_fd, CPU_TOKEN_BASE);
	TEST_ASSERT(retrieved_cpu_fd >= 0, "Failed to retrieve preserved CPU fd");

	verify_caretaker_telemetry("STAGE 2 RETRIEVE");

	ksft_print_msg("[STAGE 2] Resuming vCPUs in normal KVM_RUN and running to GUEST_DONE...\n");
	for (i = 0; i < NR_TEST_VCPUS; i++) {
		prefault_and_sync_vcpu(vcpus[i], sh, i);
		host_store_u32(&sh->vcpu[i].stop_requested, 1);
		vcpu_run(vcpus[i]);
		TEST_ASSERT_EQ(get_ucall(vcpus[i], NULL), UCALL_DONE);
		TEST_ASSERT_EQ(host_load_u32(&sh->vcpu[i].resumed_ok), 1U);
	}
	ksft_print_msg("[STAGE 2] All %d vCPUs cleanly resumed and completed in KVM!\n",
		       NR_TEST_VCPUS);

	TEST_ASSERT_EQ(luo_session_finish(session_fd), 0);
	close(retrieved_cpu_fd);
	close(session_fd);

	TEST_ASSERT_EQ(luo_session_finish(state_session_fd), 0);
	close(state_session_fd);

	TEST_ASSERT_EQ(read_cpu_online(meta->target_cpu), 1);

	kvm_vm_free(vm);
	munmap(slot0_hva, meta_snap.slot0_size);
	close(retrieved_memfd);
}

int main(int argc, char *argv[])
{
#ifdef __aarch64__
	/* Caretaker does not support nested virtualization (EL2). */
	setenv("NV", "0", 1);
#endif
	return luo_test(argc, argv, STATE_SESSION_NAME, run_stage_1, run_stage_2);
}
