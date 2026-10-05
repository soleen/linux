// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 *
 * Selftest for the On-Core Session and Scheduler Framework (CONFIG_LIVEUPDATE_ONCORE)
 * across intra-kernel cancel loops and kexec Live Updates.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include <libliveupdate.h>

#define ONCORE_TEST_DEBUGFS_PATH	"/sys/kernel/debug/oncore_test"
#define ONCORE_TEST_MAGIC		0x4f4e435254455354ULL

#define TEST_SESSION_NAME		"oncore-kexec-session"
#define STATE_SESSION_NAME		"oncore_state_session"
#define STATE_MEMFD_TOKEN		0x999
#define TEST_CPU_TOKEN			0x100
#define TEST_JOB_TOKEN_BASE		0x200

struct oncore_test_buf {
	uint64_t magic;
	uint64_t counter;
	uint64_t tickless_quanta;
	uint64_t sliced_quanta;
	int32_t  last_cpu;
	uint32_t reserved;
	uint64_t ping_val;
	uint64_t pong_val;
};

struct oncore_stage_state {
	int      target_cpu;
	uint64_t pre_counter[2];
	uint64_t pre_sliced[2];
};

static inline uint64_t load_u64(const volatile uint64_t *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static inline void store_u64(volatile uint64_t *p, uint64_t v)
{
	__atomic_store_n(p, v, __ATOMIC_RELEASE);
}

static inline int32_t load_s32(const volatile int32_t *p)
{
	return __atomic_load_n(p, __ATOMIC_ACQUIRE);
}

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int find_target_cpu_from(int start_cpu)
{
	char path[128];
	int cpu;

	for (cpu = start_cpu; cpu < 256; cpu++) {
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/preserve", cpu);
		if (access(path, R_OK) == 0) {
			snprintf(path, sizeof(path),
				 "/sys/devices/system/cpu/cpu%d/online", cpu);
			if (access(path, R_OK) == 0)
				return cpu;
		}
	}
	return -1;
}

static int find_target_cpu(void)
{
	return find_target_cpu_from(1);
}

#define ASSERT_GE(a, b)								\
	do {									\
		uint64_t _a = (uint64_t)(a);					\
		uint64_t _b = (uint64_t)(b);					\
		if (_a < _b)							\
			fail_exit("ASSERT_GE(%s, %s) failed: %llu < %llu",	\
				  #a, #b,					\
				  (unsigned long long)_a,			\
				  (unsigned long long)_b);			\
	} while (0)

static int read_cpu_online(int cpu)
{
	char path[128], buf[16];
	int fd, val = -1;

	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online",
		 cpu);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	if (read(fd, buf, sizeof(buf) - 1) > 0)
		val = atoi(buf);
	close(fd);
	return val;
}

static int preserve_cpu_fd(int session_fd, int cpu, uint64_t token)
{
	char path[128];
	int cpu_fd, ret;

	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/preserve",
		 cpu);
	cpu_fd = open(path, O_RDONLY);
	if (cpu_fd < 0)
		return -1;

	ret = luo_session_preserve_fd(session_fd, cpu_fd, token);
	close(cpu_fd);
	return ret;
}

static void read_job_buf(int job_fd, struct oncore_test_buf *out)
{
	ssize_t n;

	memset(out, 0, sizeof(*out));
	if (lseek(job_fd, 0, SEEK_SET) < 0)
		fail_exit("lseek oncore_test fd failed");
	n = read(job_fd, out, sizeof(*out));
	if (n != (ssize_t)sizeof(*out))
		fail_exit("read oncore_test fd failed (n=%zd)", n);
}

static void wait_for_pong(volatile struct oncore_test_buf *shm,
			  uint64_t expected, uint64_t timeout_ms)
{
	uint64_t deadline = monotonic_ns() + timeout_ms * 1000000ULL;

	while (load_u64(&shm->pong_val) != expected) {
		if (monotonic_ns() > deadline)
			fail_exit("Timed out waiting for pong_val=%#llx (got %#llx, counter=%llu)",
				  (unsigned long long)expected,
				  (unsigned long long)load_u64(&shm->pong_val),
				  (unsigned long long)load_u64(&shm->counter));
	}
}

static void save_stage_state(int luo_fd, const struct oncore_stage_state *st)
{
	int session_fd, mfd;

	session_fd = luo_create_session(luo_fd, STATE_SESSION_NAME);
	if (session_fd < 0)
		fail_exit("luo_create_session for state session");

	mfd = memfd_create("state_memfd", 0);
	if (mfd < 0)
		fail_exit("memfd_create for state");

	if (write(mfd, st, sizeof(*st)) != (ssize_t)sizeof(*st))
		fail_exit("write state to memfd");

	if (luo_session_preserve_fd(session_fd, mfd, STATE_MEMFD_TOKEN) < 0)
		fail_exit("preserve state memfd");

	close(mfd);
}

static void load_stage_state(int state_session_fd, struct oncore_stage_state *st)
{
	int mfd;

	mfd = luo_session_retrieve_fd(state_session_fd, STATE_MEMFD_TOKEN);
	if (mfd < 0)
		fail_exit("retrieve state memfd");

	if (lseek(mfd, 0, SEEK_SET) < 0 ||
	    read(mfd, st, sizeof(*st)) != (ssize_t)sizeof(*st))
		fail_exit("read state memfd");

	close(mfd);
}

static void test_negative_no_cpu(int luo_fd)
{
	struct liveupdate_session_preserve_fd pfd = {};
	int session_fd, job_fd, ret;

	ksft_print_msg("[STAGE 1] Subtest 1: Negative test (job without preserved CPU)\n");

	session_fd = luo_create_session(luo_fd, "oncore-neg-session");
	if (session_fd < 0)
		fail_exit("luo_create_session for negative test");

	job_fd = open(ONCORE_TEST_DEBUGFS_PATH, O_RDWR);
	if (job_fd < 0)
		fail_exit("open %s", ONCORE_TEST_DEBUGFS_PATH);

	pfd.size = sizeof(pfd);
	pfd.fd = job_fd;
	pfd.token = TEST_JOB_TOKEN_BASE;
	ret = ioctl(session_fd, LIVEUPDATE_SESSION_PRESERVE_FD, &pfd);
	if (ret == 0 || errno != ENOENT)
		fail_exit("Expected -ENOENT when preserving job without preserved CPU (ret=%d, errno=%d)",
			  ret, errno);

	close(job_fd);
	close(session_fd);
	ksft_print_msg("[STAGE 1] Subtest 1 passed (-ENOENT as expected)\n");
}

static void test_tickless_cancel_loop(int luo_fd, int target_cpu)
{
	long page_size = getpagesize();
	int iter;

	ksft_print_msg("[STAGE 1] Subtest 2: 1:1 tickless mode + mmap ping-pong + cancel loop\n");

	for (iter = 0; iter < 3; iter++) {
		volatile struct oncore_test_buf *shm;
		struct oncore_test_buf snap1, snap2;
		uint64_t c1, c2, deadline;
		int session_fd, job_fd, p;

		session_fd = luo_create_session(luo_fd, "oncore-cancel-1to1");
		if (session_fd < 0)
			fail_exit("luo_create_session (iter %d)", iter);

		if (preserve_cpu_fd(session_fd, target_cpu, TEST_CPU_TOKEN) < 0)
			fail_exit("preserve_cpu_fd (iter %d)", iter);

		if (read_cpu_online(target_cpu) != 0)
			fail_exit("CPU %d not offline after preserve (iter %d)",
				  target_cpu, iter);

		job_fd = open(ONCORE_TEST_DEBUGFS_PATH, O_RDWR);
		if (job_fd < 0)
			fail_exit("open %s (iter %d)", ONCORE_TEST_DEBUGFS_PATH, iter);

		if (luo_session_preserve_fd(session_fd, job_fd,
					    TEST_JOB_TOKEN_BASE) < 0)
			fail_exit("preserve job_fd (iter %d)", iter);

		shm = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			   job_fd, 0);
		if (shm == MAP_FAILED)
			fail_exit("mmap job_fd (iter %d)", iter);

		if (load_u64(&shm->magic) != ONCORE_TEST_MAGIC)
			fail_exit("Unexpected magic %#llx (iter %d)",
				  (unsigned long long)load_u64(&shm->magic), iter);

		deadline = monotonic_ns() + 2000000000ULL;
		while (load_u64(&shm->counter) == 0) {
			if (monotonic_ns() > deadline)
				fail_exit("Job counter did not start (iter %d)", iter);
		}

		c1 = load_u64(&shm->counter);
		usleep(20000);
		c2 = load_u64(&shm->counter);
		if (c2 <= c1)
			fail_exit("Counter did not advance in 1:1 mode (%llu -> %llu, iter %d)",
				  (unsigned long long)c1, (unsigned long long)c2, iter);

		if (load_s32(&shm->last_cpu) != target_cpu)
			fail_exit("Expected last_cpu=%d, got %d (iter %d)",
				  target_cpu, load_s32(&shm->last_cpu), iter);

		if (load_u64(&shm->tickless_quanta) < 1 ||
		    load_u64(&shm->sliced_quanta) != 0)
			fail_exit("Expected tickless>=1 and sliced==0, got tickless=%llu sliced=%llu (iter %d)",
				  (unsigned long long)load_u64(&shm->tickless_quanta),
				  (unsigned long long)load_u64(&shm->sliced_quanta),
				  iter);

		for (p = 0; p < 1000; p++) {
			uint64_t val = 0x100000ULL + (uint64_t)iter * 1000ULL + p + 1;

			store_u64(&shm->ping_val, val);
			wait_for_pong(shm, val, 1000);
		}

		munmap((void *)shm, page_size);
		close(session_fd);

		if (read_cpu_online(target_cpu) != 1)
			fail_exit("CPU %d not back online after session cancel (iter %d)",
				  target_cpu, iter);

		read_job_buf(job_fd, &snap1);
		usleep(10000);
		read_job_buf(job_fd, &snap2);
		ASSERT_GE(snap1.counter, c2);
		if (snap1.counter != snap2.counter || snap1.counter < c2)
			fail_exit("Job counter unstable after cancel (%llu vs %llu, c2=%llu)",
				  (unsigned long long)snap1.counter,
				  (unsigned long long)snap2.counter,
				  (unsigned long long)c2);

		close(job_fd);
	}

	ksft_print_msg("[STAGE 1] Subtest 2 passed (3 cancel iterations, 3000 zero-syscall ping-pongs)\n");
}

static void test_oversubscription_cancel(int luo_fd, int target_cpu)
{
	volatile struct oncore_test_buf *shm[3];
	long page_size = getpagesize();
	uint64_t c1[3], c2[3], deadline;
	int session_fd, job_fd[3];
	int i, round;

	ksft_print_msg("[STAGE 1] Subtest 3: Oversubscription (M=3 jobs on N=1 CPU) + mmap ping-pong\n");

	session_fd = luo_create_session(luo_fd, "oncore-cancel-oversub");
	if (session_fd < 0)
		fail_exit("luo_create_session for oversubscription test");

	if (preserve_cpu_fd(session_fd, target_cpu, TEST_CPU_TOKEN) < 0)
		fail_exit("preserve_cpu_fd for oversubscription test");

	for (i = 0; i < 3; i++) {
		job_fd[i] = open(ONCORE_TEST_DEBUGFS_PATH, O_RDWR);
		if (job_fd[i] < 0)
			fail_exit("open %s for job %d", ONCORE_TEST_DEBUGFS_PATH, i);

		if (luo_session_preserve_fd(session_fd, job_fd[i],
					    TEST_JOB_TOKEN_BASE + i) < 0)
			fail_exit("preserve job %d", i);

		shm[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, job_fd[i], 0);
		if (shm[i] == MAP_FAILED)
			fail_exit("mmap job %d", i);
	}

	deadline = monotonic_ns() + 3000000000ULL;
	for (i = 0; i < 3; i++) {
		while (load_u64(&shm[i]->sliced_quanta) < 2) {
			if (monotonic_ns() > deadline)
				fail_exit("Job %d did not reach sliced_quanta>=2 (got %llu)",
					  i, (unsigned long long)load_u64(&shm[i]->sliced_quanta));
			usleep(2000);
		}
	}

	for (i = 0; i < 3; i++)
		c1[i] = load_u64(&shm[i]->counter);
	usleep(60000);
	for (i = 0; i < 3; i++) {
		c2[i] = load_u64(&shm[i]->counter);
		if (c2[i] <= c1[i])
			fail_exit("Oversubscribed job %d did not advance (%llu -> %llu)",
				  i, (unsigned long long)c1[i], (unsigned long long)c2[i]);
		if (load_s32(&shm[i]->last_cpu) != target_cpu)
			fail_exit("Oversubscribed job %d ran on CPU %d (expected %d)",
				  i, load_s32(&shm[i]->last_cpu), target_cpu);
	}

	for (round = 1; round <= 10; round++) {
		for (i = 0; i < 3; i++) {
			uint64_t val = 0x300000ULL + (uint64_t)round * 16ULL + i;

			store_u64(&shm[i]->ping_val, val);
			wait_for_pong(shm[i], val, 2000);
		}
	}

	for (i = 0; i < 3; i++)
		munmap((void *)shm[i], page_size);

	close(session_fd);

	if (read_cpu_online(target_cpu) != 1)
		fail_exit("CPU %d not online after oversubscription cancel", target_cpu);

	for (i = 0; i < 3; i++)
		close(job_fd[i]);

	ksft_print_msg("[STAGE 1] Subtest 3 passed (all 3 jobs time-sliced on CPU %d)\n",
		       target_cpu);
}

static void test_multi_cpu_oversubscription(int luo_fd, int cpu1, int cpu2)
{
	volatile struct oncore_test_buf *shm[3];
	long page_size = getpagesize();
	bool saw_cpu1 = false, saw_cpu2 = false;
	uint64_t deadline;
	int session_fd, job_fd[3];
	int i;

	ksft_print_msg("[STAGE 1] Subtest 3b: Multi-CPU oversubscription (M=3 jobs on N=2 CPUs %d,%d)\n",
		       cpu1, cpu2);

	session_fd = luo_create_session(luo_fd, "oncore-cancel-2cpu");
	if (session_fd < 0)
		fail_exit("luo_create_session for 2-CPU test");

	if (preserve_cpu_fd(session_fd, cpu1, TEST_CPU_TOKEN) < 0)
		fail_exit("preserve_cpu_fd for CPU %d", cpu1);
	if (preserve_cpu_fd(session_fd, cpu2, TEST_CPU_TOKEN + 1) < 0)
		fail_exit("preserve_cpu_fd for CPU %d", cpu2);

	for (i = 0; i < 3; i++) {
		job_fd[i] = open(ONCORE_TEST_DEBUGFS_PATH, O_RDWR);
		if (job_fd[i] < 0)
			fail_exit("open %s for 2-CPU job %d", ONCORE_TEST_DEBUGFS_PATH, i);

		if (luo_session_preserve_fd(session_fd, job_fd[i],
					    TEST_JOB_TOKEN_BASE + i) < 0)
			fail_exit("preserve 2-CPU job %d", i);

		shm[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, job_fd[i], 0);
		if (shm[i] == MAP_FAILED)
			fail_exit("mmap 2-CPU job %d", i);
	}

	deadline = monotonic_ns() + 3000000000ULL;
	while (!saw_cpu1 || !saw_cpu2) {
		bool all_active = true;

		for (i = 0; i < 3; i++) {
			int32_t c = load_s32(&shm[i]->last_cpu);

			if (c == cpu1)
				saw_cpu1 = true;
			if (c == cpu2)
				saw_cpu2 = true;
			if (load_u64(&shm[i]->counter) == 0)
				all_active = false;
		}
		if (all_active && saw_cpu1 && saw_cpu2)
			break;
		if (monotonic_ns() > deadline)
			fail_exit("2-CPU test timed out (saw_cpu1=%d saw_cpu2=%d)",
				  saw_cpu1, saw_cpu2);
		usleep(2000);
	}

	for (i = 0; i < 3; i++)
		munmap((void *)shm[i], page_size);

	close(session_fd);

	if (read_cpu_online(cpu1) != 1 || read_cpu_online(cpu2) != 1)
		fail_exit("CPUs %d,%d not online after 2-CPU cancel", cpu1, cpu2);

	for (i = 0; i < 3; i++)
		close(job_fd[i]);

	ksft_print_msg("[STAGE 1] Subtest 3b passed (M=3 jobs scheduled across CPUs %d and %d)\n",
		       cpu1, cpu2);
}

static void run_stage_1(int luo_fd)
{
	struct oncore_stage_state st = {};
	struct oncore_test_buf snap[2];
	uint64_t deadline;
	int target_cpu, second_cpu, session_fd, job_fd[2], i;

	if (access(ONCORE_TEST_DEBUGFS_PATH, R_OK | W_OK) != 0)
		ksft_exit_skip("%s is not available (enable CONFIG_LIVEUPDATE_ONCORE_TEST)\n",
			       ONCORE_TEST_DEBUGFS_PATH);

	target_cpu = find_target_cpu();
	if (target_cpu < 0)
		ksft_exit_skip("No hotpluggable CPU with preserve attribute found\n");

	second_cpu = find_target_cpu_from(target_cpu + 1);

	ksft_print_msg("[STAGE 1] Target CPU for On-Core tests: %d (second_cpu=%d)\n",
		       target_cpu, second_cpu);

	test_negative_no_cpu(luo_fd);
	test_tickless_cancel_loop(luo_fd, target_cpu);
	test_oversubscription_cancel(luo_fd, target_cpu);
	if (second_cpu >= 0)
		test_multi_cpu_oversubscription(luo_fd, target_cpu, second_cpu);

	ksft_print_msg("[STAGE 1] Subtest 4: Preserving 2 On-Core jobs on CPU %d across kexec\n",
		       target_cpu);

	session_fd = luo_create_session(luo_fd, TEST_SESSION_NAME);
	if (session_fd < 0)
		fail_exit("luo_create_session for '%s'", TEST_SESSION_NAME);

	if (preserve_cpu_fd(session_fd, target_cpu, TEST_CPU_TOKEN) < 0)
		fail_exit("preserve_cpu_fd for CPU %d", target_cpu);

	for (i = 0; i < 2; i++) {
		job_fd[i] = open(ONCORE_TEST_DEBUGFS_PATH, O_RDWR);
		if (job_fd[i] < 0)
			fail_exit("open %s for kexec job %d",
				  ONCORE_TEST_DEBUGFS_PATH, i);

		if (luo_session_preserve_fd(session_fd, job_fd[i],
					    TEST_JOB_TOKEN_BASE + i) < 0)
			fail_exit("preserve kexec job %d", i);
	}

	deadline = monotonic_ns() + 3000000000ULL;
	for (i = 0; i < 2; i++) {
		do {
			read_job_buf(job_fd[i], &snap[i]);
			if (snap[i].counter > 0 && snap[i].sliced_quanta >= 1)
				break;
			if (monotonic_ns() > deadline)
				fail_exit("Kexec job %d did not start slicing (counter=%llu, sliced=%llu)",
					  i,
					  (unsigned long long)snap[i].counter,
					  (unsigned long long)snap[i].sliced_quanta);
			usleep(2000);
		} while (1);
	}

	st.target_cpu = target_cpu;
	for (i = 0; i < 2; i++) {
		read_job_buf(job_fd[i], &snap[i]);
		st.pre_counter[i] = snap[i].counter;
		st.pre_sliced[i] = snap[i].sliced_quanta;
		ksft_print_msg("[STAGE 1] Job %d pre-kexec: counter=%llu sliced_quanta=%llu cpu=%d\n",
			       i,
			       (unsigned long long)st.pre_counter[i],
			       (unsigned long long)st.pre_sliced[i],
			       snap[i].last_cpu);
		close(job_fd[i]);
	}

	save_stage_state(luo_fd, &st);

	close(luo_fd);
	daemonize_and_wait();
}

static void run_stage_2(int luo_fd, int state_session_fd)
{
	long page_size = getpagesize();
	volatile struct oncore_test_buf *shm[2];
	struct oncore_test_buf s2_a[2], s2_b[2], s2_c[2], s2_d[2];
	struct oncore_stage_state st = {};
	int session_fd, job_fd[2], cpu_fd, i, round;

	load_stage_state(state_session_fd, &st);
	ksft_print_msg("[STAGE 2] Restored state: target_cpu=%d pre_counter=[%llu, %llu]\n",
		       st.target_cpu,
		       (unsigned long long)st.pre_counter[0],
		       (unsigned long long)st.pre_counter[1]);

	session_fd = luo_retrieve_session(luo_fd, TEST_SESSION_NAME);
	if (session_fd < 0)
		fail_exit("luo_retrieve_session for '%s'", TEST_SESSION_NAME);

	/*
	 * Retrieve job fds BEFORE retrieving cpu_fd so the preserved physical
	 * CPU is still actively executing the pre-kexec On-Core jobs.
	 */
	for (i = 0; i < 2; i++) {
		job_fd[i] = luo_session_retrieve_fd(session_fd,
						    TEST_JOB_TOKEN_BASE + i);
		if (job_fd[i] < 0)
			fail_exit("retrieve job_fd %d", i);
		read_job_buf(job_fd[i], &s2_a[i]);
	}

	usleep(40000);

	for (i = 0; i < 2; i++) {
		read_job_buf(job_fd[i], &s2_b[i]);
		ksft_print_msg("[STAGE 2] Job %d post-kexec live: counter=%llu -> %llu (pre=%llu), sliced=%llu\n",
			       i,
			       (unsigned long long)s2_a[i].counter,
			       (unsigned long long)s2_b[i].counter,
			       (unsigned long long)st.pre_counter[i],
			       (unsigned long long)s2_b[i].sliced_quanta);

		if (s2_a[i].magic != ONCORE_TEST_MAGIC)
			fail_exit("Job %d corrupted magic %#llx",
				  i, (unsigned long long)s2_a[i].magic);
		if (s2_a[i].last_cpu != st.target_cpu)
			fail_exit("Job %d last_cpu=%d != target_cpu=%d",
				  i, s2_a[i].last_cpu, st.target_cpu);
		if (s2_a[i].counter <= st.pre_counter[i])
			fail_exit("Job %d counter did not advance across kexec (%llu <= %llu)",
				  i,
				  (unsigned long long)s2_a[i].counter,
				  (unsigned long long)st.pre_counter[i]);
		if (s2_b[i].counter <= s2_a[i].counter)
			fail_exit("Job %d counter did not advance live in Stage 2 (%llu <= %llu)",
				  i,
				  (unsigned long long)s2_b[i].counter,
				  (unsigned long long)s2_a[i].counter);
	}

	/*
	 * Map the KHO-preserved shared buffers in Stage 2 and perform live
	 * zero-syscall shared-memory ping-pong with the pre-kexec jobs.
	 */
	for (i = 0; i < 2; i++) {
		shm[i] = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, job_fd[i], 0);
		if (shm[i] == MAP_FAILED)
			fail_exit("Stage 2 mmap job %d", i);
	}

	for (round = 1; round <= 25; round++) {
		for (i = 0; i < 2; i++) {
			uint64_t val = 0x500000ULL + (uint64_t)round * 16ULL + i;

			store_u64(&shm[i]->ping_val, val);
			wait_for_pong(shm[i], val, 2000);
		}
	}

	for (i = 0; i < 2; i++)
		munmap((void *)shm[i], page_size);

	ksft_print_msg("[STAGE 2] Live post-kexec shared-memory ping-pong succeeded across both jobs\n");

	/* Now retrieve the preserved CPU fd, which detaches the On-Core workload. */
	cpu_fd = luo_session_retrieve_fd(session_fd, TEST_CPU_TOKEN);
	if (cpu_fd < 0)
		fail_exit("retrieve cpu_fd");
	close(cpu_fd);

	usleep(10000);
	for (i = 0; i < 2; i++)
		read_job_buf(job_fd[i], &s2_c[i]);
	usleep(20000);
	for (i = 0; i < 2; i++) {
		read_job_buf(job_fd[i], &s2_d[i]);
		if (s2_c[i].counter != s2_d[i].counter)
			fail_exit("Job %d continued advancing after CPU retrieve (%llu -> %llu)",
				  i,
				  (unsigned long long)s2_c[i].counter,
				  (unsigned long long)s2_d[i].counter);
		close(job_fd[i]);
	}

	if (luo_session_finish(session_fd) < 0)
		fail_exit("luo_session_finish for test session");
	close(session_fd);

	if (read_cpu_online(st.target_cpu) != 1)
		fail_exit("CPU %d was expected to be online after luo_session_finish",
			  st.target_cpu);

	if (luo_session_finish(state_session_fd) < 0)
		fail_exit("luo_session_finish for state session");
	close(state_session_fd);
	close(luo_fd);

	ksft_print_msg("\n--- ONCORE SCHEDULER KEXEC TEST PASSED ---\n");
}

int main(int argc, char *argv[])
{
	return luo_test(argc, argv, STATE_SESSION_NAME,
			run_stage_1, run_stage_2);
}
