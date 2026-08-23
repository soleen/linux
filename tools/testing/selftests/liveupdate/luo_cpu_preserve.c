// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (c) 2026, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * A selftest to validate the lifecycle of preserved CPUs across Live Update
 * and within a local session.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <libliveupdate.h>

#define TEST_SESSION_NAME "cpu-preserve-session"
#define STATE_SESSION_NAME "cpu_preserve_state"
#define STATE_MEMFD_TOKEN 999
#define TEST_CPU_TOKEN 0x100

static int find_target_cpu(void)
{
	char path[128];
	int cpu;

	for (cpu = 1; cpu < 256; cpu++) {
		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/preserve", cpu);
		if (access(path, R_OK) == 0) {
			snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/online", cpu);
			if (access(path, R_OK) == 0)
				return cpu;
		}
	}
	return -1;
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

static int preserve_cpu_fd(int session_fd, int cpu, int token)
{
	struct liveupdate_session_preserve_fd pfd = {};
	char path[128];
	int cpu_fd, ret;

	snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/preserve", cpu);
	cpu_fd = open(path, O_RDONLY);
	if (cpu_fd < 0)
		return -1;

	pfd.size = sizeof(pfd);
	pfd.fd = cpu_fd;
	pfd.token = token;

	ret = ioctl(session_fd, LIVEUPDATE_SESSION_PRESERVE_FD, &pfd);
	close(cpu_fd);
	return ret;
}

/* Stage 1: Executed before kexec */
static void run_stage_1(int luo_fd)
{
	int target_cpu, session_fd;

	target_cpu = find_target_cpu();
	if (target_cpu < 0)
		fail_exit("No hotpluggable CPU with preserve attribute found");

	ksft_print_msg("[STAGE 1] Target CPU for preservation: %d\n", target_cpu);

	create_state_file(luo_fd, STATE_SESSION_NAME, STATE_MEMFD_TOKEN, target_cpu);

	session_fd = luo_create_session(luo_fd, TEST_SESSION_NAME);
	if (session_fd < 0)
		fail_exit("luo_create_session for '%s'", TEST_SESSION_NAME);

	if (preserve_cpu_fd(session_fd, target_cpu, TEST_CPU_TOKEN) < 0)
		fail_exit("preserve_cpu_fd for cpu %d", target_cpu);

	if (read_cpu_online(target_cpu) != 0)
		fail_exit("CPU %d was expected to be offline after preservation", target_cpu);

	ksft_print_msg("[STAGE 1] CPU %d successfully preserved and offlined\n", target_cpu);

	close(luo_fd);
	daemonize_and_wait();
}

/* Stage 2: Executed after kexec */
static void run_stage_2(int luo_fd, int state_session_fd)
{
	struct liveupdate_session_retrieve_fd rfd = {};
	int target_cpu, session_fd;

	restore_and_read_stage(state_session_fd, STATE_MEMFD_TOKEN, &target_cpu);
	ksft_print_msg("[STAGE 2] Restored target CPU: %d\n", target_cpu);

	session_fd = luo_retrieve_session(luo_fd, TEST_SESSION_NAME);
	if (session_fd < 0)
		fail_exit("luo_retrieve_session for '%s'", TEST_SESSION_NAME);

	rfd.size = sizeof(rfd);
	rfd.token = TEST_CPU_TOKEN;
	if (ioctl(session_fd, LIVEUPDATE_SESSION_RETRIEVE_FD, &rfd) < 0)
		fail_exit("LIVEUPDATE_SESSION_RETRIEVE_FD for cpu token %#x", TEST_CPU_TOKEN);

	close(rfd.fd);

	if (read_cpu_online(target_cpu) != 1)
		fail_exit("CPU %d was expected to be online after retrieval", target_cpu);

	ksft_print_msg("[STAGE 2] CPU %d successfully retrieved and online\n", target_cpu);

	if (luo_session_finish(session_fd) < 0)
		fail_exit("luo_session_finish for test session");
	close(session_fd);

	if (luo_session_finish(state_session_fd) < 0)
		fail_exit("luo_session_finish for state session");
	close(state_session_fd);

	ksft_print_msg("\n--- CPU PRESERVATION KEXEC TEST PASSED ---\n");
}

int main(int argc, char *argv[])
{
	return luo_test(argc, argv, STATE_SESSION_NAME,
			run_stage_1, run_stage_2);
}
