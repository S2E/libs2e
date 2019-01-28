///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <cpu/kvm.h>

#include <cpu/cpus.h>
#include <cpu/exec.h>
#include <cpu/memory.h>
#include <libcpu-log.h>
#include <timer.h>

#include "coroutine.h"

#ifdef CONFIG_SYMBEX
#include <s2e/monitor.h>
#include <s2e/s2e_block.h>
#include <s2e/s2e_libcpu.h>
#endif

#include <cpu/cpu-common.h>
#include <cpu/i386/cpu.h>
#include <cpu/ioport.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#endif

// #define SE_KVM_DEBUG_IRQ
// #define SE_KVM_DEBUG_DEV_STATE

#include "s2e-kvm-interface.h"

// XXX: make this clean
int s2e_dev_save(const void *buffer, size_t size);
int s2e_dev_restore(void *buffer, int pos, size_t size);

#define false 0

bool g_cpu_thread_id_inited = false;
pthread_t g_cpu_thread_id;

// TODO: move to a better place
volatile bool s_s2e_exiting = false;

#ifdef CONFIG_SYMBEX
#include <s2e/s2e_config.h>
#include <tcg/tcg-llvm.h>

const char *g_s2e_shared_dir = NULL;
int g_execute_always_klee = 0;
int g_s2e_max_processes = 1;

#endif

/**** /dev/kvm ioctl handlers *******/

/**** vm ioctl handlers *******/

/**** vcpu ioctl handlers *******/
