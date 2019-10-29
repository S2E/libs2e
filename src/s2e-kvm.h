///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_H

#define S2E_KVM_H

#if defined(TARGET_I386) || defined(TARGET_X86_64)
#include <cpu/i386/cpuid.h>
#endif
#include <cpu/kvm.h>
#include <inttypes.h>

#include "FileDescriptorManager.h"
#include "syscalls.h"

namespace s2e {
namespace kvm {

struct stats_t {
    uint64_t mmio_reads;
    uint64_t mmio_writes;
    uint64_t io_reads;
    uint64_t io_writes;

    uint64_t kvm_runs;
    uint64_t cpu_exit;
};

extern struct stats_t g_stats;

class VM;

class S2EKVM : public IFile {
private:
    static const char *s_cpuModel;
    static const bool s_is64;

#if defined(TARGET_I386) || defined(TARGET_X86_64)
    cpuid_t m_cpuid;
#endif
    pthread_t m_timerThread;
    bool m_exiting = false;
    volatile bool m_timerExited = false;

    std::shared_ptr<VM> m_vm;

    static void *timerCb(void *param);
    void init(void);
    void initLogLevel(void);

    S2EKVM() = default;

    static void cleanup();

    void sendCpuExitSignal();

    int getApiVersion(void);
    int createVM();

#if defined(TARGET_I386) || defined(TARGET_X86_64)
    int getMSRIndexList(kvm_msr_list *list);
    int getSupportedCPUID(kvm_cpuid2 *cpuid);
#endif

public:
    virtual ~S2EKVM() {
    }

    static IFilePtr create();
    static int getVCPUMemoryMapSize(void);

    virtual int sys_ioctl(int fd, int request, uint64_t arg1);

    int checkExtension(int capability);
    int initTimerThread(void);

    bool exiting() const {
        return m_exiting;
    }

    void setExiting() {
        m_exiting = true;
    }

#if defined(TARGET_I386) || defined(TARGET_X86_64)
    const cpuid_t &getCpuid() const {
        return m_cpuid;
    }
#endif
};
}
}

#endif
