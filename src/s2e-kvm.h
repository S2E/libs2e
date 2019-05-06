///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_H

#define S2E_KVM_H

#include <cpu/i386/cpuid.h>
#include <cpu/kvm.h>
#include <inttypes.h>

#include "FDManager.h"
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
    pthread_t m_timerThread;
    bool m_exiting = false;
    bool m_timerExited = false;
    cpuid_t m_cpuid;

    std::shared_ptr<VM> m_vm;

    static void *TimerCb(void *param);
    void Init(void);
    void InitLogLevel(void);
    S2EKVM() {
    }

    static void Cleanup();

    void SendCpuExitSignal();

public:
    virtual ~S2EKVM() {
    }

    static const char *s_cpuModel;

    static IFilePtr Create();

    int GetApiVersion(void);
    int CheckExtension(int capability);
    int CreateVM();
    static int GetVCPUMemoryMapSize(void);
    int GetMSRIndexList(kvm_msr_list *list);
    int GetSupportedCPUID(kvm_cpuid2 *cpuid);
    int InitTimerThread(void);

    virtual int ioctl(int fd, int request, uint64_t arg1);

    bool Exiting() const {
        return m_exiting;
    }

    void SetExiting() {
        m_exiting = true;
    }

    const cpuid_t &GetCpuid() const {
        return m_cpuid;
    }
};
} // namespace kvm
} // namespace s2e

#endif
