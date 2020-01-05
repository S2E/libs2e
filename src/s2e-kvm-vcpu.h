///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_VCPU_H

#define S2E_KVM_VCPU_H

#include <cpu/kvm.h>
#include <inttypes.h>

#include <coroutine.h>
#if defined(TARGET_I386) || defined(TARGET_X86_64)
#include <cpu/i386/cpu.h>
#elif defined(TARGET_ARM)
#include <cpu/arm/cpu.h>
#else
#error Unsupported target architecture
#endif
#include <fsigc++/fsigc++.h>

#include "s2e-kvm-vm.h"
#include "s2e-kvm.h"

#include "FileDescriptorManager.h"
#include "syscalls.h"

namespace s2e {
namespace kvm {

// TODO: remove this global var
extern kvm_run *g_kvm_vcpu_buffer;

class VCPU : public IFile {
private:
    std::shared_ptr<S2EKVM> m_kvm;
    std::shared_ptr<VM> m_vm;

    int m_fd = -1;
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    CPUX86State *m_env = nullptr;
#elif defined(TARGET_ARM)
    CPUARMState *m_env = nullptr;
#else
#error Unsupported target architecture
#endif

    unsigned m_sigmask_size = 0;

    union s2e_kvm_sigmask_t {
        sigset_t sigset;
        uint8_t bytes[32];
    } m_sigmask = {};

    pthread_mutex_t m_cpuLock;
    pthread_t m_cpuThread;
    bool m_cpuThreadInited = false;

    kvm_run *m_cpuBuffer = nullptr;
    Coroutine *m_coroutine = nullptr;

    // Indicates that the cpu loop returned with a coroutine switch.
    // This happens when an instruction had to suspend its execution
    // to let the kvm client handle the operation (e.g., mmio, snapshot, etc.).
    bool m_handlingKvmCallback = false;

    // Indicates that the cpu loop is handling a device state snaphsot load/save.
    // This implies that g_handling_kvm_cb is 1.
    bool m_handlingDeviceState = false;

    bool m_cpuStateIsPrecise = true;

    // XXX: do we need this? Looks unused
    bool m_signalPending = false;

    volatile bool m_inKvmRun = false;

    fsigc::connection m_onExit;
    fsigc::connection m_onSelect;

    static void cpuExitSignal(int signum);
    void initializeCpuExitSignal();
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    static void setCpuSegment(SegmentCache *libcpu_seg, const kvm_segment *kvm_seg);
    static void getCpuSegment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg);
    static void get8086Segment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg);
    int setCPUID2(kvm_cpuid2 *cpuid);
#endif

    static void coroutineFcn(void *opaque);

    int initCpuLock(void);

    VCPU(std::shared_ptr<S2EKVM> &kvm, std::shared_ptr<VM> &vm, kvm_run *buffer);

    int getClock(kvm_clock_data *clock);

    // Defines which signals are blocked during execution of kvm.
    int setSignalMask(kvm_signal_mask *mask);

    ///
    /// \brief s2e_kvm_vcpu_set_regs set the general purpose registers of the CPU
    ///
    /// libcpu does not track register the program counter and eflags state precisely,
    /// in order to speed up execution. More precisely, it will not update these registers
    /// after each instruction is executed. This has important implications for KVM clients.
    /// When guest code executes an instruction that causes a VM exit (e.g., memory access
    /// to a device), the following happens:
    ///
    /// 1. libcpu suspends the current translation block and calls the I/O handler in libs2e
    /// 2. Functions in s2e-kvm-io.c trigger a coroutine switch to s2e_kvm_vcpu_run,
    ///    which returns to the KVM client
    /// 3. The KVM client handles the I/O emulation
    /// 4. The KVM client re-enters s2e_kvm_vcpu_run, which switches back to the coroutine
    ///    interrupted in step 2.
    /// 5. Execution of the translation block resumes
    ///
    /// During step 3, I/O emulation may want to access the guest cpu register state using
    /// the corresponding KVM APIs. In vanilla KVM, these APIs expect the CPU state to be
    /// fully consistent. However, this consistency is broken in libs2e because of how CPU
    /// emulation works (see explanation above). Luckily, this situation does not usually
    /// happen in practice, as the KVM client reads the CPU state when it is in sync.
    /// This function nevertheless checks for this and prints a warning.
    ///
    /// Same remarks apply for register setters, which may corrupt CPU state if called
    /// at a time where the CPU state is not properly committed.
    ///
    /// In principle, fixing this issue would require calling cpu_restore_state at every
    /// exit point.
    ///
#if defined(TARGET_I386) || defined(TARGET_X86_64)
    int setRegisters(kvm_regs *regs);

    int setFPU(kvm_fpu *fpu);
    int setSystemRegisters(kvm_sregs *sregs);
    int setMSRs(kvm_msrs *msrs);
    int setMPState(kvm_mp_state *mp);

    int getRegisters(kvm_regs *regs);
    int getFPU(kvm_fpu *fpu);
    int getSystemRegisters(kvm_sregs *sregs);
    int getMSRs(kvm_msrs *msrs);
    int getMPState(kvm_mp_state *mp);

    int interrupt(kvm_interrupt *interrupt);
    int nmi();
#elif defined(TARGET_ARM)
    int setRegs(kvm_m_regs *regs);
    int setSRegs(kvm_m_sregs *sregs);
    int setOneReg(kvm_one_reg *reg);
    int setMPState(kvm_mp_state *mp);

    int getRegs(kvm_m_regs *regs);
    int getSRegs(kvm_m_sregs *sregs);
    int getOneReg(kvm_one_reg *reg);
    int getMPState(kvm_mp_state *mp);

    inline long copy_from_user(void *to, const void *from, unsigned long n);
    inline long copy_to_user(void *to, const void *from, unsigned long n);
    uint64 core_reg_offset_from_id(uint64 id);
    int set_core_reg(kvm_one_reg *reg);
    int get_core_reg(kvm_one_reg *reg);
    int reg_from_user(void *val, const void *uaddr, uint64 id);
    int reg_to_user(void *uaddr, const void *val, uint64 id);
    int vfp_set_reg(uint64 id, const void *uaddr);
    int vfp_get_reg(uint64 id, void *uaddr);
    int init(kvm_vcpu_init *init);
#else
#error Unsupported target architecture
#endif

    int run(int vcpu_fd);

    void requestProcessExit(int code);

    virtual int sys_ioctl(int fd, int request, uint64_t arg1);
    virtual void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset);

public:
    virtual ~VCPU();

    static std::shared_ptr<VCPU> create(std::shared_ptr<S2EKVM> &kvm, std::shared_ptr<VM> &vm);

    void lock();
    void tryLock();
    void unlock();

    void sendExitSignal();
    void requestExit(void);

    void flushDisk(void);
    void saveDeviceState(void);
    void restoreDeviceState(void);
    void syncSRegs(void);
    void cloneProcess(void);

#if defined(TARGET_ARM)
    int setIrqLine(kvm_irq_level *irq_level);
#endif

    inline bool inKvmRun() const {
        return m_inKvmRun;
    }

    void flushTlb();
};
}
}

#endif
