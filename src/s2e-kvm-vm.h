///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_KVM_VM_H

#define S2E_KVM_VM_H

#include <cpu/kvm.h>
#include <inttypes.h>

#include "FDManager.h"
#include "s2e-kvm.h"

namespace s2e {
namespace kvm {

class VCPU;

class VM : public IFile {
private:
    std::shared_ptr<S2EKVM> m_kvm;
    std::shared_ptr<VCPU> m_cpu;

    VM(std::shared_ptr<S2EKVM> &kvm) : m_kvm(kvm) {
    }

public:
    static std::shared_ptr<VM> Create(std::shared_ptr<S2EKVM> &kvm);

    void SendCpuExitSignal();

    int EnableCapability(kvm_enable_cap *cap);

    int CreateVirtualCPU();

    int SetTSSAddress(uint64_t tss_addr);

    int SetUserMemoryRegion(kvm_userspace_memory_region *region);

    ///
    /// \brief s2e_kvm_vm_mem_rw intercepts all dma read/writes from the kvm client.
    ///
    /// This is important in order to keep the cpu code cache consistent as well
    /// as to keep track of dirty page.
    ///
    /// In multi-path mode, this ensures that dma reads/writes go to the right state
    /// in addition to keeping track of dirty pages.
    ///
    /// \param vm_fd the vm descriptor
    /// \param mem the memory descriptor
    /// \return
    ///
    int MemoryReadWrite(kvm_mem_rw *mem);

    int RegisterFixedRegion(kvm_fixed_region *region);

    ///
    /// \brief GetDirtyLog returns a bitmap of dirty pages
    /// for the given memory buffer.
    ///
    /// This is usually used for graphics memory by kvm clients.
    ///
    /// \param vm_fd the virtual machine fd
    /// \param log the bitmap structure
    /// \return
    ///
    int GetDirtyLog(kvm_dirty_log *log);

    int SetIdentityMapAddress(uint64_t addr);

    int SetClock(kvm_clock_data *clock);
    int GetClock(kvm_clock_data *clock);

    int IOEventFD(kvm_ioeventfd *event);

    int DiskReadWrite(kvm_disk_rw *d);
    int DeviceSnapshot(kvm_dev_snapshot *s);
    int SetClockScalePointer(unsigned *scale);

    virtual int ioctl(int fd, int request, uint64_t arg1);
};
}
}

#endif
