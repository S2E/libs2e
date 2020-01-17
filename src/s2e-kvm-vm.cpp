///
/// Copyright (C) 2015-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <memory.h>

#include <cpu/cpus.h>
#include <cpu/exec.h>
#include <cpu/memory.h>
#include <timer.h>

#include <cpu/cpu-common.h>

#if defined(TARGET_I386) || defined(TARGET_X86_64)
#include <cpu/i386/cpu.h>
#elif defined(TARGET_ARM)
#include <cpu/arm/cpu.h>
#else
#error Unsupported target architecture
#endif
#include <cpu/ioport.h>

#ifdef CONFIG_SYMBEX
#include <cpu/se_libcpu.h>
#include <s2e/cpu.h>
#include <s2e/monitor.h>
#include <s2e/s2e_block.h>
#include <s2e/s2e_config.h>
#include <s2e/s2e_libcpu.h>
#include <tcg/tcg-llvm.h>
#endif

#include "libs2e.h"

#include "s2e-kvm-vcpu.h"

#include "s2e-kvm-vm.h"
#include "s2e-kvm.h"

#ifdef CONFIG_SYMBEX
bool g_execute_always_klee = false;
#endif

namespace s2e {
namespace kvm {

std::shared_ptr<VM> VM::create(std::shared_ptr<S2EKVM> &kvm) {
    auto ret = std::shared_ptr<VM>(new VM(kvm));

    cpu_register_io(&g_io);
    tcg_exec_init(0);

    init_clocks();

#ifdef CONFIG_SYMBEX
    s2e_init_device_state();
    s2e_init_timers();

    s2e_initialize_execution(g_execute_always_klee);
    s2e_register_dirty_mask((uint64_t) get_ram_list_phys_dirty(), get_ram_list_phys_dirty_size() >> TARGET_PAGE_BITS);
    s2e_on_initialization_complete();
#endif

    return ret;
}

void VM::sendCpuExitSignal() {
    if (m_cpu) {
        m_cpu->sendExitSignal();
    }
}

int VM::enableCapability(kvm_enable_cap *cap) {
    printf("Enable capability not supported %d\n", cap->cap);
    errno = 1;
    return -1;
}

int VM::createVirtualCPU() {
    if (m_cpu) {
        return -1;
    }

    auto vm = std::dynamic_pointer_cast<VM>(g_fdm->get(this));
    assert(vm && vm.get() == this);

    // TODO: implement this
    auto vcpu = VCPU::create(m_kvm, vm);
    if (!vcpu) {
        return -1;
    }

    m_cpu = vcpu;

    return g_fdm->registerInterface(vcpu);
}

int VM::setTSSAddress(uint64_t tss_addr) {
#ifdef SE_KVM_DEBUG_INTERFACE
    printf("Setting tss addr %#" PRIx64 " not implemented yet\n", tss_addr);
#endif
    return 0;
}

int VM::setUserMemoryRegion(kvm_userspace_memory_region *region) {
    if (m_cpu) {
        m_cpu->requestExit();

        m_cpu->lock();

        assert(!m_cpu->inKvmRun());
        m_cpu->flushTlb();
        mem_desc_unregister(region->slot);
        mem_desc_register(region);

        m_cpu->unlock();
    } else {
        mem_desc_unregister(region->slot);
        mem_desc_register(region);
    }
    return 0;
}

int VM::memoryReadWrite(kvm_mem_rw *mem) {
#if !defined(CONFIG_SYMBEX_MP)
    if (!mem->is_write) {
        // Fast path for reads
        // TODO: also do it for writes
        memcpy((void *) mem->dest, (void *) mem->source, mem->length);
        return 0;
    }
#endif

    m_cpu->requestExit();
    m_cpu->lock();
    cpu_host_memory_rw(mem->source, mem->dest, mem->length, mem->is_write);
    m_cpu->unlock();
    return 0;
}

int VM::registerFixedRegion(kvm_fixed_region *region) {
#ifdef CONFIG_SYMBEX_MP
    s2e_register_ram2(region->name, region->host_address, region->size, region->flags & KVM_MEM_SHARED_CONCRETE);
#endif
    return 0;
}

#if defined(TARGET_ARM)
int VM::initMemRegions(kvm_mem_init *mem_init) {
    int ret;
    ret = s2e_init_mem(&mem_init->baseaddr, &mem_init->size, &mem_init->num, &mem_init->is_rom);
    if (ret < 0) {
        errno = 1;
    }
    return ret;
}
#endif

int VM::getDirtyLog(kvm_dirty_log *log) {
    m_cpu->requestExit();

    const MemoryDesc *r = mem_desc_get_slot(log->slot);

    if (m_kvm->exiting()) {
        // This may happen if we are called from an exit handler, e.g., if
        // plugin code called exit() from the cpu loop. We don't want
        // to deadlock in this case, so return conservatively all dirty.
        memset(log->dirty_bitmap, 0xff, (r->kvm.memory_size >> TARGET_PAGE_BITS) / 8);
        return 0;
    }

    m_cpu->tryLock();

    cpu_physical_memory_get_dirty_bitmap((uint8_t *) log->dirty_bitmap, r->ram_addr, r->kvm.memory_size,
                                         VGA_DIRTY_FLAG);

    cpu_physical_memory_reset_dirty(r->ram_addr, r->ram_addr + r->kvm.memory_size - 1, VGA_DIRTY_FLAG);

    m_cpu->unlock();
    return 0;
}

int VM::setIdentityMapAddress(uint64_t addr) {
    assert(false && "Not implemented");
}

int VM::setClock(kvm_clock_data *clock) {
    g_clock_start = clock->clock;
    g_clock_offset = cpu_get_real_ticks();
    return 0;
}

int VM::getClock(kvm_clock_data *clock) {
    clock->clock = cpu_get_real_ticks() - g_clock_offset + g_clock_start;
    clock->flags = 0;
    return 0;
}

int VM::ioEventFD(kvm_ioeventfd *event) {
#ifdef SE_KVM_DEBUG_INTERFACE
    printf("kvm_ioeventd datamatch=%#llx addr=%#llx len=%d fd=%d flags=%#" PRIx32 "\n", event->datamatch, event->addr,
           event->len, event->fd, event->flags);
#endif
    return -1;
}

int VM::diskReadWrite(kvm_disk_rw *d) {
#ifdef CONFIG_SYMBEX
    if (d->is_write) {
        d->count = s2e_bdrv_write(nullptr, d->sector, (uint8_t *) d->host_address, d->count);
    } else {
        d->count = s2e_bdrv_read(nullptr, d->sector, (uint8_t *) d->host_address, d->count);
    }
    return 0;
#else
    return -1;
#endif
}

int VM::deviceSnapshot(kvm_dev_snapshot *s) {
#ifdef CONFIG_SYMBEX_MP
    if (s->is_write) {
        return s2e_dev_save((void *) s->buffer, s->size);
    } else {
        return s2e_dev_restore((void *) s->buffer, s->pos, s->size);
    }
#else
    return -1;
#endif
}

int VM::setClockScalePointer(unsigned *scale) {
#ifdef CONFIG_SYMBEX
    if (!scale) {
        return -1;
    }

    g_sqi.exec.clock_scaling_factor = scale;
    return 0;
#else
    return -1;
#endif
}

int VM::sys_ioctl(int fd, int request, uint64_t arg1) {
    int ret = -1;

    switch ((uint32_t) request) {
        case KVM_CHECK_EXTENSION:
            ret = m_kvm->checkExtension(arg1);
            if (ret < 0) {
                errno = 1;
            }
            break;

        case KVM_SET_TSS_ADDR: {
            ret = setTSSAddress(arg1);
        } break;

        case KVM_CREATE_VCPU: {
            ret = createVirtualCPU();
        } break;

        case KVM_SET_USER_MEMORY_REGION: {
            ret = setUserMemoryRegion((kvm_userspace_memory_region *) arg1);
        } break;

        case KVM_SET_CLOCK: {
            ret = setClock((kvm_clock_data *) arg1);
        } break;

        case KVM_GET_CLOCK: {
            ret = getClock((kvm_clock_data *) arg1);
        } break;

        case KVM_ENABLE_CAP: {
            ret = enableCapability((kvm_enable_cap *) arg1);
        } break;

        case KVM_IOEVENTFD: {
            ret = ioEventFD((kvm_ioeventfd *) arg1);
        } break;

        case KVM_SET_IDENTITY_MAP_ADDR: {
            ret = setIdentityMapAddress(arg1);
        } break;

        case KVM_GET_DIRTY_LOG: {
            ret = getDirtyLog((kvm_dirty_log *) arg1);
        } break;

        case KVM_MEM_RW: {
            ret = memoryReadWrite((kvm_mem_rw *) arg1);
        } break;

        case KVM_FORCE_EXIT: {
            m_cpu->requestExit();
            ret = 0;
        } break;

        case KVM_MEM_REGISTER_FIXED_REGION: {
            ret = registerFixedRegion((kvm_fixed_region *) arg1);
        } break;

        case KVM_DISK_RW: {
            ret = diskReadWrite((kvm_disk_rw *) arg1);
        } break;

        case KVM_DEV_SNAPSHOT: {
            ret = deviceSnapshot((kvm_dev_snapshot *) arg1);
        } break;

        case KVM_SET_CLOCK_SCALE: {
            ret = setClockScalePointer((unsigned *) arg1);
        } break;
#if defined(TARGET_ARM)
        case KVM_IRQ_LINE: {
            m_cpu->setIrqLine((kvm_irq_level *) arg1);
            ret = 0;
        } break;

        case KVM_MEM_REGION_INIT: {
            ret = initMemRegions((kvm_mem_init *) arg1);
        } break;
#endif
        default: {
            fprintf(stderr, "libs2e: unknown KVM VM IOCTL %x\n", request);
            exit(-1);
        }
    }

    return ret;
}
}
}
