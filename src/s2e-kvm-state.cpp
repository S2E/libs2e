///
/// Copyright (C) 2015-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cpu/kvm.h>

#include <cpu/se_libcpu.h>
#include <timer.h>

#include "s2e-kvm-vcpu.h"

#define WR_cpu(cpu, reg, value) \
    g_sqi.regs.write_concrete(offsetof(CPUX86State, reg), (uint8_t *) &value, sizeof(target_ulong))
#define RR_cpu(cpu, reg, value) \
    g_sqi.regs.read_concrete(offsetof(CPUX86State, reg), (uint8_t *) &value, sizeof(target_ulong))

extern "C" {
// XXX: fix this declaration
void helper_wrmsr_v(target_ulong index, uint64_t val);
uint64_t helper_rdmsr_v(uint64_t index);
}

namespace s2e {
namespace kvm {

int VCPU::SetRegisters(kvm_regs *regs) {
    CPUX86State *env = m_env;

#ifdef CONFIG_SYMBEX
    WR_cpu(env, regs[R_EAX], regs->rax);
    WR_cpu(env, regs[R_EBX], regs->rbx);
    WR_cpu(env, regs[R_ECX], regs->rcx);
    WR_cpu(env, regs[R_EDX], regs->rdx);
    WR_cpu(env, regs[R_ESI], regs->rsi);
    WR_cpu(env, regs[R_EDI], regs->rdi);
    WR_cpu(env, regs[R_ESP], regs->rsp);
    WR_cpu(env, regs[R_EBP], regs->rbp);

#ifdef TARGET_X86_64
    WR_cpu(env, regs[8], regs->r8);
    WR_cpu(env, regs[9], regs->r9);
    WR_cpu(env, regs[10], regs->r10);
    WR_cpu(env, regs[11], regs->r11);
    WR_cpu(env, regs[12], regs->r12);
    WR_cpu(env, regs[13], regs->r13);
    WR_cpu(env, regs[14], regs->r14);
    WR_cpu(env, regs[15], regs->r15);
#endif
#else
    env->regs[R_EAX] = regs->rax;
    env->regs[R_EBX] = regs->rbx;
    env->regs[R_ECX] = regs->rcx;
    env->regs[R_EDX] = regs->rdx;
    env->regs[R_ESI] = regs->rsi;
    env->regs[R_EDI] = regs->rdi;
    env->regs[R_ESP] = regs->rsp;
    env->regs[R_EBP] = regs->rbp;

#ifdef TARGET_X86_64
    env->regs[8] = regs->r8;
    env->regs[9] = regs->r9;
    env->regs[10] = regs->r10;
    env->regs[11] = regs->r11;
    env->regs[12] = regs->r12;
    env->regs[13] = regs->r13;
    env->regs[14] = regs->r14;
    env->regs[15] = regs->r15;
#endif
#endif

    if (regs->rip != env->eip) {
        if (m_handlingKvmCallback || !m_cpuStateIsPrecise) {
            // We don't support this at all, it's better to crash than to risk
            // guest corruption.
            abort();
        }
    }

    env->eip = regs->rip;

    if (m_handlingKvmCallback) {
        fprintf(stderr, "warning: kvm setting cpu state while handling io\n");
        // TODO: try to set the system part of the flags register.
        // It should be OK to skip these because the KVM client usually writes
        // back the value it has just read when KVM_RUN exits. That value
        // is already stored in the CPU state of the symbex engine.
        assert(regs->rflags == env->mflags);
    } else {
        cpu_set_eflags(env, regs->rflags);
    }

    return 0;
}

int VCPU::SetFPU(kvm_fpu *fpu) {
    CPUX86State *env = m_env;

    env->fpstt = (fpu->fsw >> 11) & 7;
    env->fpus = fpu->fsw;
    env->fpuc = fpu->fcw;
    env->fpop = fpu->last_opcode;
    env->fpip = fpu->last_ip;
    env->fpdp = fpu->last_dp;
    for (unsigned i = 0; i < 8; ++i) {
        env->fptags[i] = !((fpu->ftwx >> i) & 1);
    }
    memcpy(env->fpregs, fpu->fpr, sizeof env->fpregs);
    memcpy(env->xmm_regs, fpu->xmm, sizeof env->xmm_regs);
    env->mxcsr = fpu->mxcsr;
    return 0;
}

void VCPU::SetCpuSegment(SegmentCache *libcpu_seg, const kvm_segment *kvm_seg) {
    libcpu_seg->selector = kvm_seg->selector;
    libcpu_seg->base = kvm_seg->base;
    libcpu_seg->limit = kvm_seg->limit;
    libcpu_seg->flags = (kvm_seg->type << DESC_TYPE_SHIFT) | (kvm_seg->present * DESC_P_MASK) |
                        (kvm_seg->dpl << DESC_DPL_SHIFT) | (kvm_seg->db << DESC_B_SHIFT) | (kvm_seg->s * DESC_S_MASK) |
                        (kvm_seg->l << DESC_L_SHIFT) | (kvm_seg->g * DESC_G_MASK) | (kvm_seg->avl * DESC_AVL_MASK);

    if (libcpu_seg->flags & DESC_G_MASK) {
        libcpu_seg->flags |= (libcpu_seg->limit >> 12) & 0x000f0000;
    }

    libcpu_seg->flags |= libcpu_seg->base & 0xff000000;
    libcpu_seg->flags |= (libcpu_seg->base & 0x00ff0000) >> 16;
}

int VCPU::SetSystemRegisters(kvm_sregs *sregs) {
    CPUX86State *env = m_env;

    // XXX: what about the interrupt bitmap?
    SetCpuSegment(&env->segs[R_CS], &sregs->cs);
    SetCpuSegment(&env->segs[R_DS], &sregs->ds);
    SetCpuSegment(&env->segs[R_ES], &sregs->es);
    SetCpuSegment(&env->segs[R_FS], &sregs->fs);
    SetCpuSegment(&env->segs[R_GS], &sregs->gs);
    SetCpuSegment(&env->segs[R_SS], &sregs->ss);

    SetCpuSegment(&env->tr, &sregs->tr);
    SetCpuSegment(&env->ldt, &sregs->ldt);

    env->idt.limit = sregs->idt.limit;
    env->idt.base = sregs->idt.base;
    env->gdt.limit = sregs->gdt.limit;
    env->gdt.base = sregs->gdt.base;

    env->cr[0] = sregs->cr0;
    env->cr[2] = sregs->cr2;
    env->cr[3] = sregs->cr3;
    env->cr[4] = sregs->cr4;
    env->v_tpr = sregs->cr8;
    env->v_apic_tpr = sregs->cr8 << 4;

    if (sregs->apic_base) {
        env->v_apic_base = sregs->apic_base;
    }

    env->efer = sregs->efer;
    env->hflags = cpu_compute_hflags(env);

    return 0;
}

int VCPU::SetMSRs(kvm_msrs *msrs) {
    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        helper_wrmsr_v(msrs->entries[i].index, msrs->entries[i].data);
    }
    return msrs->nmsrs;
}

int VCPU::SetMPState(kvm_mp_state *mp) {
    /* Only needed when using an irq chip */
    return 0;
}

int VCPU::GetRegisters(kvm_regs *regs) {
    CPUX86State *env = m_env;

    if (!m_cpuStateIsPrecise) {
        // Probably OK to let execution continue
        fprintf(stderr, "Getting register state in the middle of a translation block, eip/flags may be imprecise\n");
    }

#ifdef CONFIG_SYMBEX
    RR_cpu(env, regs[R_EAX], regs->rax);
    RR_cpu(env, regs[R_EBX], regs->rbx);
    RR_cpu(env, regs[R_ECX], regs->rcx);
    RR_cpu(env, regs[R_EDX], regs->rdx);
    RR_cpu(env, regs[R_ESI], regs->rsi);
    RR_cpu(env, regs[R_EDI], regs->rdi);
    RR_cpu(env, regs[R_ESP], regs->rsp);
    RR_cpu(env, regs[R_EBP], regs->rbp);

#ifdef TARGET_X86_64
    RR_cpu(env, regs[8], regs->r8);
    RR_cpu(env, regs[9], regs->r9);
    RR_cpu(env, regs[10], regs->r10);
    RR_cpu(env, regs[11], regs->r11);
    RR_cpu(env, regs[12], regs->r12);
    RR_cpu(env, regs[13], regs->r13);
    RR_cpu(env, regs[14], regs->r14);
    RR_cpu(env, regs[15], regs->r15);
#endif
#else
    regs->rax = env->regs[R_EAX];
    regs->rbx = env->regs[R_EBX];
    regs->rcx = env->regs[R_ECX];
    regs->rdx = env->regs[R_EDX];
    regs->rsi = env->regs[R_ESI];
    regs->rdi = env->regs[R_EDI];
    regs->rsp = env->regs[R_ESP];
    regs->rbp = env->regs[R_EBP];

#ifdef TARGET_X86_64
    regs->r8 = env->regs[8];
    regs->r9 = env->regs[9];
    regs->r10 = env->regs[10];
    regs->r11 = env->regs[11];
    regs->r12 = env->regs[12];
    regs->r13 = env->regs[13];
    regs->r14 = env->regs[14];
    regs->r15 = env->regs[15];
#endif
#endif

    regs->rip = env->eip;

    if (!m_handlingKvmCallback) {
        regs->rflags = cpu_get_eflags(env);
    } else {
        fprintf(stderr, "warning: kvm asking cpu state while handling io\n");
        // We must at least give the system flags to the KVM client, which
        // may use them to compute the segment registers.
        regs->rflags = env->mflags;
    }

    return 0;
}

int VCPU::GetFPU(kvm_fpu *fpu) {
    int i;
    CPUX86State *env = m_env;

    fpu->fsw = env->fpus & ~(7 << 11);
    fpu->fsw |= (env->fpstt & 7) << 11;
    fpu->fcw = env->fpuc;
    fpu->last_opcode = env->fpop;
    fpu->last_ip = env->fpip;
    fpu->last_dp = env->fpdp;
    for (i = 0; i < 8; ++i) {
        fpu->ftwx |= (!env->fptags[i]) << i;
    }
    memcpy(fpu->fpr, env->fpregs, sizeof env->fpregs);
    memcpy(fpu->xmm, env->xmm_regs, sizeof env->xmm_regs);
    fpu->mxcsr = env->mxcsr;

    return 0;
}

void VCPU::GetCpuSegment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg) {
    unsigned flags = libcpu_seg->flags;
    kvm_seg->selector = libcpu_seg->selector;
    kvm_seg->base = libcpu_seg->base;
    kvm_seg->limit = libcpu_seg->limit;
    kvm_seg->type = (flags >> DESC_TYPE_SHIFT) & 15;
    kvm_seg->present = (flags & DESC_P_MASK) != 0;
    kvm_seg->dpl = (flags >> DESC_DPL_SHIFT) & 3;
    kvm_seg->db = (flags >> DESC_B_SHIFT) & 1;
    kvm_seg->s = (flags & DESC_S_MASK) != 0;
    kvm_seg->l = (flags >> DESC_L_SHIFT) & 1;
    kvm_seg->g = (flags & DESC_G_MASK) != 0;
    kvm_seg->avl = (flags & DESC_AVL_MASK) != 0;
    kvm_seg->unusable = 0;
    kvm_seg->padding = 0;
}

void VCPU::Get8086Segment(kvm_segment *kvm_seg, const SegmentCache *libcpu_seg) {
    kvm_seg->selector = libcpu_seg->selector;
    kvm_seg->base = libcpu_seg->base;
    kvm_seg->limit = libcpu_seg->limit;
    kvm_seg->type = 3;
    kvm_seg->present = 1;
    kvm_seg->dpl = 3;
    kvm_seg->db = 0;
    kvm_seg->s = 1;
    kvm_seg->l = 0;
    kvm_seg->g = 0;
    kvm_seg->avl = 0;
    kvm_seg->unusable = 0;
}

int VCPU::GetSystemRegisters(kvm_sregs *sregs) {
    CPUX86State *env = m_env;
    // XXX: what about the interrupt bitmap?

    if (env->mflags & VM_MASK) {
        Get8086Segment(&sregs->cs, &env->segs[R_CS]);
        Get8086Segment(&sregs->ds, &env->segs[R_DS]);
        Get8086Segment(&sregs->es, &env->segs[R_ES]);
        Get8086Segment(&sregs->fs, &env->segs[R_FS]);
        Get8086Segment(&sregs->gs, &env->segs[R_GS]);
        Get8086Segment(&sregs->ss, &env->segs[R_SS]);
    } else {
        GetCpuSegment(&sregs->cs, &env->segs[R_CS]);
        GetCpuSegment(&sregs->ds, &env->segs[R_DS]);
        GetCpuSegment(&sregs->es, &env->segs[R_ES]);
        GetCpuSegment(&sregs->fs, &env->segs[R_FS]);
        GetCpuSegment(&sregs->gs, &env->segs[R_GS]);
        GetCpuSegment(&sregs->ss, &env->segs[R_SS]);
    }

    GetCpuSegment(&sregs->tr, &env->tr);
    GetCpuSegment(&sregs->ldt, &env->ldt);

    sregs->idt.limit = env->idt.limit;
    sregs->idt.base = env->idt.base;
    memset(sregs->idt.padding, 0, sizeof sregs->idt.padding);
    sregs->gdt.limit = env->gdt.limit;
    sregs->gdt.base = env->gdt.base;
    memset(sregs->gdt.padding, 0, sizeof sregs->gdt.padding);

    sregs->cr0 = env->cr[0];
    sregs->cr2 = env->cr[2];
    sregs->cr3 = env->cr[3];
    sregs->cr4 = env->cr[4];
    sregs->cr8 = env->v_tpr;

    sregs->apic_base = env->v_apic_base;
    sregs->cr8 = env->v_tpr;

    sregs->efer = env->efer;
    return 0;
}

int VCPU::GetMSRs(kvm_msrs *msrs) {
    for (unsigned i = 0; i < msrs->nmsrs; ++i) {
        msrs->entries[i].data = helper_rdmsr_v(msrs->entries[i].index);
    }
    return msrs->nmsrs;
}

int VCPU::GetMPState(kvm_mp_state *mp) {
    // Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}
}
}
