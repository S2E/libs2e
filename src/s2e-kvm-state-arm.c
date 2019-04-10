///
/// Copyright (C) 2015-2017, Cyberhaven
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



#define BIT(n) (1 << (n))
#include <cpu/kvm.h>


#include <cpu/arm/cpu.h>

#include <cpu/se_libcpu.h>
#include <timer.h>
#include "s2e-kvm-interface.h"

extern CPUArchState *env;


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

static inline long copy_from_user(void *to, const void *from, unsigned long n)
{

	memcpy(to, from, n);
	return 0;
}



static inline long copy_to_user(void *to, const void *from, unsigned long n)
{

	memcpy(to, from, n);
	return 0;
}



static uint64 core_reg_offset_from_id(uint64 id)
{
	return id & ~(KVM_REG_ARCH_MASK | KVM_REG_SIZE_MASK | KVM_REG_ARM_CORE);
}


static int get_core_reg(const struct kvm_one_reg *reg)
{
	uint32 *uaddr = (uint32 *)(long)reg->addr;
	//struct kvm_regs *regs = &vcpu->arch.ctxt.gp_regs;

	uint64 off;

	if (KVM_REG_SIZE(reg->id) != 4)
		return -ENOENT;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= sizeof(env->regs) / KVM_REG_SIZE(reg->id))
		return -ENOENT;

	uaddr=&env->regs[off];
	return 0;
			//put_user(((uint32 *)env->regs)[off], uaddr);
}


static int reg_from_user(void *val, const void *uaddr, uint64 id)
{
	if (copy_from_user(val, uaddr, KVM_REG_SIZE(id)) != 0)
		return -EFAULT;
	return 0;
}

/*
 * Writes a register value to a userspace address from a kernel variable.
 * Make sure that register size matches sizeof(*__val).
 */
static int reg_to_user(void *uaddr, const void *val, uint64 id)
{
	if (copy_to_user(uaddr, val, KVM_REG_SIZE(id)) != 0)
		return -EFAULT;
	return 0;
}


static int vfp_get_reg(int vcpu_fd, uint64 id, void *uaddr)
{

	uint32 vfpid = (id & KVM_REG_ARM_VFP_MASK);

	/* Fail if we have unknown bits set. */
	if (id & ~(KVM_REG_ARCH_MASK|KVM_REG_SIZE_MASK|KVM_REG_ARM_COPROC_MASK
		   | ((1 << KVM_REG_ARM_COPROC_SHIFT)-1)))
		return -ENOENT;

	if (vfpid < 16) {
		if (KVM_REG_SIZE(id) != 8)
			return -ENOENT;
		return reg_to_user(uaddr, &env->vfp.xregs[vfpid],
				   id);
		 return 0;
	}

	/* FP control registers are all 32 bit. */
	if (KVM_REG_SIZE(id) != 4)
		return -ENOENT;

	switch (vfpid) {
	case KVM_REG_ARM_VFP_FPEXC:
		//return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpexc, id);
		return KVM_REG_ARM_VFP_FPEXC;
	case KVM_REG_ARM_VFP_FPSCR:
		//return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpscr, id);
		return KVM_REG_ARM_VFP_FPSCR;
	case KVM_REG_ARM_VFP_FPINST:
		//return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpinst, id);
		return KVM_REG_ARM_VFP_FPINST;
	case KVM_REG_ARM_VFP_FPINST2:
		//return reg_to_user(uaddr, &vcpu->arch.ctxt.vfp.fpinst2, id);
		return KVM_REG_ARM_VFP_FPINST2;
//	case KVM_REG_ARM_VFP_MVFR0:
//		val = fmrx(MVFR0);
//		return reg_to_user(uaddr, &val, id);
//	case KVM_REG_ARM_VFP_MVFR1:
//		val = fmrx(MVFR1);
//		return reg_to_user(uaddr, &val, id);
//	case KVM_REG_ARM_VFP_FPSID:
//		val = fmrx(FPSID);
//		return reg_to_user(uaddr, &val, id);
	default:
		return -ENOENT;
	}

}

static int vfp_set_reg(int vcpu_fd, uint64 id, const void  *uaddr)
{
	uint32 vfpid = (id & KVM_REG_ARM_VFP_MASK);

	/* Fail if we have unknown bits set. */
	if (id & ~(KVM_REG_ARCH_MASK|KVM_REG_SIZE_MASK|KVM_REG_ARM_COPROC_MASK
		   | ((1 << KVM_REG_ARM_COPROC_SHIFT)-1)))
		return -ENOENT;

	if (vfpid < 16) {
		if (KVM_REG_SIZE(id) != 8)
			return -ENOENT;
		return reg_from_user(&env->vfp.xregs[vfpid],
				     uaddr, id);
	}

	/* FP control registers are all 32 bit. */
	if (KVM_REG_SIZE(id) != 4)
		return -ENOENT;

	switch (vfpid) {
	case KVM_REG_ARM_VFP_FPEXC:
		return KVM_REG_ARM_VFP_FPEXC;
	case KVM_REG_ARM_VFP_FPSCR:
		return KVM_REG_ARM_VFP_FPSCR;
	case KVM_REG_ARM_VFP_FPINST:
		return  KVM_REG_ARM_VFP_FPINST;
	case KVM_REG_ARM_VFP_FPINST2:
		return KVM_REG_ARM_VFP_FPINST2;
	/* These are invariant. */
//	case KVM_REG_ARM_VFP_MVFR0:
//		if (reg_from_user(&val, uaddr, id))
//			return -EFAULT;
//		if (val != fmrx(MVFR0))
//			return -EINVAL;
//		return 0;
//	case KVM_REG_ARM_VFP_MVFR1:
//		if (reg_from_user(&val, uaddr, id))
//			return -EFAULT;
//		if (val != fmrx(MVFR1))
//			return -EINVAL;
//		return 0;
//	case KVM_REG_ARM_VFP_FPSID:
//		if (reg_from_user(&val, uaddr, id))
//			return -EFAULT;
//		if (val != fmrx(FPSID))
//			return -EINVAL;
//		return 0;
	default:
		return -ENOENT;
	}
}
int s2e_kvm_vcpu_get_one_reg(int vcpu_fd, struct kvm_one_reg *reg){

	void  *uaddr = (void*)(long)reg->addr;
	/* We currently use nothing arch-specific in upper 32 bits */
	if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM >> 32)
		return -EINVAL;

	/* Register group 16 means we want a core register. */
	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_CORE)
		return get_core_reg(reg);

//	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_FW)
//		return kvm_arm_get_fw_reg(vcpu, reg);
//
//	if (is_timer_reg(reg->id))
//		return get_timer_reg(vcpu, reg);
	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_VFP)
		return vfp_get_reg(vcpu_fd, reg->id, uaddr);

	return (reg->id & KVM_REG_ARM_COPROC_MASK);
}


static int set_core_reg(const struct kvm_one_reg *reg)
{
	uint32 *uaddr = (uint32 *)(long)reg->addr;

	uint64 off, val=0;

	if (KVM_REG_SIZE(reg->id) != 4)
		return -ENOENT;

	/* Our ID is an index into the kvm_regs struct. */
	off = core_reg_offset_from_id(reg->id);
	if (off >= sizeof(struct kvm_regs) / KVM_REG_SIZE(reg->id))
		return -ENOENT;

	val=*uaddr;
//	if (get_user(val, uaddr) != 0)
//		return -EFAULT;

//	if (off == KVM_REG_ARM_CORE_REG(usr_regs.ARM_cpsr)) {
//		unsigned long mode = val & MODE_MASK;
//		switch (mode) {
//		case USR_MODE:
//		case FIQ_MODE:
//		case IRQ_MODE:
//		case SVC_MODE:
//		case ABT_MODE:
//		case UND_MODE:
//			break;
//		default:
//			return -EINVAL;
//		}
//	}

	((uint32 *)env->regs)[off] = val;
	return 0;
}

int s2e_kvm_vcpu_set_one_reg(int vcpu_fd, struct kvm_one_reg *reg){

	uint32 *uaddr = (uint32 *)(long)reg->addr;
	/* We currently use nothing arch-specific in upper 32 bits */
	if ((reg->id & ~KVM_REG_SIZE_MASK) >> 32 != KVM_REG_ARM >> 32)
		return -EINVAL;

	/* Register group 16 means we set a core register. */
	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_CORE)
		return set_core_reg(reg);

//	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_FW)
//		return kvm_arm_set_fw_reg(vcpu, reg);
//
//	if (is_timer_reg(reg->id))
//		return set_timer_reg(vcpu, reg);

	if ((reg->id & KVM_REG_ARM_COPROC_MASK) == KVM_REG_ARM_VFP)
		return vfp_set_reg(vcpu_fd, reg->id, uaddr);

	return (reg->id & KVM_REG_ARM_COPROC_MASK);
}

int s2e_kvm_vcpu_set_mp_state(int vcpu_fd, struct kvm_mp_state *mp) {
    /* Only needed when using an irq chip */
    return 0;
}

int s2e_kvm_vcpu_get_mp_state(int vcpu_fd, struct kvm_mp_state *mp) {
    // Not needed without IRQ chip?
    mp->mp_state = KVM_MP_STATE_RUNNABLE;
    return 0;
}




int s2e_kvm_arch_vcpu_ioctl_vcpu_init(int vcpu_fd,struct kvm_vcpu_init *init)
{
/*	int ret;

	.usr_regs.ARM_cpsr = SVC_MODE | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT;


	ret = kvm_vcpu_set_target(vcpu, init);
	if (ret)
		return ret;
*/
	return 0;

}


int s2e_kvm_vcpu_set_regs(int vcpu_fd, struct kvm_m_regs *regs) {
#ifdef CONFIG_SYMBEX
    WR_cpu(env, regs[0], regs[0]);
    WR_cpu(env, regs[1], regs[1]);
    WR_cpu(env, regs[2], regs[2]);
    WR_cpu(env, regs[3], regs[3]);
    WR_cpu(env, regs[4], regs[4]);
    WR_cpu(env, regs[5], regs[5]);
    WR_cpu(env, regs[6], regs[6]);
    WR_cpu(env, regs[7], regs[7]);
    WR_cpu(env, regs[8], regs[8]);
    WR_cpu(env, regs[9], regs[9]);
    WR_cpu(env, regs[10], regs[10]);
    WR_cpu(env, regs[11], regs[11]);
    WR_cpu(env, regs[12], regs[12]);
    WR_cpu(env, regs[13], regs[13]);
    WR_cpu(env, regs[14], regs[14]);
    WR_cpu(env, regs[15], regs[15]);
#else
    env->regs[0] = regs->regs[0];
    env->regs[1] = regs->regs[1];
    env->regs[2] = regs->regs[2];
    env->regs[3] = regs->regs[3];
    env->regs[4] = regs->regs[4];
    env->regs[5] =regs->regs[5];
    env->regs[6] = regs->regs[6];
    env->regs[7] = regs->regs[7];
    env->regs[8] = regs->regs[8];
    env->regs[9] = regs->regs[9];
    env->regs[10] = regs->regs[10];
    env->regs[11] = regs->regs[11];
    env->regs[12] = regs->regs[12];
    env->regs[13] = regs->regs[13];
    env->regs[14] = regs->regs[14];
    env->regs[15] = regs->regs[15];
    printf("r15=%#x\n",env->regs[15]);
#endif

//
//    if (regs->rip != env->eip) {
//        if (g_handling_kvm_cb || !g_cpu_state_is_precise) {
//            // We don't support this at all, it's better to crash than to risk
//            // guest corruption.
//            abort();
//        }
//    }

//    env->eip = regs->rip;
//
//    if (g_handling_kvm_cb) {
//        fprintf(stderr, "warning: kvm setting cpu state while handling io\n");
//        // TODO: try to set the system part of the flags register.
//        // It should be OK to skip these because the KVM client usually writes
//        // back the value it has just read when KVM_RUN exits. That value
//        // is already stored in the CPU state of the symbex engine.
//        assert(regs->rflags == env->mflags);
//    } else {
//        cpu_set_eflags(env, regs->rflags);
//    }

    return 0;
}
int s2e_kvm_vcpu_set_sregs(int vcpu_fd, struct kvm_m_sregs *sregs) {
    // XXX: what about the interrupt bitmap?
	env->v7m.other_sp = sregs->other_sp;
	env->v7m.vecbase = sregs->vecbase;
	env->v7m.basepri = sregs->basepri;
	env->v7m.control = sregs->control;
	env->v7m.current_sp = sregs->current_sp;
	env->v7m.exception = sregs->exception;
	env->v7m.pending_exception = sregs->pending_exception;
	env->thumb = sregs->thumb;
	printf("other_sp=%#x\n",env->v7m.other_sp);
	printf("thumb=%#x\n", env->thumb);
    return 0;
}

int s2e_kvm_vcpu_get_regs(int vcpu_fd, struct kvm_m_regs *regs) {
    if (!g_cpu_state_is_precise) {
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
    RR_cpu(env, regs[8], regs->r8);
    RR_cpu(env, regs[9], regs->r9);
    RR_cpu(env, regs[10], regs->r10);
    RR_cpu(env, regs[11], regs->r11);
    RR_cpu(env, regs[12], regs->r12);
    RR_cpu(env, regs[13], regs->r13);
    RR_cpu(env, regs[14], regs->r14);
    RR_cpu(env, regs[15], regs->r15);
#else
    regs->regs[0] = env->regs[0];
    regs->regs[1]= env->regs[1];
    regs->regs[2] = env->regs[2];
    regs->regs[3] = env->regs[3];
    regs->regs[4] = env->regs[4];
    regs->regs[5] = env->regs[5];
    regs->regs[6] = env->regs[6];
    regs->regs[7] = env->regs[7];
    regs->regs[8] = env->regs[8];
    regs->regs[9]= env->regs[9];
    regs->regs[10] = env->regs[10];
    regs->regs[11] = env->regs[11];
    regs->regs[12] = env->regs[12];
    regs->regs[13] = env->regs[13];
    regs->regs[14] = env->regs[14];
    regs->regs[15] = env->regs[15];
#endif

//    regs->rip = env->eip;
//
//    if (!g_handling_kvm_cb) {
//        regs->rflags = cpu_get_eflags(env);
//    } else {
//        fprintf(stderr, "warning: kvm asking cpu state while handling io\n");
//        // We must at least give the system flags to the KVM client, which
//        // may use them to compute the segment registers.
//        regs->rflags = env->mflags;
//    }

    return 0;
}
int s2e_kvm_vcpu_get_sregs(int vcpu_fd, struct kvm_m_sregs *sregs) {
    // XXX: what about the interrupt bitmap?

	sregs->other_sp = env->v7m.other_sp;
	sregs->vecbase = env->v7m.vecbase;
	sregs->basepri = env->v7m.basepri;
	sregs->control = env->v7m.control;
	sregs->current_sp = env->v7m.current_sp;
	sregs->exception = env->v7m.exception;
	sregs->pending_exception = env->v7m.pending_exception;
	sregs->thumb = env->thumb;
    return 0;
}

