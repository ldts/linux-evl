/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016 Philippe Gerum  <rpm@xenomai.org>.
 */
#include <linux/timekeeper_internal.h>
#include <linux/sched/signal.h>
#include <linux/irq_pipeline.h>
#include <linux/dovetail.h>
#include <asm/unistd.h>
#include <asm/syscall.h>

static bool dovetail_enabled;

void __weak arch_inband_task_init(struct task_struct *p)
{
}

void inband_task_init(struct task_struct *p)
{
	struct thread_info *ti = task_thread_info(p);

	clear_ti_local_flags(ti, _TLF_DOVETAIL|_TLF_OOB|_TLF_OFFSTAGE);
	arch_inband_task_init(p);
}

void dovetail_init_altsched(struct dovetail_altsched_context *p)
{
	struct task_struct *tsk = current;

	check_inband_stage();
	p->task = tsk;
	p->active_mm = tsk->mm;
	p->borrowed_mm = false;
}
EXPORT_SYMBOL_GPL(dovetail_init_altsched);

void dovetail_start_altsched(void)
{
	check_inband_stage();
	set_thread_local_flags(_TLF_DOVETAIL);
}
EXPORT_SYMBOL_GPL(dovetail_start_altsched);

void dovetail_stop_altsched(void)
{
	clear_thread_local_flags(_TLF_DOVETAIL);
	clear_thread_flag(TIF_MAYDAY);
}
EXPORT_SYMBOL_GPL(dovetail_stop_altsched);

void __weak handle_oob_syscall(struct pt_regs *regs)
{
}

int __weak handle_pipelined_syscall(struct irq_stage *stage,
				    struct pt_regs *regs)
{
	return 0;
}

void __weak handle_oob_mayday(struct pt_regs *regs)
{
}

static inline
void call_mayday(struct thread_info *ti, struct pt_regs *regs)
{
	clear_ti_thread_flag(ti, TIF_MAYDAY);
	handle_oob_mayday(regs);
}

void dovetail_call_mayday(struct thread_info *ti, struct pt_regs *regs)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	call_mayday(ti, regs);
	hard_local_irq_restore(flags);
}

int __pipeline_syscall(struct thread_info *ti, struct pt_regs *regs)
{
	struct irq_stage *caller_stage, *target_stage;
	struct irq_stage_data *p, *this_context;
	unsigned long flags;
	int ret = 0;

	/*
	 * We should definitely not pipeline a syscall through the
	 * slow path with IRQs off.
	 */
	WARN_ON_ONCE(dovetail_debug() && hard_irqs_disabled());

	if (!dovetail_enabled)
		return 0;

	flags = hard_local_irq_save();
	caller_stage = current_stage;
	this_context = current_staged;
	target_stage = &oob_stage;
next:
	p = this_staged(target_stage);
	set_current_staged(p);
	hard_local_irq_restore(flags);
	ret = handle_pipelined_syscall(caller_stage, regs);
	flags = hard_local_irq_save();
	/*
	 * Be careful about stage switching _and_ CPU migration that
	 * might have happened as a result of handing over the syscall
	 * to the out-of-band handler.
	 *
	 * - if a stage migration is detected, fetch the new
	 * per-stage, per-CPU context pointer.
	 *
	 * - if no stage migration happened, switch back to the
	 * initial caller's stage, on a possibly different CPU though.
	 */
	if (current_stage != target_stage)
		this_context = current_staged;
	else {
		p = this_staged(this_context->stage);
		set_current_staged(p);
	}

	if (this_context->stage == &inband_stage) {
		if (target_stage != &inband_stage && ret == 0) {
			target_stage = &inband_stage;
			goto next;
		}
		p = this_inband_staged();
		if (stage_irqs_pending(p))
			sync_current_stage();
	} else if (test_ti_thread_flag(ti, TIF_MAYDAY))
		call_mayday(ti, regs);

	hard_local_irq_restore(flags);

	return ret;
}

void sync_inband_irqs(void)
{
	struct irq_stage_data *p;
	unsigned long flags;

	flags = hard_local_irq_save();

	p = this_inband_staged();
	if (stage_irqs_pending(p))
		sync_current_stage();

	hard_local_irq_restore(flags);
}

int pipeline_syscall(struct thread_info *ti,
		     unsigned long nr, struct pt_regs *regs)
{
	unsigned long local_flags = READ_ONCE(ti_local_flags(ti));
	int ret;

	/*
	 * If the syscall number is out of bounds and we are not
	 * running in-band, this has to be a non-native system call
	 * handled by some co-kernel from the oob stage. Hand it over
	 * via the fast syscall handler.
	 *
	 * Otherwise, if the system call is out of bounds or alternate
	 * scheduling is enabled for the current thread, propagate the
	 * syscall through the pipeline stages. This allows:
	 *
	 * - the co-kernel to receive any initial - foreign - syscall
	 * a thread should send for enabling dovetailing from the
	 * in-band stage.
	 *
	 * - the co-kernel to manipulate the current execution stage
	 * for handling the request, which includes switching the
	 * current thread back to the in-band context if the syscall
	 * is a native one, or promoting it to the oob stage if
	 * handling a foreign syscall requires this.
	 *
	 * Native syscalls from common (non-dovetailed) threads are
	 * ignored by this routine, flowing down to the in-band system
	 * call handler.
	 */

	if (nr >= NR_syscalls && (local_flags & _TLF_OOB)) {
		handle_oob_syscall(regs);
		local_flags = READ_ONCE(ti_local_flags(ti));
		if (local_flags & _TLF_OOB) {
			if (test_ti_thread_flag(ti, TIF_MAYDAY))
				dovetail_call_mayday(ti, regs);
			return 1; /* don't pass down, no tail work. */
		} else {
			sync_inband_irqs();
			return -1; /* don't pass down, do tail work. */
		}
	}

	if ((local_flags & _TLF_DOVETAIL) || nr >= NR_syscalls) {
		ret = __pipeline_syscall(ti, regs);
		local_flags = READ_ONCE(ti_local_flags(ti));
		if (local_flags & _TLF_OOB)
			return 1; /* don't pass down, no tail work. */
		if (ret)
			return -1; /* don't pass down, do tail work. */
	}

	return 0; /* pass syscall down to the host. */
}

void __weak handle_oob_trap(unsigned int trapnr, struct pt_regs *regs)
{
}

void __oob_trap_notify(unsigned int exception, struct pt_regs *regs)
{
	/*
	 * We send a notification about all traps raised over a
	 * registered oob stage only.
	 */
	if (dovetail_enabled)
		handle_oob_trap(exception, regs);
}

void __weak handle_inband_event(enum inband_event_type event, void *data)
{
}

void inband_event_notify(enum inband_event_type event, void *data)
{
	check_inband_stage();

	if (dovetail_enabled)
		handle_inband_event(event, data);
}

void __weak resume_oob_task(struct task_struct *p)
{
}

static void finalize_oob_transition(void) /* hard IRQs off */
{
	struct irq_pipeline_data *pd;
	struct irq_stage_data *p;
	struct task_struct *t;

	check_inband_stage();
	pd = raw_cpu_ptr(&irq_pipeline);
	t = pd->task_inflight;
	if (t == NULL)
		return;

	/*
	 * @t which is in flight to the oob stage might have received
	 * a signal while waiting in off-stage state to be actually
	 * scheduled out. We can't act upon that signal safely from
	 * here, we simply let the task complete the migration process
	 * to the oob stage. The pending signal will be handled when
	 * the task eventually exits the out-of-band context by the
	 * converse migration.
	 */
	pd->task_inflight = NULL;

	/*
	 * IRQs are hard disabled, but the stage transition handler
	 * may assume the oob stage is stalled: fix this up.
	 */
	p = this_oob_staged();
	set_stage_bit(STAGE_STALL_BIT, p);
	resume_oob_task(t);
	clear_stage_bit(STAGE_STALL_BIT, p);
	if (stage_irqs_pending(p))
		/* Current stage (in-band) != p->stage (oob). */
		sync_stage(p->stage);
}

void oob_trampoline(void)
{
	unsigned long flags;

	flags = hard_local_irq_save();
	finalize_oob_transition();
	hard_local_irq_restore(flags);
}

int inband_switch_tail(void)
{
	bool inband;

	check_hard_irqs_disabled();

	/*
	 * We may run this code either over the inband or oob
	 * contexts. If inband, we may have a thread blocked in
	 * dovetail_leave_inband(), waiting for the co-kernel to
	 * schedule it back in over the oob context:
	 * finalize_oob_transition() should take care of it. If oob,
	 * the co-kernel just switched us back, and we may update the
	 * context markers.
	 *
	 * CAUTION: The preemption count may not reflect the active
	 * stage yet, so use the current stage pointer to determine
	 * which one we are on.
	 */
	inband = current_stage == &inband_stage;
	if (inband)
		finalize_oob_transition();
	else {
		set_thread_local_flags(_TLF_OOB);
		WARN_ON_ONCE(dovetail_debug() &&
			     (preempt_count() & STAGE_MASK));
		preempt_count_add(STAGE_OFFSET);
	}

	if (inband)
		hard_local_irq_enable();

	return !inband;
}

int dovetail_start(void)
{
	check_inband_stage();

	if (dovetail_enabled)
		return -EBUSY;

	if (!oob_stage_present())
		return -EAGAIN;

	dovetail_enabled = true;
	smp_wmb();

	return 0;
}
EXPORT_SYMBOL_GPL(dovetail_start);

void dovetail_stop(void)
{
	check_inband_stage();

	dovetail_enabled = false;
	smp_wmb();
}
EXPORT_SYMBOL_GPL(dovetail_stop);
