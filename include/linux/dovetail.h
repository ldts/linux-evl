/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016 Philippe Gerum  <rpm@xenomai.org>.
 */
#ifndef _LINUX_DOVETAIL_H
#define _LINUX_DOVETAIL_H

#ifdef CONFIG_DOVETAIL

#include <linux/sched.h>
#include <linux/thread_info.h>
#include <asm/dovetail.h>

struct pt_regs;
struct task_struct;

enum inband_event_type {
	INBAND_TASK_SCHEDULE,
	INBAND_TASK_SIGNAL,
	INBAND_TASK_MIGRATION,
	INBAND_TASK_EXIT,
	INBAND_PROCESS_CLEANUP,
};

struct dovetail_migration_data {
	struct task_struct *task;
	int dest_cpu;
};

int pipeline_syscall(struct thread_info *ti,
		     unsigned long syscall, struct pt_regs *regs);

void __oob_trap_notify(unsigned int trapnr,
		       struct pt_regs *regs);

static inline void oob_trap_notify(unsigned int trapnr,
				   struct pt_regs *regs)
{
	if (running_oob())
		__oob_trap_notify(trapnr, regs);
}

void inband_event_notify(enum inband_event_type,
			 void *data);

static inline void inband_signal_notify(struct task_struct *p)
{
	if (test_ti_local_flags(task_thread_info(p), _TLF_DOVETAIL))
		inband_event_notify(INBAND_TASK_SIGNAL, p);
}

static inline void inband_migration_notify(struct task_struct *p, int cpu)
{
	if (test_ti_local_flags(task_thread_info(p), _TLF_DOVETAIL)) {
		struct dovetail_migration_data d = {
			.task = p,
			.dest_cpu = cpu,
		};
		inband_event_notify(INBAND_TASK_MIGRATION, &d);
	}
}

static inline void inband_exit_notify(void)
{
	if (test_thread_local_flags(_TLF_DOVETAIL))
		inband_event_notify(INBAND_TASK_EXIT, NULL);
}

static inline void inband_cleanup_notify(struct mm_struct *mm)
{
	/*
	 * Notify regardless of _TLF_DOVETAIL: current may have
	 * resources to clean up although it might not be interested
	 * in other kernel events.
	 */
	inband_event_notify(INBAND_PROCESS_CLEANUP, mm);
}

void sync_inband_irqs(void);

int dovetail_start(void);

void dovetail_stop(void);

static inline
struct oob_thread_state *dovetail_current_state(void)
{
	return &current_thread_info()->oob_state;
}

static inline
struct oob_thread_state *dovetail_task_state(struct task_struct *p)
{
	return &task_thread_info(p)->oob_state;
}

void dovetail_call_mayday(struct thread_info *ti,
			  struct pt_regs *regs);

static inline void dovetail_send_mayday(struct task_struct *castaway)
{
	struct thread_info *ti = task_thread_info(castaway);

	if (test_ti_local_flags(ti, _TLF_DOVETAIL))
		set_ti_thread_flag(ti, TIF_MAYDAY);
}

#else	/* !CONFIG_DOVETAIL */

#define oob_trap_notify(__trapnr, __regs)	 do { } while (0)

static inline
int pipeline_syscall(struct thread_info *ti,
		     unsigned long syscall, struct pt_regs *regs)
{
	return 0;
}

static inline void inband_signal_notify(struct task_struct *p) { }

static inline
void inband_migration_notify(struct task_struct *p, int cpu) { }

static inline void inband_exit_notify(void) { }

static inline void inband_cleanup_notify(struct mm_struct *mm) { }

#endif	/* !CONFIG_DOVETAIL */

static inline bool dovetailing(void)
{
	return IS_ENABLED(CONFIG_DOVETAIL);
}

static inline bool dovetail_debug(void)
{
	return IS_ENABLED(CONFIG_DEBUG_DOVETAIL);
}

#endif /* _LINUX_DOVETAIL_H */
