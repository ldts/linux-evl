/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016, 2019 Philippe Gerum  <rpm@xenomai.org>.
 */
#ifndef _LINUX_IRQSTAGE_H
#define _LINUX_IRQSTAGE_H

#ifdef CONFIG_IRQ_PIPELINE

#include <linux/percpu.h>
#include <linux/bitops.h>
#include <linux/preempt.h>
#include <asm/irq_pipeline.h>

struct task_struct;
struct kvm_oob_notifier;

struct irq_stage {
	int index;
	const char *name;
};

extern struct irq_stage inband_stage;

extern struct irq_stage oob_stage;

/* Interrupts disabled for a stage. */
#define STAGE_STALL_BIT  0

struct irq_event_map;

struct irq_log {
	unsigned long himap;
	struct irq_event_map *map;
};

/* Per-CPU, per-stage data. */
struct irq_stage_data {
	unsigned long status;
	struct irq_log log;
	struct irq_stage *stage;
#ifdef CONFIG_DEBUG_IRQ_PIPELINE
	int cpu;
#endif
};

/* Per-CPU pipeline descriptor. */
struct irq_pipeline_data {
	struct irq_stage_data stages[2];
	struct irq_stage_data *__curr;
	struct pt_regs tick_regs;
#ifdef CONFIG_DOVETAIL
	struct task_struct *task_inflight;
	struct task_struct *rqlock_owner;
	struct kvm_oob_notifier *vcpu_notify;
#endif
};

DECLARE_PER_CPU(struct irq_pipeline_data, irq_pipeline);

/**
 * this_staged - IRQ stage data on the current CPU
 *
 * Return the address of @stage's data on the current CPU. IRQs must
 * be hard disabled to prevent CPU migration.
 */
static inline
struct irq_stage_data *this_staged(struct irq_stage *stage)
{
	return &raw_cpu_ptr(irq_pipeline.stages)[stage->index];
}

/**
 * percpu_inband_staged - IRQ stage data on specified CPU
 *
 * Return the address of @stage's data on @cpu.
 *
 * NOTE: this is the slowest accessor, use it carefully. Prefer
 * this_staged() for requests referring to the current
 * CPU. Additionally, if the target stage is known at build time,
 * consider using this_{inband, oob}_staged() instead.
 */
static inline
struct irq_stage_data *percpu_inband_staged(struct irq_stage *stage, int cpu)
{
	return &per_cpu(irq_pipeline.stages, cpu)[stage->index];
}

/**
 * this_inband_staged - return the address of the pipeline context
 * data for the inband stage on the current CPU. CPU migration must be
 * disabled.
 *
 * NOTE: this accessor is recommended when the stage we refer to is
 * known at build time to be the inband one.
 */
static inline struct irq_stage_data *this_inband_staged(void)
{
	return raw_cpu_ptr(&irq_pipeline.stages[0]);
}

/**
 * this_oob_staged - return the address of the pipeline context
 * data for the registered oob stage on the current CPU. CPU migration
 * must be disabled.
 *
 * NOTE: this accessor is recommended when the stage we refer to is
 * known at build time to be the registered oob stage. This address is
 * always different from the context data of the inband stage, even in
 * absence of registered oob stage.
 */
static inline struct irq_stage_data *this_oob_staged(void)
{
	return raw_cpu_ptr(&irq_pipeline.stages[1]);
}

/**
 * __current_staged() - return the address of the pipeline
 * context data of the stage running on the current CPU. CPU migration
 * must be disabled.
 */
static inline struct irq_stage_data *__current_staged(void)
{
	return raw_cpu_read(irq_pipeline.__curr);
}

#define current_staged __current_staged()

static inline
void __set_current_staged(struct irq_stage_data *pd)
{
	struct irq_pipeline_data *p = raw_cpu_ptr(&irq_pipeline);
	p->__curr = pd;
#ifdef CONFIG_DEBUG_IRQ_PIPELINE
	/*
	 * Setting our context with another processor's is a really
	 * bad idea, our caller definitely went loopy.
	 */
	WARN_ON_ONCE(raw_smp_processor_id() != pd->cpu);
#endif
}

/**
 * irq_set_*_context() - switch the current CPU to the specified stage
 * context. CPU migration must be disabled.
 *
 * NOTE: calling these routines is the only sane and safe way to
 * change the current stage for the current CPU. Don't bypass,
 * ever. Really.
 */
static inline
void switch_oob(struct irq_stage_data *pd)
{
	__set_current_staged(pd);
	if (!(preempt_count() & STAGE_MASK))
		preempt_count_add(STAGE_OFFSET);
}

static inline
void switch_inband(struct irq_stage_data *pd)
{
	__set_current_staged(pd);
	if (preempt_count() & STAGE_MASK)
		preempt_count_sub(STAGE_OFFSET);
}

static inline
void set_current_staged(struct irq_stage_data *pd)
{
	if (pd->stage == &inband_stage)
		switch_inband(pd);
	else
		switch_oob(pd);
}

static inline struct irq_stage *__current_stage(void)
{
	/*
	 * We don't have to hard disable irqs while accessing the
	 * per-CPU stage data here, because there is no way we could
	 * change stages while migrating CPUs.
	 */
	return __current_staged()->stage;
}

#define current_stage	__current_stage()

static inline bool running_inband(void)
{
	return stage_level() == 0;
}

static inline bool running_oob(void)
{
	return !running_inband();
}

static inline bool oob_stage_present(void)
{
	return oob_stage.index != 0;
}

/**
 * stage_irqs_pending() - Whether we have interrupts pending
 * (i.e. logged) on the current CPU for the given stage. Hard IRQs
 * must be disabled.
 */
static inline int stage_irqs_pending(struct irq_stage_data *pd)
{
	return pd->log.himap != 0;
}

void sync_current_stage(void);

void sync_stage(struct irq_stage *top);

void irq_post_stage(struct irq_stage *stage,
		    unsigned int irq);

#ifdef CONFIG_DEBUG_IRQ_PIPELINE

#define __check_stage_bit_access(__pd)			\
	({						\
		check_hard_irqs_disabled_in_smp();	\
		(__pd)->cpu != raw_smp_processor_id();	\
	})

#define check_stage_bit_access(__op, __bit, __pd)			\
	do {								\
		if (__check_stage_bit_access(__pd))			\
			trace_printk("REMOTE %s(%s) to %s/%d\n",	\
			     __op, __bit,  __pd->stage->name, __pd->cpu); \
	} while (0)

#define set_stage_bit(__bit, __pd)					\
	do {								\
		__set_bit(__bit, &(__pd)->status);			\
		check_stage_bit_access("set", # __bit, __pd);		\
	} while (0)

#define clear_stage_bit(__bit, __pd)					\
	do {								\
		__clear_bit(__bit, &(__pd)->status);			\
		check_stage_bit_access("clear", # __bit, __pd);		\
	} while (0)

#define test_and_set_stage_bit(__bit, __pd)				\
	({								\
		int __ret;						\
		__ret = __test_and_set_bit(__bit, &(__pd)->status);	\
		check_stage_bit_access("test_and_set", # __bit, __pd);	\
		__ret;							\
	})

#define __test_stage_bit(__bit, __pd)					\
	test_bit(__bit, &(__pd)->status)

#define test_stage_bit(__bit, __pd)					\
	({								\
		int __ret;						\
		__ret = __test_stage_bit(__bit,  __pd);			\
		check_stage_bit_access("test", # __bit, __pd);		\
		__ret;							\
	})

#else

static inline
void set_stage_bit(int bit, struct irq_stage_data *pd)
{
	__set_bit(bit, &pd->status);
}

static inline
void clear_stage_bit(int bit, struct irq_stage_data *pd)
{
	__clear_bit(bit, &pd->status);
}

static inline
int test_and_set_stage_bit(int bit, struct irq_stage_data *pd)
{
	return __test_and_set_bit(bit, &pd->status);
}

static inline
int __test_stage_bit(int bit, struct irq_stage_data *pd)
{
	return test_bit(bit, &pd->status);
}

static inline
int test_stage_bit(int bit, struct irq_stage_data *pd)
{
	return __test_stage_bit(bit, pd);
}

#endif /* !CONFIG_DEBUG_IRQ_PIPELINE */

static inline void irq_post_oob(unsigned int irq)
{
	irq_post_stage(&oob_stage, irq);
}

static inline void irq_post_inband(unsigned int irq)
{
	irq_post_stage(&inband_stage, irq);
}

static inline void oob_irq_disable(void)
{
	hard_local_irq_disable();
	set_stage_bit(STAGE_STALL_BIT, this_oob_staged());
}

static inline unsigned long oob_irq_save(void)
{
	hard_local_irq_disable();

	return test_and_set_stage_bit(STAGE_STALL_BIT, this_oob_staged());
}

static inline unsigned long oob_irqs_disabled(void)
{
	unsigned long flags, ret;

	/*
	 * Here we __must__ guard against CPU migration because we may
	 * be reading the oob stage data from the inband stage. In
	 * such a case, the oob stage on the destination CPU might be
	 * in a different (stalled) state than the oob stage is on the
	 * source one.
	 */
	flags = hard_smp_local_irq_save();
	ret = test_stage_bit(STAGE_STALL_BIT, this_oob_staged());
	hard_smp_local_irq_restore(flags);

	return ret;
}

void oob_irq_enable(void);

void __oob_irq_restore(unsigned long x);

static inline void oob_irq_restore(unsigned long x)
{
	if ((x ^ test_stage_bit(STAGE_STALL_BIT, this_oob_staged())) & 1)
		__oob_irq_restore(x);
}

bool stage_disabled(void);

unsigned long test_and_disable_stage(int *irqsoff);

static inline unsigned long disable_stage(void)
{
	return test_and_disable_stage(NULL);
}

void restore_stage(unsigned long combo);

#define stage_save_flags(__combo)					\
	do {								\
		(__combo) = irqs_merge_flags(hard_local_save_flags(),	\
					     irqs_disabled());		\
	} while (0)

int enable_oob_stage(const char *name);

int arch_enable_oob_stage(void);

void disable_oob_stage(void);

#else /* !CONFIG_IRQ_PIPELINE */

static inline bool running_inband(void)
{
	return true;
}

static inline bool running_oob(void)
{
	return false;
}

static inline bool oob_stage_present(void)
{
	return false;
}

static inline bool stage_disabled(void)
{
	return irqs_disabled();
}

#define test_and_disable_stage(__irqsoff)			\
	({							\
		unsigned long __flags;				\
		raw_local_irq_save(__flags);			\
		*(__irqsoff) = irqs_disabled_flags(__flags);	\
		__flags;					\
	})

#define disable_stage()				\
	({					\
		unsigned long __flags;		\
		raw_local_irq_save(__flags);	\
		__flags;			\
	})

#define restore_stage(__flags)	raw_local_irq_restore(__flags)

#define stage_save_flags(__flags)	raw_local_save_flags(__flags)

#endif /* !CONFIG_IRQ_PIPELINE */

#endif	/* !_LINUX_IRQSTAGE_H */
