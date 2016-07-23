#ifndef _ASM_CLOCKSOURCE_H
#define _ASM_CLOCKSOURCE_H

enum arch_clock_uaccess_type {
	ARM_CLOCK_NONE = 0,
	ARM_CLOCK_ARCH_TIMER,

	ARM_CLOCK_USER_MMIO_BASE, /* Must remain last */
};

struct arch_clocksource_data {
	bool vdso_direct;	/* Usable for direct VDSO access? */
	enum arch_clock_uaccess_type clock_type;
};

#ifdef CONFIG_VDSO

#define arch_clocksource_arch_timer_init \
	arch_clocksource_arch_timer_init
void arch_clocksource_arch_timer_init(struct clocksource *cs);

#define arch_clocksource_user_mmio_init \
	arch_clocksource_user_mmio_init
void arch_clocksource_user_mmio_init(struct clocksource *cs, unsigned id);

#endif /* CONFIG_VDSO */

#endif
