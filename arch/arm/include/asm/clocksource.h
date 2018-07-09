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

#endif
