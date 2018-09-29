/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Philippe Gerum  <rpm@xenomai.org>.
 */
#include <linux/dovetail.h>
#include <asm/fpsimd.h>

void arch_dovetail_context_resume(void)
{
	fpsimd_restore_current_oob();
}
