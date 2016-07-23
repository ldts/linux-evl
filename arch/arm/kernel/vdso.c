/*
 * Adapted from arm64 version.
 *
 * Copyright (C) 2012 ARM Limited
 * Copyright (C) 2015 Mentor Graphics Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/cache.h>
#include <linux/elf.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/timekeeper_internal.h>
#include <linux/vmalloc.h>
#include <asm/arch_timer.h>
#include <asm/barrier.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/vdso.h>
#include <asm/vdso_datapage.h>
#include <clocksource/arm_arch_timer.h>

static struct page **vdso_text_pagelist;

extern char vdso_start[], vdso_end[];

/*
 * Total number of pages needed for the data, private and text
 * portions of the VDSO.
 */
unsigned int vdso_total_pages __ro_after_init;

/*
 * The VDSO data page.
 */
static union vdso_data_store vdso_data_store __page_aligned_data;
static struct vdso_data *vdso_data = &vdso_data_store.data;

static struct page *vdso_data_page __ro_after_init;
static const struct vm_special_mapping vdso_data_mapping = {
	.name = "[vvar]",
	.pages = &vdso_data_page,
};

static int vdso_mremap(const struct vm_special_mapping *sm,
		struct vm_area_struct *new_vma)
{
	unsigned long new_size = new_vma->vm_end - new_vma->vm_start;
	unsigned long vdso_size;

	/* without VVAR and VPRIV pages */
	vdso_size = (vdso_total_pages - 2) << PAGE_SHIFT;

	if (vdso_size != new_size)
		return -EINVAL;

	current->mm->context.vdso = new_vma->vm_start;

	return 0;
}

static struct vm_special_mapping vdso_text_mapping __ro_after_init = {
	.name = "[vdso]",
	.mremap = vdso_mremap,
};

static int __init vdso_init(void)
{
	unsigned int text_pages;
	int i;

	if (memcmp(vdso_start, "\177ELF", 4)) {
		pr_err("VDSO is not a valid ELF object!\n");
		return -ENOEXEC;
	}

	text_pages = (vdso_end - vdso_start) >> PAGE_SHIFT;
	pr_debug("vdso: %i text pages at base %p\n", text_pages, vdso_start);

	/* Allocate the VDSO text pagelist */
	vdso_text_pagelist = kcalloc(text_pages, sizeof(struct page *),
				     GFP_KERNEL);
	if (vdso_text_pagelist == NULL)
		return -ENOMEM;

	/* Grab the VDSO data page. */
	vdso_data_page = virt_to_page(vdso_data);

	/* Grab the VDSO text pages. */
	for (i = 0; i < text_pages; i++) {
		struct page *page;

		page = virt_to_page(vdso_start + i * PAGE_SIZE);
		vdso_text_pagelist[i] = page;
	}

	vdso_text_mapping.pages = vdso_text_pagelist;

	vdso_total_pages = 2; /* for the data/vvar and vpriv pages */
	vdso_total_pages += text_pages;

	vdso_data->cs_type_and_seq = ARM_CLOCK_NONE << 16 | 1;

	return 0;
}
arch_initcall(vdso_init);

static int install_vpriv(struct mm_struct *mm, unsigned long addr)
{
	return mmap_region(NULL, addr, PAGE_SIZE,
			  VM_READ | VM_WRITE | VM_MAYREAD | VM_MAYWRITE,
			   0, NULL) != addr ? -EINVAL : 0;
}

static int install_vvar(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma;

	vma = _install_special_mapping(mm, addr, PAGE_SIZE,
				       VM_READ | VM_MAYREAD,
				       &vdso_data_mapping);
	if (IS_ERR(vma))
		return PTR_ERR(vma);

	if (cache_is_vivt())
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return vma->vm_start != addr ? -EINVAL : 0;
}

/* assumes mmap_sem is write-locked */
void arm_install_vdso(struct mm_struct *mm, unsigned long addr)
{
	struct vm_area_struct *vma;
	unsigned long len;

	mm->context.vdso = 0;

	if (vdso_text_pagelist == NULL)
		return;

	if (install_vpriv(mm, addr)) {
		pr_err("cannot map VPRIV at expected address!\n");
		return;
	}

	/* Account for the private storage. */
	addr += PAGE_SIZE;
	if (install_vvar(mm, addr)) {
		WARN(1, "cannot map VVAR at expected address!\n");
		return;
	}

	/* Account for vvar and vpriv pages. */
	addr += PAGE_SIZE;
	len = (vdso_total_pages - 2) << PAGE_SHIFT;

	vma = _install_special_mapping(mm, addr, len,
		VM_READ | VM_EXEC | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC,
		&vdso_text_mapping);

	if (IS_ERR(vma) || vma->vm_start != addr)
		WARN(1, "cannot map VDSO at expected address!\n");
	else
		mm->context.vdso = addr;
}

static void vdso_write_begin(struct vdso_data *vdata)
{
	++vdso_data->seq_count;
	smp_wmb(); /* Pairs with smp_rmb in vdso_read_retry */
}

static void vdso_write_end(struct vdso_data *vdata)
{
	smp_wmb(); /* Pairs with smp_rmb in vdso_read_begin */
	++vdso_data->seq_count;
}

static const struct arch_clocksource_data *tk_get_cd(const struct timekeeper *tk)
{
	return &tk->tkr_mono.clock->archdata;
}

/**
 * update_vsyscall - update the vdso data page
 *
 * Increment the sequence counter, making it odd, indicating to
 * userspace that an update is in progress.  Update the fields used
 * for coarse clocks and, if the architected system timer is in use,
 * the fields used for high precision clocks.  Increment the sequence
 * counter again, making it even, indicating to userspace that the
 * update is finished.
 *
 * Userspace is expected to sample seq_count before reading any other
 * fields from the data page.  If seq_count is odd, userspace is
 * expected to wait until it becomes even.  After copying data from
 * the page, userspace must sample seq_count again; if it has changed
 * from its previous value, userspace must retry the whole sequence.
 *
 * Calls to update_vsyscall are serialized by the timekeeping core.
 */
void update_vsyscall(struct timekeeper *tk)
{
	struct timespec64 *wtm = &tk->wall_to_monotonic;
	const struct arch_clocksource_data *cd = tk_get_cd(tk);

	vdso_write_begin(vdso_data);

	if (cd->clock_type != (vdso_data->cs_type_and_seq >> 16)) {
		u32 type = cd->clock_type;
		u16 seq = vdso_data->cs_type_and_seq;

		if (++seq == 0)
			seq = 1;
		vdso_data->cs_type_and_seq	= type << 16 | seq;

		/*
		 * vdso does not have printf, so, prepare the device name for
		 * it.
		 */
		if (cd->clock_type >= ARM_CLOCK_USER_MMIO_BASE)
			snprintf(vdso_data->mmio_dev_name,
				sizeof(vdso_data->mmio_dev_name),
				"/dev/user_mmio_clksrc/%u",
				cd->clock_type - ARM_CLOCK_USER_MMIO_BASE);
	}

	vdso_data->xtime_coarse_sec		= tk->xtime_sec;
	vdso_data->xtime_coarse_nsec		= (u32)(tk->tkr_mono.xtime_nsec >>
							tk->tkr_mono.shift);
	vdso_data->wtm_clock_sec		= wtm->tv_sec;
	vdso_data->wtm_clock_nsec		= wtm->tv_nsec;

	if (cd->clock_type != ARM_CLOCK_NONE) {
		vdso_data->cs_cycle_last	= tk->tkr_mono.cycle_last;
		vdso_data->xtime_clock_sec	= tk->xtime_sec;
		vdso_data->xtime_clock_snsec	= tk->tkr_mono.xtime_nsec;
		vdso_data->cs_mult		= tk->tkr_mono.mult;
		vdso_data->cs_shift		= tk->tkr_mono.shift;
		vdso_data->cs_mask		= tk->tkr_mono.mask;
	}

	vdso_write_end(vdso_data);

	flush_dcache_page(virt_to_page(vdso_data));
}

void update_vsyscall_tz(void)
{
	vdso_data->tz_minuteswest	= sys_tz.tz_minuteswest;
	vdso_data->tz_dsttime		= sys_tz.tz_dsttime;
	flush_dcache_page(virt_to_page(vdso_data));
}

void arch_clocksource_user_mmio_init(struct clocksource *cs, unsigned id)
{
	struct arch_clocksource_data *d = &cs->archdata;

	d->clock_type = ARM_CLOCK_USER_MMIO_BASE + id;
}

void arch_clocksource_arch_timer_init(struct clocksource *cs)
{
	struct arch_clocksource_data *d = &cs->archdata;

	d->clock_type = ARM_CLOCK_ARCH_TIMER;
}
