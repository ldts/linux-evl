/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018 Philippe Gerum  <rpm@xenomai.org>.
 */
#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/irq_pipeline.h>

/* irq_nesting tracks the interrupt nesting level for a CPU. */
DEFINE_PER_CPU(int, irq_nesting);

#ifdef CONFIG_SMP

static struct irq_domain *sipic_domain;

static void sipic_irq_noop(struct irq_data *data) { }

static unsigned int sipic_irq_noop_ret(struct irq_data *data)
{
	return 0;
}

static struct irq_chip sipic_chip = {
	.name		= "SIPIC",
	.irq_startup	= sipic_irq_noop_ret,
	.irq_shutdown	= sipic_irq_noop,
	.irq_enable	= sipic_irq_noop,
	.irq_disable	= sipic_irq_noop,
	.irq_ack	= sipic_irq_noop,
	.irq_mask	= sipic_irq_noop,
	.irq_unmask	= sipic_irq_noop,
	.flags		= IRQCHIP_PIPELINE_SAFE | IRQCHIP_SKIP_SET_WAKE,
};

static int sipic_irq_map(struct irq_domain *d, unsigned int irq,
			irq_hw_number_t hwirq)
{
	irq_set_percpu_devid(irq);
	irq_set_chip_and_handler(irq, &sipic_chip, handle_synthetic_irq);

	return 0;
}

static struct irq_domain_ops sipic_domain_ops = {
	.map	= sipic_irq_map,
};

static void create_ipi_domain(void)
{
	/*
	 * Create an IRQ domain for mapping all IPIs (in-band and
	 * out-of-band), with fixed sirq numbers starting from
	 * OOB_IPI_BASE. The sirqs obtained can be injected into the
	 * pipeline upon IPI receipt like other interrupts.
	 */
	sipic_domain = irq_domain_add_simple(NULL, NR_IPI + OOB_NR_IPI,
					     OOB_IPI_BASE,
					     &sipic_domain_ops, NULL);
}

void irq_pipeline_send_remote(unsigned int ipi,
			      const struct cpumask *cpumask)
{
	unsigned int ipinr = ipi - OOB_IPI_BASE;
	smp_cross_call(cpumask, ipinr);
}
EXPORT_SYMBOL_GPL(irq_pipeline_send_remote);

#endif	/* CONFIG_SMP */

void __init arch_irq_pipeline_init(void)
{
#ifdef CONFIG_SMP
	create_ipi_domain();
#endif
}

void arch_do_IRQ_pipelined(struct irq_desc *desc)
{
	struct pt_regs *regs = raw_cpu_ptr(&irq_pipeline.tick_regs);
	unsigned int irq = irq_desc_get_irq(desc);

#ifdef CONFIG_SMP
	/*
	 * Check for IPIs, handing them over to the specific dispatch
	 * code.
	 */
	if (irq >= OOB_IPI_BASE &&
	    irq < OOB_IPI_BASE + NR_IPI + OOB_NR_IPI) {
		__handle_IPI(irq - OOB_IPI_BASE, regs);
		return;
	}
#endif

	do_domain_irq(irq, regs);
}
