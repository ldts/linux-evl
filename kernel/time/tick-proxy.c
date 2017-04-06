/*
 * SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017 Philippe Gerum  <rpm@xenomai.org>.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/cpumask.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irq_pipeline.h>
#include <linux/stop_machine.h>
#include <linux/slab.h>
#include "tick-internal.h"

struct proxy_tick_device {
	struct clock_event_device *real_device;
	struct clock_event_device proxy_device;
	void (*original_event_handler)(struct clock_event_device *ced);
};

static unsigned int proxy_tick_irq;

static DEFINE_PER_CPU(struct proxy_tick_device, proxy_tick_device);

static inline struct clock_event_device *get_real_tick_device(void)
{
	return raw_cpu_ptr(&proxy_tick_device)->real_device;
}

static inline struct clock_event_device *get_proxy_tick_device(void)
{
	return &raw_cpu_ptr(&proxy_tick_device)->proxy_device;
}

static void proxy_event_handler(struct clock_event_device *real_ced)
{
	struct proxy_tick_device *ptd = this_cpu_ptr(&proxy_tick_device);
	struct clock_event_device *ced = &ptd->proxy_device;

	ced->event_handler(ced);
}

static int proxy_set_oneshot(struct clock_event_device *ced)
{
	struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_ced->set_state_oneshot(real_ced);
	hard_local_irq_restore(flags);

	return ret;
}

static int proxy_set_periodic(struct clock_event_device *ced)
{
	struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_ced->set_state_periodic(real_ced);
	hard_local_irq_restore(flags);

	return ret;
}

static int proxy_set_oneshot_stopped(struct clock_event_device *ced)
{
        struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_ced->set_state_oneshot_stopped(real_ced);
	hard_local_irq_restore(flags);

	return ret;
}

static int proxy_shutdown(struct clock_event_device *ced)
{
        struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_ced->set_state_shutdown(real_ced);
	hard_local_irq_restore(flags);

	return ret;
}

static void proxy_suspend(struct clock_event_device *ced)
{
        struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;

	flags = hard_local_irq_save();
	real_ced->suspend(real_ced);
	hard_local_irq_restore(flags);
}

static void proxy_resume(struct clock_event_device *ced)
{
        struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;

	flags = hard_local_irq_save();
	real_ced->resume(real_ced);
	hard_local_irq_restore(flags);
}

static int proxy_tick_resume(struct clock_event_device *ced)
{
        struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_ced->tick_resume(real_ced);
	hard_local_irq_restore(flags);

	return ret;
}

static int proxy_set_next_event(unsigned long delay,
				struct clock_event_device *ced)
{
	struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_ced->set_next_event(delay, real_ced);
	hard_local_irq_restore(flags);

	return ret;
}

static int proxy_set_next_ktime(ktime_t expires,
				struct clock_event_device *ced)
{
	struct clock_event_device *real_ced = get_real_tick_device();
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_ced->set_next_ktime(expires, real_ced);
	hard_local_irq_restore(flags);

	return ret;
}

static irqreturn_t proxy_irq_handler(int sirq, void *dev_id)
{
	struct clock_event_device *evt;

	/*
	 * Tricky: we may end up running this in-band IRQ handler
	 * because tick_notify_proxy() was posted either:
	 *
	 * - by the co-kernel from ops->handle_event() for emulating a
	 * regular kernel tick, if the clock chip device on the local
	 * CPU is managed in out-of-band mode (i.e. a proxy device was
	 * fully enabled on the receiving CPU).  In this case, the
	 * active tick device for the regular timing core is the proxy
	 * device, whose event handler is identical to the real tick
	 * device's.
	 *
	 * - or directly by the clock chip driver on the local CPU via
	 * clockevents_handle_event(), for propagating a tick to the
	 * regular kernel nobody from the oob stage is interested on
	 * i.e. no proxy device was registered on the receiving CPU,
	 * which was excluded from @cpumask in the call to
	 * tick_install_proxy(). In this case, the active tick device
	 * for the regular timing core is a real clock event device.
	 *
	 * In both cases, we are running on the in-band stage, and we
	 * should fire the event handler of the currently active tick
	 * device for the regular timing core.
	 */
	evt = raw_cpu_ptr(&tick_cpu_device)->evtdev;
	evt->event_handler(evt);

	return IRQ_HANDLED;
}

static void register_proxy_device(void *arg) /* irqs_disabled() */
{
	struct clock_event_device *proxy_ced, *real_ced;
	const struct proxy_tick_ops *ops = arg;
	struct proxy_tick_device *ptd;
	int cpu = smp_processor_id();

	real_ced = raw_cpu_ptr(&tick_cpu_device)->evtdev;
	proxy_ced = get_proxy_tick_device();

	/* Setup the percpu proxy device slots. */
	ptd = this_cpu_ptr(&proxy_tick_device);
	ptd->original_event_handler = real_ced->event_handler;
	ptd->real_device = real_ced;

	/*
	 * Install a proxy clock event device on this CPU.  The proxy
	 * device has the same characteristics as the real one
	 * (esp. CLOCK_EVT_FEAT_C3STOP if present!), except the
	 * broadcast capability SIRQs don't support, so add
	 * CLOCK_EVT_FEAT_PERCPU.
	 */
	proxy_ced->features = real_ced->features | CLOCK_EVT_FEAT_PERCPU;
	proxy_ced->name = "proxy";
	proxy_ced->irq = real_ced->irq;
	proxy_ced->cpumask = cpumask_of(cpu);
	proxy_ced->rating = real_ced->rating;
	proxy_ced->mult = real_ced->mult;
	proxy_ced->shift = real_ced->shift;
	proxy_ced->max_delta_ticks = real_ced->max_delta_ticks;
	proxy_ced->min_delta_ticks = real_ced->min_delta_ticks;
	proxy_ced->max_delta_ns = real_ced->max_delta_ns;
	proxy_ced->min_delta_ns = real_ced->min_delta_ns;
	/*
	 * Interpose default handlers which are safe wrt preemption by
	 * the oob stage.
	 */
	proxy_ced->set_state_oneshot = NULL;
	if (real_ced->set_state_oneshot)
		proxy_ced->set_state_oneshot = proxy_set_oneshot;
	proxy_ced->set_state_periodic = NULL;
	if (real_ced->set_state_periodic)
		proxy_ced->set_state_periodic = proxy_set_periodic;
	proxy_ced->set_state_oneshot_stopped = NULL;
	if (real_ced->set_state_oneshot_stopped)
		proxy_ced->set_state_oneshot_stopped = proxy_set_oneshot_stopped;
	proxy_ced->suspend = NULL;
	if (real_ced->suspend)
		proxy_ced->suspend = proxy_suspend;
	proxy_ced->resume = NULL;
	if (real_ced->resume)
		proxy_ced->resume = proxy_resume;
	proxy_ced->tick_resume = NULL;
	if (real_ced->tick_resume)
		proxy_ced->tick_resume = proxy_tick_resume;
	proxy_ced->set_next_event = NULL;
	if (real_ced->set_next_event)
		proxy_ced->set_next_event = proxy_set_next_event;
	proxy_ced->set_next_ktime = NULL;
	if (real_ced->set_next_ktime)
		proxy_ced->set_next_ktime = proxy_set_next_ktime;
	proxy_ced->set_state_shutdown = NULL;
	if (real_ced->set_state_shutdown)
		proxy_ced->set_state_shutdown = proxy_shutdown;
	/*
	 * ops->register_device() must fill in the
	 * set_next_event/set_next_ktime() handler and the rating of
	 * the proxy device, before proceeding to its registration on
	 * the clockevent framework. The features bits may be altered
	 * for the purpose of adding CLOCK_EVT_FEAT_KTIME if
	 * set_next_ktime() is preferred over set_next_event().
	 */
	ops->register_device(proxy_ced, real_ced);

	/*
	 * If the proxy replaced the current (real) tick device, we
	 * have two issues to handle:
	 *
	 * 1. the event handler of the real device was nop'ed during
	 * the transition.  We need to restore a valid handler for
	 * routing ticks to the regular timer core as if they came
	 * from the proxy device, until the timer IRQ is switched to
	 * out-of-band mode. Once this happens, ticks are routed to
	 * the overlay handler instead.
	 *
	 * 2. the clock event layer decides to transition the device
	 * overlaid by the proxy from detached->shutdown, which makes
	 * it unusable anew (see clockevent_replace) when the proxy is
	 * unbound.
	 *
	 * This might happen as follows:
	 *
	 * - proxy is registered on CPUx from ->register_device()
	 *   - real device is released, set to detached state
	 *     - tick notifier runs on released devices
	 *       - real device is picked for bc, old bc is released
	 *         - real device is installed, set to shutdown state
	 * ...
	 *
	 * 1. now that we have the real device switched to a shutdown
	 *    state, the clockchip handler may have turned off the
	 *    hardware.
	 *
	 * 2. if/when the proxy is unregistered from CPUx, the real
	 *    device is not considered as it is not in detached state
	 *    (clockevent_replace), so the dummy device is picked
	 *    instead.
	 *
	 * In both cases, the CPU gets no tick anymore. What we need
	 * to do to fix the situation is two-fold:
	 *
	 * - switch the real device back to detached state.
	 *
	 * - trigger a tick immediately on the proxy device, which
	 *   causes the real device's set_next_event() handler to be
	 *   called, turning it on again before scheduling the event.
	 */
	if (raw_cpu_ptr(&tick_cpu_device)->evtdev == proxy_ced) {
		real_ced->event_handler = proxy_event_handler;
		clockevents_switch_state(real_ced, CLOCK_EVT_STATE_DETACHED);
		if (clockevent_state_oneshot(proxy_ced))
			clockevents_program_event(proxy_ced, ktime_get(), true);
	}
}

static int enable_oob_timer(void *arg) /* hard_irqs_disabled() */
{
	const struct proxy_tick_ops *ops = arg;
	struct clock_event_device *real_ced;

	/*
	 * Install the overlay handler on this CPU's real clock
	 * device, then turn on out-of-band mode for the associated
	 * IRQ (duplicates are silently ignored if the IRQ is common
	 * to multiple CPUs).
	 */
	real_ced = get_real_tick_device();
	if (WARN_ON(real_ced == NULL))
		return -ENODEV;

	real_ced->event_handler = ops->handle_event;
	real_ced->features |= CLOCK_EVT_FEAT_OOB;
	barrier();

	/*
	 * irq_switch_oob() grabs the IRQ descriptor lock which is
	 * mutable, so that is fine to invoke this routine with hard
	 * IRQs off.
	 */
	irq_switch_oob(real_ced->irq, true);

	return 0;
}

int tick_install_proxy(struct proxy_tick_ops *ops,
		       const struct cpumask *cpumask)
{
	struct clock_event_device *real_ced;
	int ret, cpu, sirq;

	cpus_read_lock();

	for_each_cpu(cpu, cpumask) {
		real_ced = per_cpu(tick_cpu_device, cpu).evtdev;
		ret = -EINVAL;
		if (real_ced == NULL) {
			WARN(1, "no clockevent device on CPU%d!", cpu);
			goto fail;
		}
		if ((real_ced->features &
		     (CLOCK_EVT_FEAT_PIPELINE|CLOCK_EVT_FEAT_ONESHOT))
		    != (CLOCK_EVT_FEAT_PIPELINE|CLOCK_EVT_FEAT_ONESHOT)) {
			WARN(1, "cannot use clockevent device %s in pipelined mode!",
			     real_ced->name);
			goto fail;
		}
	}

	sirq = irq_create_direct_mapping(synthetic_irq_domain);
	if (WARN_ON(sirq == 0)) {
		ret = -EAGAIN;
		goto fail;
	}

	ret = __request_percpu_irq(sirq, proxy_irq_handler,
				   IRQF_NO_THREAD, /* no IRQF_TIMER here. */
				   "proxy tick",
				   &proxy_tick_device);
	if (WARN_ON(ret)) {
		irq_dispose_mapping(sirq);
		goto fail;
	}

	proxy_tick_irq = sirq;
	barrier();

	/*
	 * Install a proxy tick device on each CPU. As the proxy
	 * device is picked, the previous (real) tick device is shut
	 * down by the clockevent core.  Immediately after, the proxy
	 * device starts controlling the real device under the hood to
	 * carry out timing requests from the co-kernel.  From that
	 * point, the co-kernel is also in charge of emulating host
	 * ticks, as requested by the host kernel through calls to the
	 * ->set_next_event()/set_next_ktime() handler of the proxy
	 * device.
	 *
	 * For a short period of time, after the proxy device is
	 * installed, and until the real device IRQ is switched to
	 * pipelined mode, the flow is as follows:
	 *
	 *    [kernel timing request]
	 *        proxy_dev->set_next_event(proxy_dev)
	 *            overlay_program_event(proxy_dev)
	 *                original_clockevent_set_next_event(real_dev)
	 *        ...
	 *        <tick event>
	 *        original_timer_handler() [ROOT STAGE]
	 *            clockevents_handle_event(real_dev)
	 *               proxy_event_handler(real_dev)
	 *                  original_clockevent_handler(proxy_dev)
	 *
	 * Eventually, we substitute the original clock event handler
	 * with the overlay handler for the real clock event device,
	 * then turn on out-of-band mode for the timer IRQ associated
	 * to the latter. The last two steps are performed over a
	 * stop_machine() context, so that no tick can race with this
	 * code while we swap handlers.
	 *
	 * Once the hand over is complete, the flow is as follows:
	 *
	 *    [kernel timing request]
	 *        proxy_dev->set_next_event(proxy_dev)
	 *            overlay_program_event(proxy_dev)
	 *                original_clockevent_set_next_event(real_dev)
	 *        ...
	 *        <tick event>
	 *        original_timer_handler() [HEAD STAGE]
	 *            clockevents_handle_event(real_dev)
	 *                overlay_handle_event(proxy_dev)
	 *                    ...(host tick emulation)...
	 *                    tick_kick_proxy()
	 *        ...
	 *        proxy_irq_handler(proxy_dev) [ROOT stage]
	 *            clockevents_handle_event(proxy_dev)
	 *                original_clockevent_handler(proxy_dev)
	 */

	on_each_cpu_mask(cpumask, register_proxy_device, ops, true);

	cpus_read_unlock();

	/*
	 * Start ticking from the oob interrupt stage via out-of-band
	 * events.
	 */
	stop_machine(enable_oob_timer, ops, cpumask);

	return 0;
fail:
	cpus_read_unlock();

	return ret;
}
EXPORT_SYMBOL_GPL(tick_install_proxy);

static void unregister_proxy_device(void *arg) /* irqs_disabled() */
{
	struct clock_event_device *real_ced, *proxy_ced;
	const struct proxy_tick_ops *ops = arg;
	struct proxy_tick_device *ptd;

	ptd = raw_cpu_ptr(&proxy_tick_device);
	real_ced = ptd->real_device;
	ptd->real_device = NULL;

	if (ops->unregister_device) {
		proxy_ced = &ptd->proxy_device;
		ops->unregister_device(proxy_ced, real_ced);
	}
}

static int disable_oob_timer(void *arg) /* hard_irqs_disabled() */
{
	struct clock_event_device *real_ced, *proxy_ced;
	struct proxy_tick_device *ptd;

	ptd = raw_cpu_ptr(&proxy_tick_device);
	real_ced = ptd->real_device;
	if (real_ced == NULL)
		return 0;

	real_ced->event_handler = ptd->original_event_handler;
	real_ced->features &= ~CLOCK_EVT_FEAT_OOB;
	barrier();
	proxy_ced = get_proxy_tick_device();
	proxy_ced->set_next_event = real_ced->set_next_event;
	irq_switch_oob(real_ced->irq, false);

	return 0;
}

void tick_uninstall_proxy(struct proxy_tick_ops *ops,
			  const struct cpumask *cpumask)
{
	struct clock_event_device *proxy_ced;
	struct proxy_tick_device *ptd;
	int cpu;

	/*
	 * Undo all we did in tick_install_proxy(), handing over
	 * control of the tick device back to the host kernel, then
	 * removing the proxy device on each CPU.
	 */
	stop_machine(disable_oob_timer, NULL, cpu_online_mask);

	cpus_read_lock();

	for_each_cpu(cpu, cpumask) {
		ptd = &per_cpu(proxy_tick_device, cpu);
		proxy_ced = &ptd->proxy_device;
		if (!clockevent_state_detached(proxy_ced))
			clockevents_unbind_device(proxy_ced, cpu);
	}

	on_each_cpu_mask(cpumask, unregister_proxy_device, ops, true);

	cpus_read_unlock();

	/*
	 * Remove the synthetic IRQ we used for emulating ticks from
	 * the proxy device.
	 */
	free_percpu_irq(proxy_tick_irq, &proxy_tick_device);
	irq_dispose_mapping(proxy_tick_irq);
}
EXPORT_SYMBOL_GPL(tick_uninstall_proxy);

void tick_notify_proxy(void)
{
	/*
	 * Schedule a tick on the proxy device to occur from the
	 * in-band stage, which will trigger proxy_irq_handler() at
	 * some point (i.e. when the in-band stage is back in control
	 * and not stalled).
	 */
	irq_post_inband(proxy_tick_irq);
}
EXPORT_SYMBOL_GPL(tick_notify_proxy);
