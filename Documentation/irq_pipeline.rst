.. include:: <isonum.txt>

====================
Interrupt pipelining
====================

:Copyright: |copy| 2016-2018: Philippe Gerum

Purpose
=======

To protect from deadlocks and maintain data integrity, Linux hard
disables interrupts around any critical section of code which must not
be preempted by interrupt handlers on the same CPU, enforcing a
strictly serialized execution among those contexts.

The unpredictable delay this may cause before external events can be
handled is a major roadblock for kernel components requiring
predictable and very short response times to external events, in the
range of a few microseconds.

To address this issue, a mechanism called *interrupt pipelining* turns
all device IRQs into pseudo-NMIs, only to run NMI-safe interrupt
handlers from the perspective of the regular kernel activities.

Two-stage IRQ pipeline
======================

Interrupt pipelining is a lightweight approach based on the
introduction of a separate, high-priority execution stage for running
out-of-band interrupt handlers immediately upon IRQ receipt, which
cannot be delayed by the in-band, regular kernel work even if the
latter serializes the execution by - seemingly - disabling interrupts.

IRQs which have no handlers in the high priority stage may be deferred
on the receiving CPU until the out-of-band activity has quiesced on
that CPU. Eventually, the preempted in-band code can resume normally,
which may involve handling the deferred interrupts.

In other words, interrupts are flowing down from the out-of-band to
the in-band interrupt stages, which form a two-stage pipeline for
prioritizing interrupt delivery.

The runtime context of the out-of-band interrupt handlers is known as
the *oob stage* of the pipeline, as opposed to the in-band kernel
activities sitting on the *inband stage*::

                    Out-of-band                 In-band
                    IRQ handlers()            IRQ handlers()
               __________   _______________________   ______
                  .     /  /  .             .     /  /  .
                  .    /  /   .             .    /  /   .
                  .   /  /    .             .   /  /    .
                  ___/  /______________________/  /     .
     [IRQ] -----> _______________________________/      .
                  .           .             .           .
                  .   OOB     .             .   In-band .
                  .   Stage   .             .   Stage   .
               _____________________________________________


A software core can base its own activities on the oob stage,
interposing on specific IRQ events, for delivering real-time
capabilities to a particular set of applications. Meanwhile, the
regular kernel operations keep going over the in-band stage
unaffected, only delayed by short preemption times for running the
out-of-band work.  A generic interface for coupling such a real-time
core to the kernel is described in the
:ref:`Documentation/dovetail.rst <Dovetail>`) document.

.. NOTE:: Interrupt pipelining is a partial implementation of [#f2]_,
          in which an interrupt *stage* is a limited form of an
          operating system *domain*.

Virtual interrupt flag
----------------------

.. _flag:
As hinted earlier, predictable response time of out-of-band handlers
to IRQ receipts requires the in-band kernel work not to be allowed to
delay them by masking interrupts in the CPU.

However, critical sections delimited this way by the in-band code must
still be enforced for the *in-band stage*, so that system integrity is
not at risk. This means that although out-of-band IRQ handlers may run
at any time while the *oob stage* is accepting interrupts, in-band IRQ
handlers should be allowed to run only when the in-band stage is
accepting interrupts too.

So we need to decouple the interrupt masking and delivery logic which
applies to the oob stage from the one in effect on the in-band stage,
by implementing a dual interrupt control.

To this end, a software logic managing a virtual interrupt disable
flag is introduced by the interrupt pipeline between the hardware and
the generic IRQ management layer. This logic can mask IRQs from the
perspective of the regular kernel work when :c:func:`local_irq_save`,
:c:func:`local_irq_disable` or any lock-controlled masking operations
like :c:func:`spin_lock_irqsave` is called, while still accepting IRQs
from the CPU for immediate delivery to out-of-band handlers.

The oob stage protects from interrupts by disabling them in the CPU's
status register, while the in-band stage disables interrupts only
virtually. A stage for which interrupts are disabled is said to be
*stalled*. Conversely, *unstalling* a stage means re-enabling
interrupts for it.

Obviously, stalling the oob stage implicitly means disabling
further IRQ receipts for the in-band stage too.

Interrupt deferral for the *in-band stage*
---------------------------------------

.. _deferral:
.. _deferred:
When the in-band stage is stalled because the virtual interrupt disable
flag is set, any IRQ event which was not immediately delivered to the
*oob stage* is recorded into a per-CPU log, postponing delivery to
the regular kernel handler.

Such delivery is deferred until the in-band kernel code clears the
virtual interrupt disable flag by calling :c:func:`local_irq_enable`
or any of its variants, which unstalls the in-band stage. When this
happens, the interrupt state is resynchronized by playing the log,
firing the in-band handlers for which an IRQ event is pending.

::
   /* Both stages unstalled on entry */
   local_irq_save(flags);
   <IRQx received: no out-of-band handler>
       (pipeline logs IRQx event)
   ...
   local_irq_restore(flags);
       (pipeline plays IRQx event)
            handle_IRQx_interrupt();

If the in-band stage is unstalled at the time of the IRQ receipt, the
in-band handler is immediately invoked, just like with the
non-pipelined IRQ model.

.. NOTE:: The principle of deferring interrupt delivery based on a
          software flag coupled to an event log has been originally
          described as "Optimistic interrupt protection" in [#f1]_.

Device interrupts virtually turned into NMIs
--------------------------------------------

From the standpoint of the in-band kernel code (i.e. the one running
over the *in-band* interrupt stage) , the interrupt pipelining logic
virtually turns all device IRQs into NMIs, for running out-of-band
handlers.

.. _re-entry:
For this reason, out-of-band code may generally **NOT** re-enter
in-band code, for preventing creepy situations like this one::

   /* in-band context */
   spin_lock_irqsave(&lock, flags);
      <IRQx received: out-of-band handler installed>
         handle_oob_event();
            /* attempted re-entry to in-band from out-of-band. */
            in_band_routine();
               spin_lock_irqsave(&lock, flags);
               <DEADLOCK>
               ...
            ...
         ...
   ...
   spin_unlock irqrestore(&lock, flags);

Even in absence of an attempt to get a spinlock recursively, the outer
in-band code in the example above is entitled to assume that no access
race can occur on the current CPU while interrupts are
masked. Re-entering in-band code from an out-of-band handler would
invalidate this assumption.

In rare cases, we may need to fix up the in-band kernel routines in
order to allow out-of-band handlers to call them. Typically, atomic_
helpers are such routines, which serialize in-band and out-of-band
callers.

Synthetic interrupt vectors
---------------------------

.. _synthetic:
The pipeline introduces an additional type of interrupts, which are
purely software-originated, with no hardware involvement. These IRQs
can be triggered by any kernel code. Synthetic IRQs are inherently
per-CPU events.

Because the common pipeline flow_ applies to synthetic interrupts, it
is possible to attach them to out-of-band and/or in-band handlers,
just like device interrupts.

.. NOTE:: synthetic interrupts and regular softirqs differ in essence:
          the latter only exist in the in-band context, and therefore
          cannot trigger out-of-band activities.

Synthetic interrupt vectors are allocated from the
*synthetic_irq_domain*, using the :c:func:`irq_create_direct_mapping`
routine.

For instance, a synthetic interrupt can be used for triggering an
in-band activity on the in-band stage from the oob stage as follows::

  #include <linux/irq_pipeline.h>

  static irqreturn_t sirq_handler(int sirq, void *dev_id)
  {
        do_in_band_work();

        return IRQ_HANDLED;
  }

  static struct irqaction sirq_action = {
        .handler = sirq_handler,
        .name = "In-band synthetic interrupt",
        .flags = IRQF_NO_THREAD,
  };

  unsigned int alloc_sirq(void)
  {
	unsigned int sirq;

	sirq = irq_create_direct_mapping(synthetic_irq_domain);
	if (!sirq)
		return 0;

	setup_percpu_irq(sirq, &sirq_action);

	return sirq;
  }

Code can schedule the execution of :c:func:`sirq_handler` like this::

  irq_inject_pipeline(sirq);

or, via a lightweight injection method requiring hard IRQs to be
disabled::

  unsigned long flags = hard_local_irqsave();
  irq_post_inband(sirq);
  hard_local_irqrestore(flags);

Conversely, a synthetic interrupt can be handled from the out-of-band
context::

  static irqreturn_t sirq_oob_handler(int sirq, void *dev_id)
  {
        do_out_of_band_work();

        return IRQ_HANDLED;
  }

  unsigned int alloc_sirq(void)
  {
	unsigned int sirq;

	sirq  = irq_create_direct_mapping(synthetic_irq_domain);
	if (!sirq)
		return 0;

	ret = __request_percpu_irq(sirq, sirq_oob_handler,
                                   IRQF_OOB,
                                   "Out-of-band synthetic interrupt",
                                   dev_id);
	if (ret) {
		irq_dispose_mapping(sirq);
		return 0;
	}

	return sirq;
  }

Code can trigger the immediate execution of :c:func:`sirq_oob_handler`
on the oob stage as follows::

  irq_inject_pipeline(sirq);

Pipelined interrupt flow
------------------------

.. _flow:
When interrupt pipelining is enabled, IRQs are first delivered to
the pipeline entry point via a call to
:c:func:`generic_pipeline_irq`::

    asm_irq_entry
       -> irqchip_handle_irq()
          -> handle_domain_irq()
             -> generic_pipeline_irq()
                -> irq_flow_handler()
                <IRQ delivery logic>

Contrary to the non-pipelined model, the generic IRQ flow handler does
*not* call the in-band interrupt handler immediately, but only runs
the irqchip-specific handler for acknowledging the incoming IRQ event
in the interrupt controller, before running out-of-band handlers for
that event if any.

In absence of out-of-band handler for the event, the device may keep
asserting the interrupt signal until the cause has been lifted in its
own registers. For this reason, the flow handlers as modified by the
pipeline code may have to to mask the interrupt line until the in-band
handler has run from the in-band stage, lifting the interrupt cause. This
typically happens with level-triggered interrupts. This addresses the
following scenario, which happens for a similar reason while an IRQ
thread waits for being scheduled in, requiring the same kind of
provision::

    /* in-band stage stalled on entry */
    asm_irq_entry
       ...
          -> generic_pipeline_irq()
             ...
                <IRQ logged, delivery deferred>
    asm_irq_exit
    /*
     * CPU allowed to accept interrupts again with IRQ cause not
     * acknowledged in device yet => **IRQ storm**.
     */
    asm_irq_entry
       ...
    asm_irq_exit
    asm_irq_entry
       ...
    asm_irq_exit

Since all of the IRQ handlers sharing an interrupt line are either
in-band or out-of-band in a mutually exclusive way, such masking
cannot delay out-of-band events.

Prerequisites
=============

The interrupt pipeline requires the following features to be available
from the target kernel:

- Generic IRQ handling
- IRQ domains
- Clock event abstraction

Implementation
==============

The following kernel areas are involved in interrupt pipelining:

- Generic IRQ core

  * IRQ descriptor management.

    The driver API to the IRQ subsystem exposes the new interrupt type
    flag `IRQF_OOB`, denoting an out-of-band handler with the
    :c:func:`setup_irq`, :c:func:`request_irq`, and
    :c:func:`__request_percpu_irq` routines.

    Support for IRQ domains is a prerequisite for interrupt
    pipelining. :c:func:`handle_domain_irq` from the IRQ domain
    interface redirects the interrupt flow to the pipeline entry,
    represented by the :c:func:`generic_pipeline_irq`
    routine.

  * IRQ flow handlers

    Generic flow handlers acknowledge the incoming IRQ event in the
    hardware as usual, by calling the appropriate irqchip routine
    (e.g. :c:func:`irq_ack`, :c:func:`irq_eoi`). However, the flow_
    handlers do not immediately invoke the in-band interrupt
    handlers. Instead, they hand the event over to the pipeline core
    by calling :c:func:`handle_oob_irq`.

    If an out-of-band handler exists for the interrupt received,
    :c:func:`handle_oob_irq` invokes it immediately, after switching
    the execution context to the oob stage if not current yet.

    Otherwise, if the execution context is currently over the in-band
    stage and unstalled, the pipeline core delivers it immediately to
    the in-band handler. In all other cases, the interrupt is
    deferred, marked as pending into the current CPU's event log, then
    the IRQ frame is left.

  * IRQ work

    .. _irq_work:
    With interrupt pipelining, a code running over the oob stage
    could have preempted the in-band stage in the middle of a critical
    section. For this reason, it would be unsafe to call any
    in-band routine from an out-of-band context.

    Triggering in-band work handlers from out-of-band code can be done
    by using :c:func:`irq_work_queue`. The work request issued from
    the oob stage will be scheduled for running over the in-band
    stage.

    .. NOTE:: the interrupt pipeline forces the use of a synthetic_
              IRQ as a notification signal for the IRQ work machinery,
              instead of a hardware-specific interrupt vector.

  * IRQ pipeline core

- Arch-specific bits

  * CPU interrupt mask handling

    The architecture-specific code which manipulates the interrupt
    flag in the CPU's state register
    (i.e. arch/<arch>/include/asm/irqflags.h) is split between real
    and virtual interrupt control:

    + the *native_* level helpers affect the hardware state in the CPU.

    + the *arch_* level helpers affect the virtual interrupt disable
      flag_ implemented by the pipeline core for controlling the in-band
      stage protection against interrupts.

    This means that generic helpers from <linux/irqflags.h> such as
    :c:func:`local_irq_disable` and :c:func:`local_irq_enable`
    actually refer to the virtual protection scheme when interrupts
    are pipelined, implementing interrupt deferral_ for the protected
    in-band code running over the in-band stage.

  * Assembly-level IRQ, exception paths

    Since interrupts are only virtually masked for the in-band code,
    IRQs can still be taken by the CPU although they should not be
    visible from the in-band stage when they happen in the following
    situations:

    + when the virtual protection flag_ is raised, meaning the in-band
      stage does not accept IRQs, in which case interrupt _deferral
      happens.

    + when the CPU runs out-of-band code, regardless of the state of
      the virtual protection flag.

    In both cases, the low-level assembly code handling incoming IRQs
    takes a fast exit path unwinding the interrupt frame early,
    instead of running the common in-band epilogue which checks for
    task rescheduling opportunities and pending signals.

    Likewise, the low-level fault/exception handling code also takes a
    fast exit path under the same circumstances. Typically, an
    out-of-band handler causing a minor page fault should benefit from
    a lightweight PTE fixup performed by the high-level fault handler,
    but is not allowed to traverse the rescheduling logic upon return
    from exception.

- Scheduler core

  * CPUIDLE support

    The logic of the CPUIDLE framework has to account for those
    specific issues the interrupt pipelining introduces:

    - the kernel might be idle in the sense that no in-band activity
    is scheduled yet, and planning to shut down the timer device
    suffering the C3STOP (mis)feature.  However, at the same time,
    some out-of-band code might wait for a tick event already
    programmed in the timer hardware they both share via the proxy_
    clock event device.

    - switching the CPU to a power saving state may incur a
    significant latency, particularly for waking it up before it can
    handle an incoming IRQ, which is at odds with the purpose of
    interrupt pipelining.

    Obviously, we don't want the CPUIDLE logic to turn off the
    hardware timer when C3STOP is in effect for the timer device,
    which would cause the pending out-of-band event to be
    lost.

    Likewise, the wake up latency induced by entering a sleep state on
    a particular hardware may not always be acceptable.

    Since the in-band kernel code does not know about the out-of-band
    code plans by design, CPUIDLE calls :c:func:`irq_cpuidle_control`
    to figure out whether the out-of-band system is fine with entering
    the idle state as well.  This routine should be overriden by the
    out-of-band code for receiving such notification (*__weak*
    binding).

    If this hook returns a boolean *true* value, CPUIDLE proceeds as
    normally. Otherwise, the CPU is simply denied from entering the
    idle state, leaving the timer hardware enabled.

    ..CAUTION:: If some out-of-band code waiting for an external event
    cannot bear with the latency that might be induced by the default
    architecture-specific CPU idling code, then CPUIDLE is not usable
    and should be disabled at build time.

  * Kernel preemption control (PREEMPT)

    :c:func:`preempt_schedule_irq` reconciles the virtual interrupt
    state - which has not been touched by the assembly level code upon
    kernel entry - with basic assumptions made by the scheduler core,
    such as entering with interrupts disabled.

- Timer management

  * Proxy tick device

.. _proxy:
    The proxy tick device is a synthetic clock event device for
    handing over control of the hardware tick device in use by the
    kernel to an out-of-band timing logic.

    With this proxy in place, the out-of-band code must carry out the
    timing requests from the in-band timer core (i.e. hrtimers) in
    addition to its own timing duties.

    In other words, the proxy tick device shares the functionality of
    the actual device between the in-band and out-of-band contexts,
    with only the latter actually programming the hardware.

- Generic locking & atomic

  * Generic atomic ops

.. _atomic:
    The effect of virtualizing interrupt protection must be reversed
    for atomic helpers in <asm-generic/{atomic|bitops/atomic}.h> and
    <asm-generic/cmpxchg-local.h>, so that no interrupt can preempt
    their execution, regardless of the stage their caller live
    on.

    This is required to keep those helpers usable on data which
    might be accessed concurrently from both stages.

    The usual way to revert such virtualization consists of delimiting
    the protected section with :c:func:`hard_local_irq_save`,
    :c:func:`hard_local_irq_restore` calls, in replacement for
    :c:func:`local_irq_save`, :c:func:`local_irq_restore`
    respectively.

  * Mutable and hard spinlocks

    .. _spinlocks:
    The pipeline core introduces two spinlock types:

    + *hard* spinlocks manipulate the CPU interrupt mask, and don't
      affect the kernel preemption state in locking/unlocking
      operations.

      This type of spinlock is useful for implementing a critical
      section to serialize concurrent accesses from both in-band and
      out-of-band contexts, i.e. from in-band and oob stages. Obviously,
      sleeping into a critical section protected by a hard spinlock
      would be a very bad idea.

      In other words, hard spinlocks are not subject to virtual
      interrupt disabling, therefore can be used to serialize with
      out-of-band activities, including from the in-band kernel
      code. At any rate, those sections ought to be quite short, for
      keeping latency low.

   + Mutable spinlocks are used internally by the pipeline core to
     protect access to IRQ descriptors (`struct irq_desc::lock`), so
     that we can keep the original locking scheme of the generic IRQ
     core unmodified for handling out-of-band interrupts.

     Mutable spinlocks behave like *hard* spinlocks when traversed by
     the low-level IRQ handling code on entry to the pipeline, or
     common *raw* spinlocks otherwise, preserving the kernel
     (virtualized) interrupt and preemption states as perceived by the
     in-band context. This type of lock is not meant to be used in any
     other situation.

  * Lockdep

    The lock validator automatically reconciles the real and virtual
    interrupt states, so it can deliver proper diagnosis for locking
    constructs defined in both in-band and out-of-band contexts.

    This means that *hard* and *mutable* spinlocks_ are included in
    the validation set when LOCKDEP is enabled.

  .. CAUTION:: These two additional types are subject to LOCKDEP
                analysis. However, be aware that latency figures are
                likely to be really **bad** when LOCKDEP is enabled,
                due to the large amount of work the lock validator may
                have to do while critical sections are being enforced
                by disabling interrupts in the CPU.

- Drivers

  * IRQ chip drivers

    .. _irqchip:
    `irqchip` drivers need to be specifically adapted for supporting the
    pipelined interrupt model. The basic task is to ensure that the
    following `struct irq_chip` handlers can be called from an
    out-of-band context safely when defined for the interrupt
    controller: :c:func:`irq_mask`, :c:func:`irq_ack`,
    :c:func:`irq_mask_ack`, :c:func:`irq_eoi`, :c:func:`irq_unmask`.

    Such handler is deemed safe to be called from out-of-band context
    when it does not invoke **any** regular kernel service, which
    might cause an invalid in-band context re-entry_.

    The generic IRQ management core serializes calls to `irqchip`
    handlers for a given IRQ by serializing access to its interrupt
    descriptor, acquiring the per-descriptor `irq_desc::lock`
    spinlock.  Holding `irq_desc::lock` when running a handler for any
    IRQ shared between all CPUs ensures that a single CPU handles the
    event.

    In addition, there might be inner spinlocks defined by some
    `irqchip` drivers for serializing handlers accessing a common
    interrupt controller hardware for _distinct_ IRQs from multiple
    CPUs concurrently.  Adapting the `irqchip` driver to support
    interrupt pipelining may involve converting those spinlocks hard
    spinlocks_.

    .. CAUTION:: switching to hard spinlocks_ should involve a careful
                 review of any section in the `irqchip` driver
                 serializing execution with such spinlock. Any such
                 section would then have the same requirement about
                 not calling any regular kernel service, and be short
                 enough to keep interrupt latency figures low.

    Other section of code which were originally serialized by common
    interrupt disabling may need to be made fully atomic_ for running
    consistenly in pipelined interrupt mode. This can be done by
    introducing hard masking with :c:func:`hard_local_irq_save()`,
    :c:func:`hard_local_irq_restore()`.

    Finally, `IRQCHIP_PIPELINE_SAFE` must be added to `struct
    irqchip::flags` member of a pipeline-aware `irqchip` driver, in
    order to notify the kernel that such controller can operate in
    pipelined interrupt mode.

    .. NOTE:: :c:func:`irq_set_chip` will complain loudly with a
              kernel warning whenever the `irqchip` descriptor passed
              does not bear the `IRQCHIP_PIPELINE_SAFE` flag and
              CONFIG_IRQ_PIPELINE is enabled.

  * Clock event devices

    Clock chip devices which may be controlled by the proxy tick
    device need their drivers to be specifically adapted for such use:

    + :c:func:`clockevents_handle_event` must be used to invoke the
      event handler from the interrupt handler, instead of
      dereferencing `struct clock_event_device::event_handler`
      directly.

    + `struct clock_event_device::irq` must be properly set to the
      actual IRQ number signaling an event from this device.

    + `struct clock_event_device::features` must include
      `CLOCK_EVT_FEAT_PIPELINE`.

    + `__IRQF_TIMER` must be set for the action handler of the timer
       device interrupt.

    .. CAUTION:: only oneshot-capable clock event devices can be
                 shared via the proxy tick device.

- Misc

  * :c:func:`printk`

    :c:func:`printk` may be called by out-of-band code safely, without
    encurring extra latency. The output is conveyed like
    NMI-originated output, which involves some delay until the in-band
    code resumes, and the console driver(s) can handle it.

  * Tracing core

    Tracepoints can be traversed by out-of-band code safely. Dynamic
    tracing is available to a kernel running the pipelined interrupt
    model too.

Terminology
===========

.. _terminology:
======================   =======================================================
    Term                                       Definition
======================   =======================================================
OOB stage                high-priority execution context trigged by out-of-band IRQs
In-band stage            regular execution context performing GPOS work
Out-of-band code         code running over the oob stage
In-band code             code running over the in-band stage


Resources
=========

.. [#f1] Stodolsky, Chen & Bershad; "Fast Interrupt Priority Management in Operating System Kernels"
    https://www.usenix.org/legacy/publications/library/proceedings/micro93/full_papers/stodolsky.txt
.. [#f2] Yaghmour, Karim; "ADEOS - Adaptive Domain Environment for Operating Systems"
    https://www.opersys.com/ftp/pub/Adeos/adeos.pdf
