========================
Introduction to Dovetail
========================

:Copyright: |copy| 2016-2018: Philippe Gerum

Using Linux as a host for lightweight software cores specialized in
delivering very short and bounded response times has been a popular
way of supporting real-time applications in the embedded space over
the years.

This design - known as the *dual kernel* approach - introduces a small
real-time infrastructure which schedules time-critical activities
independently from the main kernel. Application threads co-managed by
this infrastructure still benefit from the ancillary kernel services
such as virtual memory management, and can also leverage the rich GPOS
feature set Linux provides such as networking, data storage or GUIs.

There are significant upsides to keeping the real-time core separate
from the GPOS infrastructure:

- because the two kernels are independent, real-time activities are
  not serialized with GPOS operations internally, removing potential
  delays which might be induced by the non time-critical
  work. Likewise, there is no requirement for keeping the GPOS
  operations fine-grained and highly preemptible at any time, which
  would otherwise induce noticeable overhead on low-end hardware, due
  to the need for pervasive task priority inheritance and IRQ
  threading.

- when debugging a real-time issue, the functional isolation of the
  real-time infrastructure from the rest of the kernel code restricts
  bug hunting to the scope of the small co-kernel, excluding most
  interactions with the very large GPOS kernel base.

- with a dedicated infrastructure providing a specific, well-defined
  set of real-time services, applications can unambiguously figure out
  which API calls are available for supporting time-critical work,
  excluding all the rest as being potentially non-deterministic with
  respect to response time.

To support such a *dual kernel system*, we need the kernel to exhibit
a high-priority execution context, for running out-of-band real-time
duties concurrently to the regular operations.

.. NOTE:: Dovetail only introduces the basic mechanisms for hosting
such a real-time core, enabling the common programming model for its
applications in user-space. It does *not* implement the real-time core
per se, which should be provided by a separate kernel component.

Interrupt pipelining
====================

.. _pipeline
The real-time core has to act upon device interrupts with no delay,
regardless of the regular kernel operations which may be ongoing when
the interrupt is received by the CPU. Therefore, there is a basic
requirement for prioritizing interrupt masking and delivery between
the real-time core and GPOS operations, while maintaining consistent
internal serialization for the kernel.

To this end, Dovetail leverages a mechanism called *interrupt
pipelining*, which is described in the
:ref:`Documentation/irq_pipeline.rst <Interrupt Pipeline>`)
document. Understanding the concepts and mechanisms described in the
later document is required for a full comprehension of the Dovetail
basics.

Alternate scheduling
====================

Dovetail promotes the idea that a *dual kernel* system should keep the
functional overlap between the kernel and the real-time core
minimal. To this end, a real-time thread should be merely seen as a
regular task with additional scheduling capabilities guaranteeing very
low response times.

To support such idea, Dovetail enables kthreads and regular user tasks
to run alternatively in the out-of-band execution context introduced
by the interrupt pipeline_ (aka *oob* stage), or the common in-band
kernel context for GPOS operations (aka *in-band* stage).

As a result, real-time core applications in user-space benefit from
the common Linux programming model - including virtual memory
protection -, and still have access to the regular Linux services when
carrying out non time-critical work.

Task migration to the oob stage
-------------------------------

Low latency response time to events can be achieved when Linux tasks
wait for them from the out-of-band execution context. The real-time
core is responsible for switching a task to such a context as part of
its task management rules; Dovetail facilitates this migration with
dedicated services.

The migration process of a task from the GPOS/in-band context to the
high-priority, out-of-band context is as follows:

1. :c:func:`dovetail_leave_inband` is invoked from the migrating task
   context, with the same prerequisites than for calling
   :c:func:`schedule` (preemption enabled, interrupts on).

.. _`in-band sleep operation`:
2. the caller is put to interruptible sleep state (S).

3. before resuming in-band operations, the next task picked by the
   (regular kernel) scheduler on the same CPU for replacing the
   migrating task fires :c:func:`resume_oob_task` which the
   real-time core should override (*__weak* binding). Before the call,
   the oob stage is stalled, interrupts are disabled in the CPU. The
   in-band execution stage is still current though.

4. the real-time core's implementation of
   :c:func:`resume_oob_task` is passed a pointer to the
   task_struct descriptor of the migrating task. This routine is expected
   to perform the necessary steps for taking control over the task on
   behalf of the real-time core, re-scheduling its code appropriately
   over the oob stage. This typically involves resuming it from the
   `out-of-band suspended state`_ applied during the converse migration
   path. The real-time core is expected to call :c:func:`dovetail_resume_oob`
   before transitioning from the inband task context its preempts to any
   out-of-band thread.

5. at some point later, when the migrated task is picked by the
   real-time scheduler, it resumes execution on the oob stage with the
   register file previously saved by the kernel scheduler in
   :c:func:`switch_to` at step 1.

Task migration to the in-band stage
-----------------------------------

Sometimes, a real-time thread may want to leave the out-of-band
context, continuing execution from the in-band context instead, so as
to:

- run non time-critical (in-band) work involving regular system calls
  handled by the kernel,

- recover from CPU exceptions, such as handling major memory access
  faults, for which there is no point in caring for response time, and
  therefore makes no sense to duplicate in the real-time core anyway.

.. NOTE: The discussion about exception_ handling covers the last
   point in details.

The migration process of a task from the high-priority, out-of-band
context to the GPOS/in-band context is as follows::

1. the real-time core schedules an in-band handler for execution which
   should call :c:func:`wake_up_process` to unblock the migrating task
   from the standpoint of the kernel scheduler. This is the
   counterpart of the :ref:`in-band sleep operation <in-band sleep
   operation>` from the converse migration path. The
   :ref:`Documentation/irq_pipeline.rst` <irq_work> mechanism can be
   used for scheduling such event from the out-of-band context.

.. _`out-of-band suspended state`:
2. the real-time core suspends execution of the current task from its
   own standpoint, calling :c:func:`dovetail_leave_oob` right before
   scheduling out the task. The real-time scheduler is assumed to be
   using the common :c:func:`switch_to` routine for switching task
   contexts.

3. at some point later, the out-of-band context is exited by the
   current CPU when no more high-priority work is left, causing the
   preempted in-band kernel code to resume execution on the in-band
   stage. The handler scheduled at step 1 eventually runs, waking up
   the migrating task from the standpoint of the kernel.

4. the migrating task resumes from the tail scheduling code of the
   real-time scheduler, where it suspended in step 2. Noticing the
   migration, the real-time core eventually calls
   :c:func:`dovetail_resume_inband` for finalizing the transition of
   the incoming task to the in-band stage.

Binding to the real-time core
-----------------------------

.. _binding:
Dovetail facilitates fine-grained per-thread management from the
real-time core, as opposed to per-process. For this reason, the
real-time core should at least implement a mechanism for turning a
regular task into a real-time thread with extended capabilities,
binding it to the core.

The real-time core should inform the kernel about its intent to share
control over a task, by calling :c:func::`dovetail_start_altsched` on
behalf of that task, i.e. when such task is current.

For this reason, the binding operation is usually carried out by a
dedicated system call exposed by the real-time core, which a regular
task would invoke.

Once :c:func::`dovetail_start_altsched` has returned, Dovetail
notifications are enabled for the current task (see below).

.. NOTE:: Whether there should be distinct procedures for binding
	  processes *and* threads to the real-time core, or only a
	  thread binding procedure is up to the real-time core
	  implementation.

Notifications
-------------

Exception handling
~~~~~~~~~~~~~~~~~~

.. _exception
If a processor exception is raised while the CPU is busy running a
real-time thread in the out-of-band context (e.g. due to some invalid
memory access, bad instruction, FPU or alignment error etc), the task
may have to leave such context immediately if the fault handler is not
protected against out-of-band interrupts, and therefore cannot be
properly serialized with out-of-band code.

Dovetail notifies the real-time core about incoming exceptions early
from the low-level fault handlers, but only when some out-of-band code
was running when the exception was taken. The real-time core may then
take action, such as reconciling the current task's execution context
with the kernel's expectations before the task may traverse the
regular fault handling code.

.. HINT:: Enabling debuggers to trace real-time thread involves
          dealing with debug traps the former may poke into the
          debuggee's code for breakpointing duties.

The notification is issued by a call to :c:func:`oob_trap_notify`
which in turn invokes the :c:func:`handle_oob_trap` routine the
real-time core should override for receiving those events (*__weak*
binding). Interrupts are **disabled** in the CPU when
:c:func:`handle_oob_trap` is called.::

     /* out-of-band code running */
     *bad_pointer = 42;
        [ACCESS EXCEPTION]
	   /* low-level fault handler in arch/<arch>/mm */
           -> do_page_fault()
	      -> oob_trap_notify(...)
	         /* real-time core */
	         -> handle_oob_trap(...)
		    -> forced task migration to in-band stage
	   ...
           -> handle_mm_fault()

.. NOTE:: handling minor memory access faults only requiring quick PTE
          fixups should not involve switching the current task to the
          in-band context though. Instead, the fixup code should be
          made :ref:`Documentation/irq_pipeline.rst` strictly <atomic>
          for serializing accesses from any context.

System calls
~~~~~~~~~~~~

A real-time core interfaced with the kernel via Dovetail may introduce
its own set of system calls. From the standpoint of the kernel, this
is a foreign set of calls, which can be distinguished unambiguously
from regular ones based on an arch-specific marker.

.. HINT:: Syscall numbers from this set might have a different base,
	  and/or some high-order bit set which regular syscall numbers
	  would not have.

If a task bound to the real-time core issues any system call,
regardless of which of the kernel or real-time core should handle it,
the latter must be given the opportunity to:

- perform the service directly, possibly switching the caller to
  out-of-band context first would the request require it.

- pass the request downward to the normal system call path on the
  in-band stage, possibly switching the caller to in-band context if
  needed.

If a regular task (i.e. *not* known from the real-time core [yet])
issues any foreign system call, the real-time core is given a chance
to handle it. This way, a foreign system call which would initially
bind a regular task to the real-time core would be delivered to the
real-time core as expected (see binding_).

Dovetail intercepts system calls early in the kernel entry code,
delivering them to the proper handler according to the following
logic::

     is_foreign(syscall_nr)?
	    Y: is_bound(task)
	           Y: -> handle_oob_syscall()
		   N: -> handle_pipelined_syscall()
            N: is_bound(task)
	           Y: -> handle_pipelined_syscall()
		   N: -> normal syscall handling

:c:func:`handle_oob_syscall` is the fast path for handling foreign
system calls from tasks already running in out-of-band context.

:c:func:`handle_pipelined_syscall` is a slower path for handling requests
which might require the caller to switch to the out-of-band context
first before proceeding.

In-band kernel events
~~~~~~~~~~~~~~~~~~~~~

The last set of notifications involves pure in-band events which the
real-time core may need to know about, as they may affect its own task
management. Except for INBAND_PROCESS_CLEANUP which is called for
*any* exiting user-space task, all other notifications are only issued
for tasks bound to the real-time core (which may involve kthreads).

The notification is issued by a call to :c:func:`inband_event_notify`
which in turn invokes the :c:func:`handle_inband_event` routine the
real-time core should override for receiving those events (*__weak*
binding). Interrupts are **enabled** in the CPU when
:c:func:`handle_inband_event` is called.

The notification hook is given the event type code, and a single
pointer argument which relates to the event type.

The following events are defined (include/linux/dovetail.h):

- INBAND_TASK_SCHEDULE(struct task_struct *next)

  sent in preparation of a context switch, right before the memory
  context is switched to *next*.

- INBAND_TASK_SIGNAL(struct task_struct *target)

  sent when *target* is about to receive a signal. The real-time core
  may decide to schedule a transition of the recipient to the in-band
  stage in order to have it handle that signal asap, which is required
  for keeping the kernel sane. This notification is always sent from
  the context of the issuer.

- INBAND_TASK_MIGRATION(struct dovetail_migration_data *p)

  sent when p->task is about to move to CPU p->dest_cpu.

- INBAND_TASK_EXIT(struct task_struct *current)

  sent from :c:func:`do_exit` before the current task has dropped the
  files and mappings it owns.

- INBAND_PROCESS_CLEANUP(struct mm_struct *mm)

  sent before *mm* is entirely dropped, before the mappings are
  exited. Per-process resources which might be maintained by the
  real-time core could be released there, as all threads have exited.

Terminology
===========

See the :ref:`Documentation/irq_pipeline.rst` <Interrupt Pipeline
terminology>.
