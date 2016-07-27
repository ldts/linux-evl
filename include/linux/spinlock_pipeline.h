#ifndef __LINUX_SPINLOCK_PIPELINE_H
#define __LINUX_SPINLOCK_PIPELINE_H

#ifndef __LINUX_SPINLOCK_H
# error "Please don't include this file directly. Use spinlock.h."
#endif

#define hard_spin_lock_irqsave(__rlock, __flags)		\
	do {							\
		(__flags) = __hard_spin_lock_irqsave(__rlock);	\
	} while (0)

#define hard_spin_trylock_irqsave(__rlock, __flags)			\
	({								\
		int __locked;						\
		(__flags) = __hard_spin_trylock_irqsave(__rlock, &__locked); \
		__locked;						\
	})

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)

#define hard_lock_acquire(__rlock, __try, __ip)				\
	do {								\
		if (irq_pipeline_debug_locking())			\
			spin_acquire(&(__rlock)->dep_map, 0, __try, __ip); \
	} while (0)

#define hard_lock_release(__rlock, __ip)				\
	do {								\
		if (irq_pipeline_debug_locking())			\
			spin_release(&(__rlock)->dep_map, 1, __ip);	\
	} while (0)

#ifdef CONFIG_DEBUG_SPINLOCK
#define hard_spin_lock_init(__lock)				\
	do {							\
		static struct lock_class_key __key;		\
		__raw_spin_lock_init((raw_spinlock_t *)__lock, #__lock, &__key); \
	} while (0)
#else
#define hard_spin_lock_init(__rlock)				\
	do { *(__rlock) = __HARD_SPIN_LOCK_UNLOCKED(__rlock); } while (0)
#endif

/*
 * XXX: no preempt_enable/disable when hard locking.
 */

static inline
void hard_spin_lock(struct raw_spinlock *rlock)
{
	hard_lock_acquire(rlock, 0, _THIS_IP_);
	LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
}

static inline
void hard_spin_unlock(struct raw_spinlock *rlock)
{
	hard_lock_release(rlock, _THIS_IP_);
	do_raw_spin_unlock(rlock);
}

static inline
void hard_spin_lock_irq(struct raw_spinlock *rlock)
{
	hard_local_irq_disable();
	hard_lock_acquire(rlock, 0, _THIS_IP_);
	LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);
}

static inline
void hard_spin_unlock_irq(struct raw_spinlock *rlock)
{
	hard_lock_release(rlock, _THIS_IP_);
	do_raw_spin_unlock(rlock);
	hard_local_irq_enable();
}

static inline
void hard_spin_unlock_irqrestore(struct raw_spinlock *rlock,
				 unsigned long flags)
{
	hard_lock_release(rlock, _THIS_IP_);
	do_raw_spin_unlock(rlock);
	hard_local_irq_restore(flags);
}

static inline
unsigned long __hard_spin_lock_irqsave(struct raw_spinlock *rlock)
{
	unsigned long flags = hard_local_irq_save();

	hard_lock_acquire(rlock, 0, _THIS_IP_);
	/*
	 * We don't want the hand-coded irq-enable of
	 * do_raw_spin_lock_flags(), hard locked sections assume that
	 * interrupts are not re-enabled during lock-acquire.
	 */
	LOCK_CONTENDED(rlock, do_raw_spin_trylock, do_raw_spin_lock);

	return flags;
}

static inline
int hard_spin_trylock(struct raw_spinlock *rlock)
{
	if (do_raw_spin_trylock(rlock)) {
		hard_lock_acquire(rlock, 1, _THIS_IP_);
		return 1;
	}
	return 0;
}

static inline
unsigned long __hard_spin_trylock_irqsave(struct raw_spinlock *rlock,
					  int *locked)
{
	unsigned long flags = hard_local_irq_save();
	*locked = hard_spin_trylock(rlock);
	return *locked ? flags : ({ hard_local_irq_restore(flags); flags; });
}

static inline
int hard_spin_trylock_irq(struct raw_spinlock *rlock)
{
	hard_local_irq_disable();
	return hard_spin_trylock(rlock) ? : ({ hard_local_irq_enable(); 0; });
}

static inline
int hard_spin_is_locked(struct raw_spinlock *rlock)
{
	return arch_spin_is_locked(&rlock->raw_lock);
}

static inline
int hard_spin_is_contended(struct raw_spinlock *rlock)
{
#ifdef CONFIG_GENERIC_LOCKBREAK
	return rlock->break_lock;
#elif defined(arch_spin_is_contended)
	return arch_spin_is_contended(&rlock->raw_lock);
#else
	return 0;
#endif
}

#else  /* !SMP && !DEBUG_SPINLOCK */

#define hard_spin_lock_init(__rlock)	do { (void)(__rlock); } while (0)
#define hard_spin_lock(__rlock)		__HARD_LOCK(__rlock)
#define hard_spin_unlock(__rlock)	__HARD_UNLOCK(__rlock)
#define hard_spin_lock_irq(__rlock)	__HARD_LOCK_IRQ(__rlock)
#define hard_spin_unlock_irq(__rlock)	__HARD_UNLOCK_IRQ(__rlock)
#define hard_spin_unlock_irqrestore(__rlock, __flags)	\
	__HARD_UNLOCK_IRQRESTORE(__rlock, __flags)
#define __hard_spin_lock_irqsave(__rlock)		\
	({						\
		unsigned long __flags;			\
		__HARD_LOCK_IRQSAVE(__rlock, __flags);	\
		__flags;				\
	})
#define __hard_spin_trylock_irqsave(__rlock, __locked)	\
	({						\
		unsigned long __flags;			\
		__HARD_LOCK_IRQSAVE(__rlock, __flags);	\
		*(__locked) = 1;			\
		__flags;				\
	})
#define hard_spin_trylock(__rlock)	({ __HARD_LOCK(__rlock); 1; })
#define hard_spin_trylock_irq(__rlock)	({ __HARD_LOCK_IRQ(__rlock); 1; })
#define hard_spin_is_locked(__rlock)	((void)(__rlock), 0)
#define hard_spin_is_contended(__rlock)	((void)(__rlock), 0)
#endif	/* !SMP && !DEBUG_SPINLOCK */

#endif /* __LINUX_SPINLOCK_PIPELINE_H */
