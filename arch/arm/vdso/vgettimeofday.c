/*
 * Copyright 2015 Mentor Graphics Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the
 * License.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/compiler.h>
#include <linux/hrtimer.h>
#include <linux/time.h>
#include <linux/io.h>
#include <linux/fcntl.h>
#include <linux/err.h>
#include <linux/mman.h>
#include <linux/compiler.h>
#include <linux/ioctl.h>
#include <linux/clocksource.h>
#include <asm/arch_timer.h>
#include <asm/barrier.h>
#include <asm/bug.h>
#include <asm/page.h>
#include <asm/unistd.h>
#include <asm/vdso_datapage.h>

#ifndef CONFIG_AEABI
#error This code depends on AEABI system call conventions
#endif

extern struct vdso_data *__get_datapage(void);

struct clksrc_info;

typedef u64 vdso_read_cycles_fn(const struct clksrc_info *info);

struct clksrc_info {
	vdso_read_cycles_fn *read_cycles;
	struct clksrc_user_mmio_info mmio;
};

struct vdso_priv {
	u32 current_cs_type_and_seq;
	struct clksrc_info clksrc_info[ARM_CLOCK_USER_MMIO_BASE + CLKSRC_USER_MMIO_MAX];
};
extern struct vdso_priv *__get_privpage(void);

#define syscall3(nr, a0, a1, a2)			\
	_syscall3((u32)a0, (u32)a1, (u32)a2, nr)

#define syscall2(nr, a0, a1) \
	_syscall2((u32)a0, (u32)a1, nr)

#define syscall1(nr, a0) \
	syscall2(nr, a0, 0)

#define sys_open(filename, flags) \
	syscall2(__NR_open, filename, flags)

#define sys_ioctl(fd, cmd, ptr)			\
	syscall3(__NR_ioctl, fd, cmd, ptr)

#define sys_close(fd) \
	syscall1(__NR_close, fd)

#define sys_clock_gettime(id, ts) \
	syscall2(__NR_clock_gettime, id, ts)

#define sys_gettimeofday(tv, tz) \
	syscall2(__NR_gettimeofday, tv, tz)

static notrace u64 read_none(const struct clksrc_info *info)
{
	return 0;
}

static notrace u64 read_arch_timer(const struct clksrc_info *info)
{
#ifdef CONFIG_ARM_ARCH_TIMER
	return arch_counter_get_cntvct();
#else
	return 0;
#endif
}

static notrace u64 readl_mmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return readl_relaxed(info->reg_lower);
}

static notrace u64 readl_mmio_down(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return ~(u64)readl_relaxed(info->reg_lower) & info->mask_lower;
}

static notrace u64 readw_mmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return readw_relaxed(info->reg_lower);
}

static notrace u64 readw_mmio_down(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	return ~(u64)readl_relaxed(info->reg_lower) & info->mask_lower;
}

static notrace u64 readl_dmmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	void __iomem *reg_lower, *reg_upper;
	u32 upper, old_upper, lower;

	reg_lower = info->reg_lower;
	reg_upper = info->reg_upper;

	upper = readl_relaxed(reg_upper);
	do {
		old_upper = upper;
		lower = readl_relaxed(reg_lower);
		upper = readl_relaxed(reg_upper);
	} while (upper != old_upper);

	return (((u64)upper) << info->bits_lower) | lower;
}

static notrace u64 readw_dmmio_up(const struct clksrc_info *vinfo)
{
	const struct clksrc_user_mmio_info *info = &vinfo->mmio;
	void __iomem *reg_lower, *reg_upper;
	u16 upper, old_upper, lower;

	reg_lower = info->reg_lower;
	reg_upper = info->reg_upper;

	upper = readw_relaxed(reg_upper);
	do {
		old_upper = upper;
		lower = readw_relaxed(reg_lower);
		upper = readw_relaxed(reg_upper);
	} while (upper != old_upper);

	return (((u64)upper) << info->bits_lower) | lower;
}

static inline notrace u16 to_type(u32 type_and_seq)
{
	return type_and_seq >> 16;
}

static inline notrace u16 to_seq(u32 type_and_seq)
{
	return type_and_seq;
}

static inline notrace u32 to_type_and_seq(u16 type, u16 seq)
{
	return (u32)type << 16U | seq;
}

static inline notrace bool clock_accessible(struct vdso_priv *vpriv)
{
	return to_type(vpriv->current_cs_type_and_seq) != ARM_CLOCK_NONE;
}

static notrace u64 read_cycles(struct vdso_priv *vpriv)
{
	const struct clksrc_info *info;
	unsigned cs;

	cs = to_type(READ_ONCE(vpriv->current_cs_type_and_seq));
	info = &vpriv->clksrc_info[cs];
	return info->read_cycles(info);
}

static notrace __cold vdso_read_cycles_fn *get_nommio_read_cycles(unsigned type)
{
	switch (type) {
	case ARM_CLOCK_ARCH_TIMER:
		return &read_arch_timer;
	default:
		return &read_none;
	}
}

static notrace __cold vdso_read_cycles_fn *get_mmio_read_cycles(unsigned type)
{
	switch (type) {
	case CLKSRC_MMIO_L_UP:
		return &readl_mmio_up;
	case CLKSRC_MMIO_L_DOWN:
		return &readl_mmio_down;
	case CLKSRC_MMIO_W_UP:
		return &readw_mmio_up;
	case CLKSRC_MMIO_W_DOWN:
		return &readw_mmio_down;
	case CLKSRC_DMMIO_L_UP:
		return &readl_dmmio_up;
	case CLKSRC_DMMIO_W_UP:
		return &readw_dmmio_up;
	default:
		return &read_none;
	}
}

static notrace u32 __vdso_read_begin(const struct vdso_data *vdata)
{
	u32 seq;
repeat:
	seq = READ_ONCE(vdata->seq_count);
	if (seq & 1) {
		cpu_relax();
		goto repeat;
	}
	return seq;
}

static notrace u32 _vdso_read_begin(const struct vdso_data *vdata)
{
	u32 seq;

	seq = __vdso_read_begin(vdata);

	smp_rmb(); /* Pairs with smp_wmb in vdso_write_end */
	return seq;
}

static notrace int vdso_read_retry(const struct vdso_data *vdata, u32 start)
{
	smp_rmb(); /* Pairs with smp_wmb in vdso_write_begin */
	return vdata->seq_count != start;
}

static notrace long _syscall3(u32 a0, u32 a1, u32 a2, u32 nr)
{
	register u32 r0 asm("r0") = a0;
	register u32 r1 asm("r1") = a1;
	register u32 r2 asm("r2") = a2;
	register long ret asm ("r0");
	register long _nr asm("r7") = nr;

	asm volatile(
	"	swi #0\n"
	: "=r" (ret)
	: "r"(r0), "r"(r1), "r"(r2), "r"(_nr)
	: "memory");

	return ret;
}

static notrace long _syscall2(u32 a0, u32 a1, u32 nr)
{
	register u32 r0 asm("r0") = a0;
	register u32 r1 asm("r1") = a1;
	register long ret asm ("r0");
	register long _nr asm("r7") = nr;

	asm volatile(
	"	swi #0\n"
	: "=r" (ret)
	: "r"(r0), "r"(r1), "r"(_nr)
	: "memory");

	return ret;
}

static notrace noinline __cold
void vdso_map_clock(const struct vdso_data *vdata, struct vdso_priv *vpriv,
		    u32 seq, u32 new_type_and_seq)
{
	vdso_read_cycles_fn *read_cycles;
	u32 new_cs_seq, new_cs_type;
	struct clksrc_info *info;
	int fd, err;

	new_cs_seq = to_seq(new_type_and_seq);
	new_cs_type = to_type(new_type_and_seq);
	info = &vpriv->clksrc_info[new_cs_type];

	if (new_cs_type < ARM_CLOCK_USER_MMIO_BASE) {
		read_cycles = get_nommio_read_cycles(new_cs_type);
		goto done;
	}

	err = sys_open(vdata->mmio_dev_name, O_RDONLY);
	if (err < 0)
		goto fallback_to_syscall;
	fd = err;

	if (vdso_read_retry(vdata, seq)) {
		_vdso_read_begin(vdata);
		if (to_seq(vdata->cs_type_and_seq) != new_cs_seq) {
			/*
			 * mmio_dev_name no longer corresponds to
			 * vdata->cs_type_and_seq
			 */
			sys_close(fd);
			return;
		}
	}

	err = sys_ioctl(fd, CLKSRC_USER_MMIO_MAP, &info->mmio);
	sys_close(fd);
	if (err < 0)
		goto fallback_to_syscall;

	read_cycles = get_mmio_read_cycles(info->mmio.type);
  done:
	info->read_cycles = read_cycles;
	smp_wmb();
	new_type_and_seq = to_type_and_seq(new_cs_type, new_cs_seq);
	WRITE_ONCE(vpriv->current_cs_type_and_seq, new_type_and_seq);

	return;

  fallback_to_syscall:
	new_cs_type = ARM_CLOCK_NONE;
	info = &vpriv->clksrc_info[new_cs_type];
	read_cycles = get_nommio_read_cycles(new_cs_type);
	goto done;
}

static notrace u32 vdso_read_begin(const struct vdso_data *vdata,
				   struct vdso_priv *vpriv)
{
	u32 seq, cs_type_and_seq;

	for (;;) {
		seq = _vdso_read_begin(vdata);

		cs_type_and_seq = READ_ONCE(vpriv->current_cs_type_and_seq);
		if (likely(to_seq(cs_type_and_seq) == to_seq(vdata->cs_type_and_seq)))
			return seq;

		vdso_map_clock(vdata, vpriv, seq, vdata->cs_type_and_seq);
	}
}

static notrace int do_realtime_coarse(struct timespec *ts,
				      struct vdso_data *vdata,
				      struct vdso_priv *vpriv)
{
	u32 seq;

	do {
		seq = vdso_read_begin(vdata, vpriv);

		ts->tv_sec = vdata->xtime_coarse_sec;
		ts->tv_nsec = vdata->xtime_coarse_nsec;

	} while (vdso_read_retry(vdata, seq));

	return 0;
}

static notrace int do_monotonic_coarse(struct timespec *ts,
				       struct vdso_data *vdata,
				       struct vdso_priv *vpriv)
{
	struct timespec tomono;
	u32 seq;

	do {
		seq = vdso_read_begin(vdata, vpriv);

		ts->tv_sec = vdata->xtime_coarse_sec;
		ts->tv_nsec = vdata->xtime_coarse_nsec;

		tomono.tv_sec = vdata->wtm_clock_sec;
		tomono.tv_nsec = vdata->wtm_clock_nsec;

	} while (vdso_read_retry(vdata, seq));

	ts->tv_sec += tomono.tv_sec;
	timespec_add_ns(ts, tomono.tv_nsec);

	return 0;
}

static notrace u64 get_ns(struct vdso_data *vdata, struct vdso_priv *vpriv)
{
	u64 cycle_delta;
	u64 cycle_now;
	u64 nsec;

	cycle_now = read_cycles(vpriv);

	cycle_delta = (cycle_now - vdata->cs_cycle_last) & vdata->cs_mask;

	nsec = (cycle_delta * vdata->cs_mult) + vdata->xtime_clock_snsec;
	nsec >>= vdata->cs_shift;

	return nsec;
}

static notrace int do_realtime(struct timespec *ts,
			       struct vdso_data *vdata,
			       struct vdso_priv *vpriv)
{
	u64 nsecs;
	u32 seq;

	do {
		seq = vdso_read_begin(vdata, vpriv);

		if (!clock_accessible(vpriv))
			return -1;

		ts->tv_sec = vdata->xtime_clock_sec;
		nsecs = get_ns(vdata, vpriv);

	} while (vdso_read_retry(vdata, seq));

	ts->tv_nsec = 0;
	timespec_add_ns(ts, nsecs);

	return 0;
}

static notrace int do_monotonic(struct timespec *ts,
				struct vdso_data *vdata,
				struct vdso_priv *vpriv)
{
	struct timespec tomono;
	u64 nsecs;
	u32 seq;

	do {
		seq = vdso_read_begin(vdata, vpriv);

		if (!clock_accessible(vpriv))
			return -1;

		ts->tv_sec = vdata->xtime_clock_sec;
		nsecs = get_ns(vdata, vpriv);

		tomono.tv_sec = vdata->wtm_clock_sec;
		tomono.tv_nsec = vdata->wtm_clock_nsec;

	} while (vdso_read_retry(vdata, seq));

	ts->tv_sec += tomono.tv_sec;
	ts->tv_nsec = 0;
	timespec_add_ns(ts, nsecs + tomono.tv_nsec);

	return 0;
}

notrace int __vdso_clock_gettime(clockid_t clkid, struct timespec *ts)
{
	struct vdso_data *vdata;
	struct vdso_priv *vpriv;
	int ret = -1;

	vdata = __get_datapage();
	vpriv = __get_privpage();

	switch (clkid) {
	case CLOCK_REALTIME_COARSE:
		ret = do_realtime_coarse(ts, vdata, vpriv);
		break;
	case CLOCK_MONOTONIC_COARSE:
		ret = do_monotonic_coarse(ts, vdata, vpriv);
		break;
	case CLOCK_REALTIME:
		ret = do_realtime(ts, vdata, vpriv);
		break;
	case CLOCK_MONOTONIC:
		ret = do_monotonic(ts, vdata, vpriv);
		break;
	default:
		break;
	}

	if (ret)
		ret = sys_clock_gettime(clkid, ts);

	return ret;
}

notrace int __vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	struct timespec ts;
	struct vdso_data *vdata;
	struct vdso_priv *vpriv;
	int ret;

	vdata = __get_datapage();
	vpriv = __get_privpage();

	ret = do_realtime(&ts, vdata, vpriv);
	if (ret)
		return sys_gettimeofday(tv, tz);

	if (tv) {
		tv->tv_sec = ts.tv_sec;
		tv->tv_usec = ts.tv_nsec / 1000;
	}
	if (tz) {
		tz->tz_minuteswest = vdata->tz_minuteswest;
		tz->tz_dsttime = vdata->tz_dsttime;
	}

	return ret;
}

/* Avoid unresolved references emitted by GCC */

void __aeabi_unwind_cpp_pr0(void)
{
}

void __aeabi_unwind_cpp_pr1(void)
{
}

void __aeabi_unwind_cpp_pr2(void)
{
}
