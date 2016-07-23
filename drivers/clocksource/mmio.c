/*
 * Generic MMIO clocksource support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/clocksource.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/hashtable.h>

struct clocksource_mmio {
	void __iomem *reg;
	struct clocksource clksrc;
};

struct clocksource_user_mmio {
	unsigned int mask_lower;
	unsigned int bits_lower;
	void __iomem *reg_upper;
	unsigned int mask_upper;
	struct clocksource_mmio mmio;
	struct list_head link;
	unsigned int id;
	enum clksrc_user_mmio_type type;
	unsigned long phys_lower;
	unsigned long phys_upper;

	struct device *dev;
	struct cdev char_dev;

	DECLARE_HASHTABLE(mappings, 10);
	struct spinlock lock;
};

struct user_mmio_clksrc_mapping {
	struct mm_struct *mm;
	struct clocksource_user_mmio *cs;
	void *regs;
	struct hlist_node link;
	atomic_t refs;
};

static struct class *user_mmio_class;
static dev_t user_mmio_devt;

static DEFINE_SPINLOCK(user_clksrcs_lock);
static unsigned int user_clksrcs_count;
static LIST_HEAD(user_clksrcs);

static inline struct clocksource_mmio *to_mmio_clksrc(struct clocksource *c)
{
	return container_of(c, struct clocksource_mmio, clksrc);
}

u64 clocksource_mmio_readl_up(struct clocksource *c)
{
	return (u64)readl_relaxed(to_mmio_clksrc(c)->reg);
}

u64 clocksource_mmio_readl_down(struct clocksource *c)
{
	return ~(u64)readl_relaxed(to_mmio_clksrc(c)->reg) & c->mask;
}

u64 clocksource_mmio_readw_up(struct clocksource *c)
{
	return (u64)readw_relaxed(to_mmio_clksrc(c)->reg);
}

u64 clocksource_mmio_readw_down(struct clocksource *c)
{
	return ~(u64)readw_relaxed(to_mmio_clksrc(c)->reg) & c->mask;
}

static inline struct clocksource_user_mmio *
to_user_mmio_clksrc(struct clocksource *c)
{
	return container_of(c, struct clocksource_user_mmio, mmio.clksrc);
}

u64 clocksource_dual_mmio_readl_up(struct clocksource *c)
{
	struct clocksource_user_mmio *cs = to_user_mmio_clksrc(c);
	u32 upper, old_upper, lower;

	upper = readl_relaxed(cs->reg_upper);
	do {
		old_upper = upper;
		lower = readl_relaxed(cs->mmio.reg);
		upper = readl_relaxed(cs->reg_upper);
	} while (upper != old_upper);

	return (((u64)upper) << cs->bits_lower) | lower;
}

u64 clocksource_dual_mmio_readw_up(struct clocksource *c)
{
	struct clocksource_user_mmio *cs = to_user_mmio_clksrc(c);
	u16 upper, old_upper, lower;

	upper = readw_relaxed(cs->reg_upper);
	do {
		old_upper = upper;
		lower = readw_relaxed(cs->mmio.reg);
		upper = readw_relaxed(cs->reg_upper);
	} while (upper != old_upper);

	return (((u64)upper) << cs->bits_lower) | lower;
}

static void _clocksource_mmio_init(void __iomem *base, const char *name,
	unsigned long hz, int rating, unsigned int bits,
	u64 (*read)(struct clocksource *),
	struct clocksource_mmio *cs)
{
	cs->reg = base;
	cs->clksrc.name = name;
	cs->clksrc.rating = rating;
	cs->clksrc.read = read;
	cs->clksrc.mask = CLOCKSOURCE_MASK(bits);
	cs->clksrc.flags = CLOCK_SOURCE_IS_CONTINUOUS;
}

/**
 * clocksource_mmio_init - Initialize a simple mmio based clocksource
 * @base:	Virtual address of the clock readout register
 * @name:	Name of the clocksource
 * @hz:		Frequency of the clocksource in Hz
 * @rating:	Rating of the clocksource
 * @bits:	Number of valid bits
 * @read:	One of clocksource_mmio_read*() above
 */
int __init clocksource_mmio_init(void __iomem *base, const char *name,
	unsigned long hz, int rating, unsigned bits,
	u64 (*read)(struct clocksource *))
{
	struct clocksource_mmio *cs;
	int err;

	if (bits > 64 || bits < 16)
		return -EINVAL;

	cs = kzalloc(sizeof(struct clocksource_mmio), GFP_KERNEL);
	if (!cs)
		return -ENOMEM;

	_clocksource_mmio_init(base, name, hz, rating, bits, read, cs);

	err = clocksource_register_hz(&cs->clksrc, hz);
	if (err < 0) {
		kfree(cs);
		return err;
	}

	return err;
}

static void clksrc_vmopen(struct vm_area_struct *vma)
{
	struct user_mmio_clksrc_mapping *mapping;

	mapping = vma->vm_private_data;

	atomic_inc(&mapping->refs);
}

static void clksrc_vmclose(struct vm_area_struct *vma)
{
	struct user_mmio_clksrc_mapping *mapping;

	mapping = vma->vm_private_data;

	if (atomic_dec_and_test(&mapping->refs)) {
		spin_lock(&mapping->cs->lock);
		hash_del(&mapping->link);
		spin_unlock(&mapping->cs->lock);
		kfree(mapping);
	}
}

static const struct vm_operations_struct clksrc_vmops = {
	.open = clksrc_vmopen,
	.close = clksrc_vmclose,
};

static int user_mmio_clksrc_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long addr, upper_pfn, lower_pfn;
	struct user_mmio_clksrc_mapping *mapping, *tmp;
	struct clocksource_user_mmio *cs;
	unsigned int bits_upper;
	unsigned long h_key;
	pgprot_t prot;
	size_t pages;
	int err;

	pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	if (pages > 2)
		return -EINVAL;

	vma->vm_private_data = NULL;
	vma->vm_ops = &clksrc_vmops;
	cs = file->private_data;

	upper_pfn = cs->phys_upper >> PAGE_SHIFT;
	lower_pfn = cs->phys_lower >> PAGE_SHIFT;
	bits_upper = fls(cs->mmio.clksrc.mask) - cs->bits_lower;
	if (pages == 2 && (!bits_upper || upper_pfn == lower_pfn))
		return -EINVAL;

	h_key = (unsigned long)vma->vm_mm / sizeof(*vma->vm_mm);

	prot = pgprot_noncached(vma->vm_page_prot);
	addr = vma->vm_start;

	err = remap_pfn_range(vma, addr, lower_pfn, PAGE_SIZE, prot);
	if (err < 0)
		return err;

	if (pages == 2) {
		addr += PAGE_SIZE;
		err = remap_pfn_range(vma, addr, upper_pfn, PAGE_SIZE, prot);
		if (err < 0)
			return err;
	}

	mapping = kmalloc(sizeof(*mapping), GFP_KERNEL);
	if (!mapping)
		return -ENOSPC;

	mapping->mm = vma->vm_mm;
	mapping->cs = cs;
	mapping->regs = (void *)vma->vm_start;

	spin_lock(&cs->lock);
	hash_for_each_possible(cs->mappings, tmp, link, h_key) {
		if (tmp->mm != vma->vm_mm)
			continue;
		spin_unlock(&cs->lock);

		kfree(mapping);

		return -EBUSY;
	}
	hash_add(cs->mappings, &mapping->link, h_key);
	spin_unlock(&cs->lock);

	atomic_set(&mapping->refs, 1);
	vma->vm_private_data = mapping;

	return 0;
}

static long
user_mmio_clksrc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct user_mmio_clksrc_mapping *mapping;
	struct clksrc_user_mmio_info __user *u;
	struct clksrc_user_mmio_info info;
	struct clocksource_user_mmio *cs;
	unsigned long upper_pfn, lower_pfn;
	unsigned int bits_upper;
	void __user *map_base;
	unsigned long h_key;
	size_t size;

	u = (struct clksrc_user_mmio_info __user *)arg;

	switch (cmd) {
	case CLKSRC_USER_MMIO_MAP:
		break;
	default:
		return -ENOTTY;
	}

	cs = file->private_data;

	h_key = (unsigned long)current->mm / sizeof(*current->mm);

	size = PAGE_SIZE;
	upper_pfn = cs->phys_upper >> PAGE_SHIFT;
	lower_pfn = cs->phys_lower >> PAGE_SHIFT;
	bits_upper = fls(cs->mmio.clksrc.mask) - cs->bits_lower;
	if (bits_upper && upper_pfn != lower_pfn)
		size += PAGE_SIZE;

	do {
		spin_lock(&cs->lock);
		hash_for_each_possible(cs->mappings, mapping, link, h_key) {
			if (mapping->mm != current->mm)
				continue;
			spin_unlock(&cs->lock);

			map_base = mapping->regs;
			goto found;
		}
		spin_unlock(&cs->lock);

		map_base =
			(void *)vm_mmap(file, 0, size, PROT_READ, MAP_SHARED, 0);
	} while (IS_ERR(map_base) && PTR_ERR(map_base) == -EBUSY);

	if (IS_ERR(map_base))
		return PTR_ERR(map_base);

found:
	info.type = cs->type;
	info.reg_lower = map_base + offset_in_page(cs->phys_lower);
	info.mask_lower = cs->mmio.clksrc.mask;
	info.bits_lower = cs->bits_lower;
	info.reg_upper = NULL;
	if (cs->phys_upper)
		info.reg_upper = map_base + (size - PAGE_SIZE)
			+ offset_in_page(cs->phys_upper);
	info.mask_upper = cs->mask_upper;

	return copy_to_user(u, &info, sizeof(*u));
}

static int user_mmio_clksrc_open(struct inode *inode, struct file *file)
{
	struct clocksource_user_mmio *cs;

	if (file->f_mode & FMODE_WRITE)
		return -EINVAL;

	cs = container_of(inode->i_cdev, typeof(*cs), char_dev);
	file->private_data = cs;

	return 0;
}

static const struct file_operations user_mmio_clksrc_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = user_mmio_clksrc_ioctl,
	.open		= user_mmio_clksrc_open,
	.mmap		= user_mmio_clksrc_mmap,

};

static int __init
cs_create_char_dev(struct class *class, struct clocksource_user_mmio *cs)
{
	int err;

	cs->dev = device_create(class, NULL,
				MKDEV(MAJOR(user_mmio_devt), cs->id),
				cs, "user_mmio_clksrc/%d", cs->id);
	if (IS_ERR(cs->dev))
		return PTR_ERR(cs->dev);

	spin_lock_init(&cs->lock);
	hash_init(cs->mappings);

	cdev_init(&cs->char_dev, &user_mmio_clksrc_fops);
	cs->char_dev.kobj.parent = &cs->dev->kobj;

	err = cdev_add(&cs->char_dev, cs->dev->devt, 1);
	if (err < 0)
		goto err_device_destroy;

	return 0;

err_device_destroy:
	device_destroy(class, MKDEV(MAJOR(user_mmio_devt), cs->id));
	return err;
}

static unsigned long default_revmap(void *virt)
{
	struct vm_struct *vm;

	vm = find_vm_area(virt);
	if (!vm)
		return 0;

	return vm->phys_addr + (virt - vm->addr);
}

typedef u64 clksrc_read_t(struct clocksource *);
typedef unsigned long clksrc_revmap_t(void *);

int __init clocksource_user_dual_mmio_init(
	void __iomem *reg_lower, unsigned int bits_lower,
	void __iomem *reg_upper, unsigned int bits_upper,
	const char *name, unsigned long hz, int rating,
	clksrc_read_t *read, clksrc_revmap_t *revmap)
{
	static clksrc_read_t *user_types[CLKSRC_MMIO_TYPE_NR] = {
		[CLKSRC_MMIO_L_UP] = clocksource_mmio_readl_up,
		[CLKSRC_MMIO_L_DOWN] = clocksource_mmio_readl_down,
		[CLKSRC_DMMIO_L_UP] = clocksource_dual_mmio_readl_up,
		[CLKSRC_MMIO_W_UP] = clocksource_mmio_readw_up,
		[CLKSRC_MMIO_W_DOWN] = clocksource_mmio_readw_down,
		[CLKSRC_DMMIO_W_UP] = clocksource_dual_mmio_readw_up,
	};
	unsigned long phys_upper, phys_lower;
	struct clocksource_user_mmio *cs;
	enum clksrc_user_mmio_type type;
	struct class *class = NULL;
	int err;

	if (bits_lower > 32 || bits_lower < 16 || bits_upper > 32)
		return -EINVAL;

	for (type = 0; type < ARRAY_SIZE(user_types); type++)
		if (read == user_types[type])
			break;

	if (type == ARRAY_SIZE(user_types))
		return -EINVAL;

	if (!revmap)
		revmap = default_revmap;

	phys_lower = revmap(reg_lower);
	if (!phys_lower)
		return -EINVAL;

	if (bits_upper) {
		phys_upper = revmap(reg_upper);
		if (!phys_upper)
			return -EINVAL;
	} else
		phys_upper = 0;

	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return -ENOMEM;

	spin_lock_init(&cs->lock);
	cs->type = type;
	cs->mask_lower = CLOCKSOURCE_MASK(bits_lower);
	cs->bits_lower = bits_lower;
	cs->reg_upper = reg_upper;
	cs->mask_upper = CLOCKSOURCE_MASK(bits_upper);

	_clocksource_mmio_init(reg_lower, name, hz, rating,
			       bits_lower + bits_upper, read, &cs->mmio);

	err = clocksource_register_hz(&cs->mmio.clksrc, hz);
	if (err < 0) {
		kfree(cs);
		return err;
	}

	cs->phys_lower = phys_lower;
	cs->phys_upper = phys_upper;

	spin_lock(&user_clksrcs_lock);
	cs->id = user_clksrcs_count++;
	if (cs->id < CLKSRC_USER_MMIO_MAX) {
		list_add_tail(&cs->link, &user_clksrcs);
		class = user_mmio_class;
	}
	spin_unlock(&user_clksrcs_lock);

#ifdef arch_clocksource_user_mmio_init
	arch_clocksource_user_mmio_init(&cs->mmio.clksrc, cs->id);
#endif

	if (cs->id >= CLKSRC_USER_MMIO_MAX)
		pr_warn("%s: Too many clocksources\n", name);

	if (class) {
		err = cs_create_char_dev(class, cs);
		if (err < 0)
			pr_warn("%s: Failed to add character device\n", name);
	}

	if (bits_lower != 32 || read != clocksource_dual_mmio_readl_up)
		return 0;

	/*
	 * Some architectures may prefer to only use the low 32 bits of the
	 * clocksource for latency reasons.
	 */
	clocksource_user_mmio_init(reg_lower,
				   kasprintf(GFP_KERNEL, "%s_low_32", name),
				   hz, rating + 1, bits_lower,
				   clocksource_mmio_readl_up, revmap);

	return 0;
}

static int __init mmio_clksrc_chr_dev_init(void)
{
	struct clocksource_user_mmio *cs;
	struct class *class;
	int err;

	class = class_create(THIS_MODULE, "user_mmio_clkcsrc");
	if (IS_ERR(class)) {
		pr_err("couldn't create user mmio clocksources class\n");
		return PTR_ERR(class);
	}

	err = alloc_chrdev_region(&user_mmio_devt, 0, CLKSRC_USER_MMIO_MAX,
				  "user_mmio_clksrc");
	if (err < 0) {
		pr_err("failed to allocate user mmio clocksources character devivces region\n");
		goto err_class_destroy;
	}

	/*
	 * Calling list_for_each_entry is safe here: clocksources are always
	 * added to the list tail, never removed.
	 */
	spin_lock(&user_clksrcs_lock);
	list_for_each_entry(cs, &user_clksrcs, link) {
		spin_unlock(&user_clksrcs_lock);

		err = cs_create_char_dev(class, cs);
		if (err < 0)
			pr_err("%s: Failed to add character device\n",
			       cs->mmio.clksrc.name);

		spin_lock(&user_clksrcs_lock);
	}
	user_mmio_class = class;
	spin_unlock(&user_clksrcs_lock);

	return 0;

err_class_destroy:
	class_destroy(class);
	return err;
}
device_initcall(mmio_clksrc_chr_dev_init);
