/*
 *  linux/arch/arm/mm/dma-mapping.c
 *
 *  Copyright (C) 2000-2004 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *  DMA uncached mapping support.
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>

#include <asm/memory.h>
#include <asm/highmem.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/sizes.h>

/* Sanity check size */
#if (CONSISTENT_DMA_SIZE % SZ_2M)
#error "CONSISTENT_DMA_SIZE must be multiple of 2MiB"
#endif

#define CONSISTENT_END	(0xffe00000)
#define CONSISTENT_BASE	(CONSISTENT_END - CONSISTENT_DMA_SIZE)

#define CONSISTENT_OFFSET(x)	(((unsigned long)(x) - CONSISTENT_BASE) >> PAGE_SHIFT)
#define CONSISTENT_PTE_INDEX(x) (((unsigned long)(x) - CONSISTENT_BASE) >> PGDIR_SHIFT)
#define NUM_CONSISTENT_PTES (CONSISTENT_DMA_SIZE >> PGDIR_SHIFT)


/*
 * These are the page tables (2MB each) covering uncached, DMA consistent allocations
 */
static pte_t *consistent_pte[NUM_CONSISTENT_PTES];
static DEFINE_SPINLOCK(consistent_lock);

/*
 * VM region handling support.
 *
 * This should become something generic, handling VM region allocations for
 * vmalloc and similar (ioremap, module space, etc).
 *
 * I envisage vmalloc()'s supporting vm_struct becoming:
 *
 *  struct vm_struct {
 *    struct vm_region	region;
 *    unsigned long	flags;
 *    struct page	**pages;
 *    unsigned int	nr_pages;
 *    unsigned long	phys_addr;
 *  };
 *
 * get_vm_area() would then call vm_region_alloc with an appropriate
 * struct vm_region head (eg):
 *
 *  struct vm_region vmalloc_head = {
 *	.vm_list	= LIST_HEAD_INIT(vmalloc_head.vm_list),
 *	.vm_start	= VMALLOC_START,
 *	.vm_end		= VMALLOC_END,
 *  };
 *
 * However, vmalloc_head.vm_start is variable (typically, it is dependent on
 * the amount of RAM found at boot time.)  I would imagine that get_vm_area()
 * would have to initialise this each time prior to calling vm_region_alloc().
 */
struct arm_vm_region {
	struct list_head	vm_list;
	unsigned long		vm_start;
	unsigned long		vm_end;
	struct page		*vm_pages;
	int			vm_active;
};

static struct arm_vm_region consistent_head = {
	.vm_list	= LIST_HEAD_INIT(consistent_head.vm_list),
	.vm_start	= CONSISTENT_BASE,
	.vm_end		= CONSISTENT_END,
};

static struct arm_vm_region *
arm_vm_region_alloc(struct arm_vm_region *head, size_t size, gfp_t gfp)
{
	unsigned long addr = head->vm_start, end = head->vm_end - size;
	unsigned long flags;
	struct arm_vm_region *c, *new;

	new = kmalloc(sizeof(struct arm_vm_region), gfp);
	if (!new)
		goto out;

	spin_lock_irqsave(&consistent_lock, flags);

	list_for_each_entry(c, &head->vm_list, vm_list) {
		if ((addr + size) < addr)
			goto nospc;
		if ((addr + size) <= c->vm_start)
			goto found;
		addr = c->vm_end;
		if (addr > end)
			goto nospc;
	}

 found:
	/*
	 * Insert this entry _before_ the one we found.
	 */
	list_add_tail(&new->vm_list, &c->vm_list);
	new->vm_start = addr;
	new->vm_end = addr + size;
	new->vm_active = 1;

	spin_unlock_irqrestore(&consistent_lock, flags);
	return new;

 nospc:
	spin_unlock_irqrestore(&consistent_lock, flags);
	kfree(new);
 out:
	return NULL;
}

static struct arm_vm_region *arm_vm_region_find(struct arm_vm_region *head, unsigned long addr)
{
	struct arm_vm_region *c;
	
	list_for_each_entry(c, &head->vm_list, vm_list) {
		if (c->vm_active && c->vm_start == addr)
			goto out;
	}
	c = NULL;
 out:
	return c;
}

#ifdef CONFIG_HUGETLB_PAGE
#error ARM Coherent DMA allocator does not (yet) support huge TLB
#endif

static void *
__dma_alloc(struct device *dev, size_t size, dma_addr_t *handle, gfp_t gfp,
	    pgprot_t prot)
{
	struct page *page;
	struct arm_vm_region *c;
	unsigned long order;
	u64 mask = ISA_DMA_THRESHOLD, limit;

	if (!consistent_pte[0]) {
		printk(KERN_ERR "%s: not initialised\n", __func__);
		dump_stack();
		return NULL;
	}

	if (dev) {
		mask = dev->coherent_dma_mask;

		/*
		 * Sanity check the DMA mask - it must be non-zero, and
		 * must be able to be satisfied by a DMA allocation.
		 */
		if (mask == 0) {
			dev_warn(dev, "coherent DMA mask is unset\n");
			goto no_page;
		}

		if ((~mask) & ISA_DMA_THRESHOLD) {
			dev_warn(dev, "coherent DMA mask %#llx is smaller "
				 "than system GFP_DMA mask %#llx\n",
				 mask, (unsigned long long)ISA_DMA_THRESHOLD);
			goto no_page;
		}
	}

	/*
	 * Sanity check the allocation size.
	 */
	size = PAGE_ALIGN(size);
	limit = (mask + 1) & ~mask;
	if ((limit && size >= limit) ||
	    size >= (CONSISTENT_END - CONSISTENT_BASE)) {
		printk(KERN_WARNING "coherent allocation too big "
		       "(requested %#x mask %#llx)\n", size, mask);
		goto no_page;
	}

	order = get_order(size);

	if (mask != 0xffffffff)
		gfp |= GFP_DMA;

	page = alloc_pages(gfp, order);
	if (!page)
		goto no_page;

	/*
	 * Invalidate any data that might be lurking in the
	 * kernel direct-mapped region for device DMA.
	 */
	{
		void *ptr = page_address(page);
		memset(ptr, 0, size);
		dmac_flush_range(ptr, ptr + size);
		outer_flush_range(__pa(ptr), __pa(ptr) + size);
	}

	/*
	 * Allocate a virtual address in the consistent mapping region.
	 */
	c = arm_vm_region_alloc(&consistent_head, size,
			    gfp & ~(__GFP_DMA | __GFP_HIGHMEM));
	if (c) {
		pte_t *pte;
		struct page *end = page + (1 << order);
		int idx = CONSISTENT_PTE_INDEX(c->vm_start);
		u32 off = CONSISTENT_OFFSET(c->vm_start) & (PTRS_PER_PTE-1);

		pte = consistent_pte[idx] + off;
		c->vm_pages = page;

		split_page(page, order);

		/*
		 * Set the "dma handle"
		 */
		*handle = page_to_dma(dev, page);

		do {
			BUG_ON(!pte_none(*pte));

			/*
			 * x86 does not mark the pages reserved...
			 */
			SetPageReserved(page);
			set_pte_ext(pte, mk_pte(page, prot), 0);
			page++;
			pte++;
			off++;
			if (off >= PTRS_PER_PTE) {
				off = 0;
				pte = consistent_pte[++idx];
			}
		} while (size -= PAGE_SIZE);

		/*
		 * Free the otherwise unused pages.
		 */
		while (page < end) {
			__free_page(page);
			page++;
		}

		return (void *)c->vm_start;
	}

	if (page)
		__free_pages(page, order);
 no_page:
	*handle = ~0;
	return NULL;
}

/*
 * Allocate DMA-coherent memory space and return both the kernel remapped
 * virtual and bus address for that space.
 */
void *
dma_alloc_coherent(struct device *dev, size_t size, dma_addr_t *handle, gfp_t gfp)
{
	void *memory;

	if (dma_alloc_from_coherent(dev, size, handle, &memory))
		return memory;

	if (arch_is_coherent()) {
		void *virt;

		virt = kmalloc(size, gfp);
		if (!virt)
			return NULL;
		*handle =  virt_to_dma(dev, virt);

		return virt;
	}

	return __dma_alloc(dev, size, handle, gfp,
			   pgprot_noncached(pgprot_kernel));
}
EXPORT_SYMBOL(dma_alloc_coherent);

/*
 * Allocate a writecombining region, in much the same way as
 * dma_alloc_coherent above.
 */
void *
dma_alloc_writecombine(struct device *dev, size_t size, dma_addr_t *handle, gfp_t gfp)
{
	return __dma_alloc(dev, size, handle, gfp,
			   pgprot_writecombine(pgprot_kernel));
}
EXPORT_SYMBOL(dma_alloc_writecombine);

static int dma_mmap(struct device *dev, struct vm_area_struct *vma,
		    void *cpu_addr, dma_addr_t dma_addr, size_t size)
{
	unsigned long flags, user_size, kern_size;
	struct arm_vm_region *c;
	int ret = -ENXIO;

	user_size = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

	spin_lock_irqsave(&consistent_lock, flags);
	c = arm_vm_region_find(&consistent_head, (unsigned long)cpu_addr);
	spin_unlock_irqrestore(&consistent_lock, flags);

	if (c) {
		unsigned long off = vma->vm_pgoff;

		kern_size = (c->vm_end - c->vm_start) >> PAGE_SHIFT;

		if (off < kern_size &&
		    user_size <= (kern_size - off)) {
			ret = remap_pfn_range(vma, vma->vm_start,
					      page_to_pfn(c->vm_pages) + off,
					      user_size << PAGE_SHIFT,
					      vma->vm_page_prot);
		}
	}

	return ret;
}

int dma_mmap_coherent(struct device *dev, struct vm_area_struct *vma,
		      void *cpu_addr, dma_addr_t dma_addr, size_t size)
{
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return dma_mmap(dev, vma, cpu_addr, dma_addr, size);
}
EXPORT_SYMBOL(dma_mmap_coherent);

int dma_mmap_writecombine(struct device *dev, struct vm_area_struct *vma,
			  void *cpu_addr, dma_addr_t dma_addr, size_t size)
{
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	return dma_mmap(dev, vma, cpu_addr, dma_addr, size);
}
EXPORT_SYMBOL(dma_mmap_writecombine);

/*
 * free a page as defined by the above mapping.
 * Must not be called with IRQs disabled.
 */
void dma_free_coherent(struct device *dev, size_t size, void *cpu_addr, dma_addr_t handle)
{
	struct arm_vm_region *c;
	unsigned long flags, addr;
	pte_t *ptep;
	int idx;
	u32 off;

	WARN_ON(irqs_disabled());

	if (dma_release_from_coherent(dev, get_order(size), cpu_addr))
		return;

	if (arch_is_coherent()) {
		kfree(cpu_addr);
		return;
	}

	size = PAGE_ALIGN(size);

	spin_lock_irqsave(&consistent_lock, flags);
	c = arm_vm_region_find(&consistent_head, (unsigned long)cpu_addr);
	if (!c)
		goto no_area;

	c->vm_active = 0;
	spin_unlock_irqrestore(&consistent_lock, flags);

	if ((c->vm_end - c->vm_start) != size) {
		printk(KERN_ERR "%s: freeing wrong coherent size (%ld != %d)\n",
		       __func__, c->vm_end - c->vm_start, size);
		dump_stack();
		size = c->vm_end - c->vm_start;
	}

	idx = CONSISTENT_PTE_INDEX(c->vm_start);
	off = CONSISTENT_OFFSET(c->vm_start) & (PTRS_PER_PTE-1);
	ptep = consistent_pte[idx] + off;
	addr = c->vm_start;
	do {
		pte_t pte = ptep_get_and_clear(&init_mm, addr, ptep);
		unsigned long pfn;

		ptep++;
		addr += PAGE_SIZE;
		off++;
		if (off >= PTRS_PER_PTE) {
			off = 0;
			ptep = consistent_pte[++idx];
		}

		if (!pte_none(pte) && pte_present(pte)) {
			pfn = pte_pfn(pte);

			if (pfn_valid(pfn)) {
				struct page *page = pfn_to_page(pfn);

				/*
				 * x86 does not mark the pages reserved...
				 */
				ClearPageReserved(page);

				__free_page(page);
				continue;
			}
		}

		printk(KERN_CRIT "%s: bad page in kernel page table\n",
		       __func__);
	} while (size -= PAGE_SIZE);

	flush_tlb_kernel_range(c->vm_start, c->vm_end);

	spin_lock_irqsave(&consistent_lock, flags);
	list_del(&c->vm_list);
	spin_unlock_irqrestore(&consistent_lock, flags);

	kfree(c);
	return;

 no_area:
	spin_unlock_irqrestore(&consistent_lock, flags);
	printk(KERN_ERR "%s: trying to free invalid coherent area: %p\n",
	       __func__, cpu_addr);
	dump_stack();
}
EXPORT_SYMBOL(dma_free_coherent);

/*
 * Initialise the consistent memory allocation.
 */
static int __init consistent_init(void)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	int ret = 0, i = 0;
	u32 base = CONSISTENT_BASE;

	do {
		pgd = pgd_offset(&init_mm, base);
		pmd = pmd_alloc(&init_mm, pgd, base);
		if (!pmd) {
			printk(KERN_ERR "%s: no pmd tables\n", __func__);
			ret = -ENOMEM;
			break;
		}
		WARN_ON(!pmd_none(*pmd));

		pte = pte_alloc_kernel(pmd, base);
		if (!pte) {
			printk(KERN_ERR "%s: no pte tables\n", __func__);
			ret = -ENOMEM;
			break;
		}

		consistent_pte[i++] = pte;
		base += (1 << PGDIR_SHIFT);
	} while (base < CONSISTENT_END);

	return ret;
}

core_initcall(consistent_init);

#if defined(CONFIG_ARCH_OX820) && defined(CONFIG_SMP)
#include <mach/rps-irq.h>
#include <mach/ipi.h>
#include <mach/rps-timer.h>

extern int gic_set_cpu(unsigned int irq, const struct cpumask *mask_val);

extern asmlinkage void local_v6_dma_inv_range(const void *, const void *);
extern asmlinkage void local_v6_dma_clean_range(const void *, const void *);
extern asmlinkage void local_v6_dma_flush_range(const void *, const void *);

/*
 * Make an area consistent for devices.
 * Note: Drivers should NOT use this function directly, as it will break
 * platforms with CONFIG_DMABOUNCE.
 * Use the driver DMA support - see dma-mapping.h (dma_sync_*)
 *
 * PLX: IPI s/w broadcast of cache operations on MPCore in software does not
 *      support outer cache operations at present. If we did then the inner
 *      cache ops on all CPUs could happen in parallel, but the outer cache
 *      ops would have to happen only from a single CPU once inner cache ops
 *      had completed on all CPUs
 */
void dma_cache_maint(
	const void *start,
	size_t      size,
	int         direction)
{
	unsigned long flags;
	unsigned int  cpu;
	cpumask_t     callmap;
    struct fiq_coherency_communication_s* comms;
#ifdef CONFIG_FIQ_TIMEOUTS
	unsigned long start_ticks;
#endif // CONFIG_FIQ_TIMEOUTS

	/* Prevent re-entrance on this processor */
	local_irq_save(flags);
	cpu = get_cpu();
	
	/* We can support a maximum of 2 CPUs */
	BUG_ON(cpu > 1);

	/* Find the other CPU */
	callmap = cpu_online_map;
	cpu_clear(cpu, callmap);

    /* get the ipi work structure */
    comms = &(per_cpu(fiq_coherency_communication, cpu));

	/* If we're here when the other CPU is still processing a previous cache
	   coherency operation then something is wrong */
	BUG_ON(comms->nents);

#ifdef CONFIG_FIQS_USE_ACKS
	// Protocol violation if the cache ops ack flag is already set
	BUG_ON(comms->ack);
#endif // CONFIG_FIQS_USE_ACKS

	/* Only do this if there is another CPU active */
	if (!cpus_empty(callmap)) {
		/* Prepare one memory range */
		comms->type = CACHE_COHERENCY;
		comms->message.cache_coherency.type = direction;
		comms->message.cache_coherency.range[0].start = start;
		comms->message.cache_coherency.range[0].end = start + size;
		comms->nents = 1;
		smp_wmb();

#ifdef CONFIG_SERIALIZE_FIQS
		// Wait for exclusive access to the ability to raise a FIQ
		while (test_and_set_bit(CACHE_BRDCST_PRIV_FLAG, &cache_brdcst_priviledge));
#endif // CONFIG_SERIALIZE_FIQS

		/* Inform the other CPU that there's per-CPU data to examine */
		OX820_RPS_trigger_fiq((cpu == 0) ? 1 : 0);

#ifdef CONFIG_FIQS_USE_ACKS
		// Wait for the other CPU to enter the FIQ handler so no strex can occur
		// during the cache operations
#ifdef CONFIG_FIQ_TIMEOUTS
		start_ticks = *((volatile unsigned long*)TIMER2_VALUE);
#endif // CONFIG_FIQ_TIMEOUTS
		smp_rmb();
		while (!comms->ack) {
#ifdef CONFIG_FIQ_TIMEOUTS
			unsigned long elapsed_ticks;
			unsigned long now_ticks = *((volatile unsigned long*)TIMER2_VALUE);

			if (now_ticks > start_ticks) {
				elapsed_ticks = (TIMER_2_LOAD_VALUE - now_ticks) + start_ticks;
			} else {
				elapsed_ticks = start_ticks - now_ticks;
			}

			if (elapsed_ticks > TIMER_2_PRESCALED_CLK) {
				// Try to force a debug message out using serial interrupts on this
				// known functional CPU
				gic_set_cpu(55, cpumask_of(cpu));
				printk(KERN_WARNING "dma_cache_maint() Wait for FIQ ack took longer "
					"than 1 second, giving up (CPU %d, ticks 0x%p)\n", cpu,
					(void*)elapsed_ticks);
				break;
			}
#endif // CONFIG_FIQ_TIMEOUTS
			smp_rmb();
		}
#endif // CONFIG_FIQS_USE_ACKS
	}

	/* Run the local operation in parallel with the other CPU */
	switch (direction) {
		case DMA_BIDIRECTIONAL:
			local_v6_dma_flush_range(start, start + size);
			break;
		case DMA_TO_DEVICE:
			local_v6_dma_clean_range(start, start + size);
			break;
		case DMA_FROM_DEVICE:
			local_v6_dma_inv_range(start, start + size);
			break;
		default:
			printk(KERN_WARNING "Unknown DMA direction %d\n", direction);
	}

	/* Only do this if there is another CPU active */
	if (!cpus_empty(callmap)) {
#ifdef CONFIG_FIQS_USE_ACKS
		// Signal the other CPU that we have completed our cache ops
		comms->ack = 0;
		smp_wmb();
#endif // CONFIG_FIQS_USE_ACKS

		/* Rendezvous the two cpus here */
#ifdef CONFIG_FIQ_TIMEOUTS
		start_ticks = *((volatile unsigned long*)TIMER2_VALUE);
#endif // CONFIG_FIQ_TIMEOUTS
		smp_rmb();
		while (comms->nents) {
#ifdef CONFIG_FIQ_TIMEOUTS
			unsigned long elapsed_ticks;
			unsigned long now_ticks = *((volatile unsigned long*)TIMER2_VALUE);

			if (now_ticks > start_ticks) {
				elapsed_ticks = (TIMER_2_LOAD_VALUE - now_ticks) + start_ticks;
			} else {
				elapsed_ticks = start_ticks - now_ticks;
			}

			if (elapsed_ticks > TIMER_2_PRESCALED_CLK) {
				// Try to force a debug message out using serial interrupts on this
				// known functional CPU
				gic_set_cpu(55, cpumask_of(cpu));
				printk(KERN_WARNING "dma_cache_maint() Wait for sync took longer "
					"than 1 second, giving up (CPU %d, ticks 0x%p)\n", cpu,
					(void*)elapsed_ticks);
				break;
			}
#endif // CONFIG_FIQ_TIMEOUTS
			smp_rmb();
		}

#ifdef CONFIG_SERIALIZE_FIQS
		// Relinquish exclusive access to the ability to raise a FIQ
		clear_bit(CACHE_BRDCST_PRIV_FLAG, &cache_brdcst_priviledge);
#endif // CONFIG_SERIALIZE_FIQS
	}

	put_cpu();
	local_irq_restore(flags);
}

/*
 * PLX: IPI s/w broadcast of cache operations on MPCore in software does not
 *      support outer cache operations at present. If we did then the inner
 *      cache ops on all CPUs could happen in parallel, but the outer cache
 *      ops would have to happen only from a single CPU once inner cache ops
 *      had completed on all CPUs
 */
static void dma_cache_maint_contiguous(
	struct page  *page,
	unsigned long offset,
	size_t        size,
	int           direction)
{
	void *vaddr;
	int   himem = 0;

	/* Get virtual mapping for page and offset */
	if (!PageHighMem(page)) {
		vaddr = page_address(page) + offset;
	} else {
		vaddr = kmap_high_get(page);
		if (vaddr) {
			himem = 1;
			vaddr += offset;
		}
	}

	/* Only do cache op if retrieved a virtual mapping for the page */
	if (vaddr) {
		unsigned long flags;
		unsigned int  cpu;
		cpumask_t     callmap;
		struct fiq_coherency_communication_s* comms;
#ifdef CONFIG_FIQ_TIMEOUTS
		unsigned long start_ticks;
#endif // CONFIG_FIQ_TIMEOUTS

		/* Prevent re-entrance on this processor */
		local_irq_save(flags);
		cpu = get_cpu();
	
		/* We can support a maximum of 2 CPUs */
		BUG_ON(cpu > 1);

		/* Find the other CPU */
		callmap = cpu_online_map;
		cpu_clear(cpu, callmap);

		// get the ipi work structure
		comms = &(per_cpu(fiq_coherency_communication, cpu));

		/* If we're here when the other CPU is still processing a previous cache
		   coherency operation then something is wrong */
		BUG_ON(comms->nents);

#ifdef CONFIG_FIQS_USE_ACKS
		// Protocol violation if the cache ops ack flag is already set
		BUG_ON(comms->ack);
#endif // CONFIG_FIQS_USE_ACKS

		/* Only do this if there is another CPU active */
		if (!cpus_empty(callmap)) {
			/* Prepare one memory range */
			comms->type = CACHE_COHERENCY;
			comms->message.cache_coherency.type = direction;
			comms->message.cache_coherency.range[0].start = vaddr;
			comms->message.cache_coherency.range[0].end = vaddr + size;
			comms->nents = 1;
			smp_wmb();

#ifdef CONFIG_SERIALIZE_FIQS
			// Wait for exclusive access to the ability to raise a FIQ
			while (test_and_set_bit(CACHE_BRDCST_PRIV_FLAG, &cache_brdcst_priviledge));
#endif // CONFIG_SERIALIZE_FIQS

			/* Inform the other CPU that there's per-CPU data to examine */
			OX820_RPS_trigger_fiq((cpu == 0) ? 1 : 0);

#ifdef CONFIG_FIQS_USE_ACKS
			// Wait for the other CPU to enter the FIQ handler so no strex can occur
			// during the cache operations
#ifdef CONFIG_FIQ_TIMEOUTS
			start_ticks = *((volatile unsigned long*)TIMER2_VALUE);
#endif // CONFIG_FIQ_TIMEOUTS
			smp_rmb();
			while (!comms->ack) {
#ifdef CONFIG_FIQ_TIMEOUTS
				unsigned long elapsed_ticks;
				unsigned long now_ticks = *((volatile unsigned long*)TIMER2_VALUE);

				if (now_ticks > start_ticks) {
					elapsed_ticks = (TIMER_2_LOAD_VALUE - now_ticks) + start_ticks;
				} else {
					elapsed_ticks = start_ticks - now_ticks;
				}

				if (elapsed_ticks > TIMER_2_PRESCALED_CLK) {
					// Try to force a debug message out using serial interrupts on this
					// known functional CPU
					gic_set_cpu(55, cpumask_of(cpu));
					printk(KERN_WARNING "dma_cache_maint_contiguous() Wait for FIQ ack took longer "
						"than 1 second, giving up (CPU %d, ticks 0x%p)\n", cpu,
						(void*)elapsed_ticks);
					break;
				}
#endif // CONFIG_FIQ_TIMEOUTS
				smp_rmb();
			}
#endif // CONFIG_FIQS_USE_ACKS
		}

		/* Run the local operation in parallel with the other CPU */
		switch (direction) {
			case DMA_BIDIRECTIONAL:
				local_v6_dma_flush_range(vaddr, vaddr + size);
				break;
			case DMA_TO_DEVICE:
				local_v6_dma_clean_range(vaddr, vaddr + size);
				break;
			case DMA_FROM_DEVICE:
				local_v6_dma_inv_range(vaddr, vaddr + size);
				break;
			default:
				printk(KERN_WARNING "Unknown DMA direction %d\n", direction);
		}

		/* Only do this if there is another CPU active */
		if (!cpus_empty(callmap)) {
#ifdef CONFIG_FIQS_USE_ACKS
			// Signal the other CPU that we have completed our cache ops
			comms->ack = 0;
			smp_wmb();
#endif // CONFIG_FIQS_USE_ACKS

			/* Rendezvous the two cpus here */
#ifdef CONFIG_FIQ_TIMEOUTS
			start_ticks = *((volatile unsigned long*)TIMER2_VALUE);
#endif // CONFIG_FIQ_TIMEOUTS
			smp_rmb();
			while (comms->nents) {
#ifdef CONFIG_FIQ_TIMEOUTS
				unsigned long elapsed_ticks;
				unsigned long now_ticks = *((volatile unsigned long*)TIMER2_VALUE);

				if (now_ticks > start_ticks) {
					elapsed_ticks = (TIMER_2_LOAD_VALUE - now_ticks) + start_ticks;
				} else {
					elapsed_ticks = start_ticks - now_ticks;
				}

				if (elapsed_ticks > TIMER_2_PRESCALED_CLK) {
					// Try to force a debug message out using serial interrupts on this
					// known functional CPU
					gic_set_cpu(55, cpumask_of(cpu));
					printk(KERN_WARNING "dma_cache_maint_contiguous() Wait for sync took longer "
						"than 1 second, giving up (CPU %d, ticks 0x%p)\n", cpu,
						(void*)elapsed_ticks);
					break;
				}
#endif // CONFIG_FIQ_TIMEOUTS
				smp_rmb();
			}

#ifdef CONFIG_SERIALIZE_FIQS
			// Relinquish exclusive access to the ability to raise a FIQ
			clear_bit(CACHE_BRDCST_PRIV_FLAG, &cache_brdcst_priviledge);
#endif // CONFIG_SERIALIZE_FIQS
		}

		put_cpu();
		local_irq_restore(flags);
	}

	if (vaddr && himem) {
		kunmap_high(page);
	}
}
#else // defined(CONFIG_ARCH_OX820) && defined(CONFIG_SMP)
void dma_cache_maint(
	const void *start,
	size_t      size,
	int         direction)
{
	void (*inner_op)(const void *, const void *);
	void (*outer_op)(unsigned long, unsigned long);

	BUG_ON(!virt_addr_valid(start) || !virt_addr_valid(start + size - 1));

	switch (direction) {
	case DMA_FROM_DEVICE:		/* invalidate only */
		inner_op = dmac_inv_range;
		outer_op = outer_inv_range;
		break;
	case DMA_TO_DEVICE:		/* writeback only */
		inner_op = dmac_clean_range;
		outer_op = outer_clean_range;
		break;
	case DMA_BIDIRECTIONAL:		/* writeback and invalidate */
		inner_op = dmac_flush_range;
		outer_op = outer_flush_range;
		break;
	default:
		BUG();
	}

	inner_op(start, start + size);
	outer_op(__pa(start), __pa(start) + size);
}

static void dma_cache_maint_contiguous(
	struct page  *page,
	unsigned long offset,
	size_t        size,
	int           direction)
{
	void *vaddr;
	unsigned long paddr;
	void (*inner_op)(const void *, const void *);
	void (*outer_op)(unsigned long, unsigned long);

	switch (direction) {
	case DMA_FROM_DEVICE:		/* invalidate only */
		inner_op = dmac_inv_range;
		outer_op = outer_inv_range;
		break;
	case DMA_TO_DEVICE:		/* writeback only */
		inner_op = dmac_clean_range;
		outer_op = outer_clean_range;
		break;
	case DMA_BIDIRECTIONAL:		/* writeback and invalidate */
		inner_op = dmac_flush_range;
		outer_op = outer_flush_range;
		break;
	default:
		BUG();
	}

	if (!PageHighMem(page)) {
		vaddr = page_address(page) + offset;
		inner_op(vaddr, vaddr + size);
	} else {
		vaddr = kmap_high_get(page);
		if (vaddr) {
			vaddr += offset;
			inner_op(vaddr, vaddr + size);
			kunmap_high(page);
		}
	}

	paddr = page_to_phys(page) + offset;
	outer_op(paddr, paddr + size);
}
#endif // defined(CONFIG_ARCH_OX820) && defined(CONFIG_SMP)
EXPORT_SYMBOL(dma_cache_maint);

void dma_cache_maint_page(struct page *page, unsigned long offset,
			  size_t size, int dir)
{
	/*
	 * A single sg entry may refer to multiple physically contiguous
	 * pages.  But we still need to process highmem pages individually.
	 * If highmem is not configured then the bulk of this loop gets
	 * optimized out.
	 */
	size_t left = size;
	do {
		size_t len = left;
		if (PageHighMem(page) && len + offset > PAGE_SIZE) {
			if (offset >= PAGE_SIZE) {
				page += offset / PAGE_SIZE;
				offset %= PAGE_SIZE;
			}
			len = PAGE_SIZE - offset;
		}
		dma_cache_maint_contiguous(page, offset, len, dir);
		offset = 0;
		page++;
		left -= len;
	} while (left);
}
EXPORT_SYMBOL(dma_cache_maint_page);

#if !defined(CONFIG_ARCH_OX820) || !defined(CONFIG_SMP)
/**
 * dma_map_sg - map a set of SG buffers for streaming mode DMA
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to map
 * @dir: DMA transfer direction
 *
 * Map a set of buffers described by scatterlist in streaming mode for DMA.
 * This is the scatter-gather version of the dma_map_single interface.
 * Here the scatter gather list elements are each tagged with the
 * appropriate dma address and length.  They are obtained via
 * sg_dma_{address,length}.
 *
 * Device ownership issues as mentioned for dma_map_single are the same
 * here.
 */
int dma_map_sg(struct device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction dir)
{
	struct scatterlist *s;
	int i, j;

	for_each_sg(sg, s, nents, i) {
		s->dma_address = dma_map_page(dev, sg_page(s), s->offset,
						s->length, dir);
		if (dma_mapping_error(dev, s->dma_address))
			goto bad_mapping;
	}
	return nents;

 bad_mapping:
	for_each_sg(sg, s, i, j)
		dma_unmap_page(dev, sg_dma_address(s), sg_dma_len(s), dir);
	return 0;
}
EXPORT_SYMBOL(dma_map_sg);
#endif

/**
 * dma_unmap_sg - unmap a set of SG buffers mapped by dma_map_sg
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to unmap (returned from dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 *
 * Unmap a set of streaming mode DMA translations.  Again, CPU access
 * rules concerning calls here are the same as for dma_unmap_single().
 */
void dma_unmap_sg(struct device *dev, struct scatterlist *sg, int nents,
		enum dma_data_direction dir)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i)
		dma_unmap_page(dev, sg_dma_address(s), sg_dma_len(s), dir);
}
EXPORT_SYMBOL(dma_unmap_sg);

/**
 * dma_sync_sg_for_cpu
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to map (returned from dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 */
void dma_sync_sg_for_cpu(struct device *dev, struct scatterlist *sg,
			int nents, enum dma_data_direction dir)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i) {
		dmabounce_sync_for_cpu(dev, sg_dma_address(s), 0,
					sg_dma_len(s), dir);
	}
}
EXPORT_SYMBOL(dma_sync_sg_for_cpu);

/**
 * dma_sync_sg_for_device
 * @dev: valid struct device pointer, or NULL for ISA and EISA-like devices
 * @sg: list of buffers
 * @nents: number of buffers to map (returned from dma_map_sg)
 * @dir: DMA transfer direction (same as was passed to dma_map_sg)
 */
void dma_sync_sg_for_device(struct device *dev, struct scatterlist *sg,
			int nents, enum dma_data_direction dir)
{
	struct scatterlist *s;
	int i;

	for_each_sg(sg, s, nents, i) {
		if (!dmabounce_sync_for_device(dev, sg_dma_address(s), 0,
					sg_dma_len(s), dir))
			continue;

		if (!arch_is_coherent())
			dma_cache_maint_page(sg_page(s), s->offset,
					     s->length, dir);
	}
}
EXPORT_SYMBOL(dma_sync_sg_for_device);
