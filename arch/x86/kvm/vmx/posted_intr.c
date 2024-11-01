// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kvm_host.h>
#include <linux/pkram.h>

#include <asm/irq_remapping.h>
#include <asm/cpu.h>

#include "lapic.h"
#include "posted_intr.h"
#include "trace.h"
#include "vmx.h"

/*
 * We maintain a per-CPU linked-list of vCPU, so in wakeup_handler() we
 * can find which vCPU should be waken up.
 */
static DEFINE_PER_CPU(struct list_head, blocked_vcpu_on_cpu);
static DEFINE_PER_CPU(spinlock_t, blocked_vcpu_on_cpu_lock);

static inline struct pi_desc *vcpu_to_pi_desc(struct kvm_vcpu *vcpu)
{
	return to_vmx(vcpu)->pi_desc;
}

void vmx_vcpu_pi_load(struct kvm_vcpu *vcpu, int cpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);
	struct pi_desc old, new;
	unsigned int dest;

	/*
	 * In case of hot-plug or hot-unplug, we may have to undo
	 * vmx_vcpu_pi_put even if there is no assigned device.  And we
	 * always keep PI.NDST up to date for simplicity: it makes the
	 * code easier, and CPU migration is not a fast path.
	 */
	if (!pi_test_sn(pi_desc) && vcpu->cpu == cpu)
		return;

	/*
	 * If the 'nv' field is POSTED_INTR_WAKEUP_VECTOR, do not change
	 * PI.NDST: pi_post_block is the one expected to change PID.NDST and the
	 * wakeup handler expects the vCPU to be on the blocked_vcpu_list that
	 * matches PI.NDST. Otherwise, a vcpu may not be able to be woken up
	 * correctly.
	 */
	if (pi_desc->nv == POSTED_INTR_WAKEUP_VECTOR || vcpu->cpu == cpu) {
		pi_clear_sn(pi_desc);
		goto after_clear_sn;
	}

	/* The full case.  */
	do {
		old.control = new.control = pi_desc->control;

		dest = cpu_physical_id(cpu);

		if (x2apic_mode)
			new.ndst = dest;
		else
			new.ndst = (dest << 8) & 0xFF00;

		new.sn = 0;
	} while (cmpxchg64(&pi_desc->control, old.control,
			   new.control) != old.control);

after_clear_sn:

	/*
	 * Clear SN before reading the bitmap.  The VT-d firmware
	 * writes the bitmap and reads SN atomically (5.2.3 in the
	 * spec), so it doesn't really have a memory barrier that
	 * pairs with this, but we cannot do that and we need one.
	 */
	smp_mb__after_atomic();

	if (!pi_is_pir_empty(pi_desc))
		pi_set_on(pi_desc);
}

void vmx_vcpu_pi_put(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	if (!kvm_arch_has_assigned_device(vcpu->kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP)  ||
		!kvm_vcpu_apicv_active(vcpu))
		return;

	/* Set SN when the vCPU is preempted */
	if (vcpu->preempted)
		pi_set_sn(pi_desc);
}

static void __pi_post_block(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);
	struct pi_desc old, new;
	unsigned int dest;

	do {
		old.control = new.control = pi_desc->control;
		WARN(old.nv != POSTED_INTR_WAKEUP_VECTOR,
		     "Wakeup handler not enabled while the VCPU is blocked\n");

		dest = cpu_physical_id(vcpu->cpu);

		if (x2apic_mode)
			new.ndst = dest;
		else
			new.ndst = (dest << 8) & 0xFF00;

		/* set 'NV' to 'notification vector' */
		new.nv = POSTED_INTR_VECTOR;
	} while (cmpxchg64(&pi_desc->control, old.control,
			   new.control) != old.control);

	if (!WARN_ON_ONCE(vcpu->pre_pcpu == -1)) {
		spin_lock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		list_del(&vcpu->blocked_vcpu_list);
		spin_unlock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		vcpu->pre_pcpu = -1;
	}
}

/*
 * This routine does the following things for vCPU which is going
 * to be blocked if VT-d PI is enabled.
 * - Store the vCPU to the wakeup list, so when interrupts happen
 *   we can find the right vCPU to wake up.
 * - Change the Posted-interrupt descriptor as below:
 *      'NDST' <-- vcpu->pre_pcpu
 *      'NV' <-- POSTED_INTR_WAKEUP_VECTOR
 * - If 'ON' is set during this process, which means at least one
 *   interrupt is posted for this vCPU, we cannot block it, in
 *   this case, return 1, otherwise, return 0.
 *
 */
int pi_pre_block(struct kvm_vcpu *vcpu)
{
	unsigned int dest;
	struct pi_desc old, new;
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	if (!kvm_arch_has_assigned_device(vcpu->kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP)  ||
		!kvm_vcpu_apicv_active(vcpu))
		return 0;

	WARN_ON(irqs_disabled());
	local_irq_disable();
	if (!WARN_ON_ONCE(vcpu->pre_pcpu != -1)) {
		vcpu->pre_pcpu = vcpu->cpu;
		spin_lock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
		list_add_tail(&vcpu->blocked_vcpu_list,
			      &per_cpu(blocked_vcpu_on_cpu,
				       vcpu->pre_pcpu));
		spin_unlock(&per_cpu(blocked_vcpu_on_cpu_lock, vcpu->pre_pcpu));
	}

	do {
		old.control = new.control = pi_desc->control;

		WARN((pi_desc->sn == 1),
		     "Warning: SN field of posted-interrupts "
		     "is set before blocking\n");

		/*
		 * Since vCPU can be preempted during this process,
		 * vcpu->cpu could be different with pre_pcpu, we
		 * need to set pre_pcpu as the destination of wakeup
		 * notification event, then we can find the right vCPU
		 * to wakeup in wakeup handler if interrupts happen
		 * when the vCPU is in blocked state.
		 */
		dest = cpu_physical_id(vcpu->pre_pcpu);

		if (x2apic_mode)
			new.ndst = dest;
		else
			new.ndst = (dest << 8) & 0xFF00;

		/* set 'NV' to 'wakeup vector' */
		new.nv = POSTED_INTR_WAKEUP_VECTOR;
	} while (cmpxchg64(&pi_desc->control, old.control,
			   new.control) != old.control);

	/* We should not block the vCPU if an interrupt is posted for it.  */
	if (pi_test_on(pi_desc) == 1)
		__pi_post_block(vcpu);

	local_irq_enable();
	return (vcpu->pre_pcpu == -1);
}

void pi_post_block(struct kvm_vcpu *vcpu)
{
	if (vcpu->pre_pcpu == -1)
		return;

	WARN_ON(irqs_disabled());
	local_irq_disable();
	__pi_post_block(vcpu);
	local_irq_enable();
}

/*
 * Handler for POSTED_INTERRUPT_WAKEUP_VECTOR.
 */
void pi_wakeup_handler(void)
{
	struct kvm_vcpu *vcpu;
	int cpu = smp_processor_id();

	spin_lock(&per_cpu(blocked_vcpu_on_cpu_lock, cpu));
	list_for_each_entry(vcpu, &per_cpu(blocked_vcpu_on_cpu, cpu),
			blocked_vcpu_list) {
		struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

		if (pi_test_on(pi_desc) == 1)
			kvm_vcpu_kick(vcpu);
	}
	spin_unlock(&per_cpu(blocked_vcpu_on_cpu_lock, cpu));
}

void __init pi_init_cpu(int cpu)
{
	INIT_LIST_HEAD(&per_cpu(blocked_vcpu_on_cpu, cpu));
	spin_lock_init(&per_cpu(blocked_vcpu_on_cpu_lock, cpu));
}

bool pi_has_pending_interrupt(struct kvm_vcpu *vcpu)
{
	struct pi_desc *pi_desc = vcpu_to_pi_desc(vcpu);

	return pi_test_on(pi_desc) ||
		(pi_test_sn(pi_desc) && !pi_is_pir_empty(pi_desc));
}


/*
 * Bail out of the block loop if the VM has an assigned
 * device, but the blocking vCPU didn't reconfigure the
 * PI.NV to the wakeup vector, i.e. the assigned device
 * came along after the initial check in pi_pre_block().
 */
void vmx_pi_start_assignment(struct kvm *kvm)
{
	if (!irq_remapping_cap(IRQ_POSTING_CAP))
		return;

	kvm_make_all_cpus_request(kvm, KVM_REQ_UNBLOCK);
}

/*
 * pi_update_irte - set IRTE for Posted-Interrupts
 *
 * @kvm: kvm
 * @host_irq: host irq of the interrupt
 * @guest_irq: gsi of the interrupt
 * @set: set or unset PI
 * returns 0 on success, < 0 on failure
 */
int pi_update_irte(struct kvm *kvm, unsigned int host_irq, uint32_t guest_irq,
		   bool set)
{
	struct kvm_kernel_irq_routing_entry *e;
	struct kvm_irq_routing_table *irq_rt;
	struct kvm_lapic_irq irq;
	struct kvm_vcpu *vcpu;
	struct vcpu_data vcpu_info;
	int idx, ret = 0;

	if (!kvm_arch_has_assigned_device(kvm) ||
	    !irq_remapping_cap(IRQ_POSTING_CAP) ||
	    !kvm_vcpu_apicv_active(kvm->vcpus[0]))
		return 0;

	idx = srcu_read_lock(&kvm->irq_srcu);
	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	if (guest_irq >= irq_rt->nr_rt_entries ||
	    hlist_empty(&irq_rt->map[guest_irq])) {
		pr_warn_once("no route for guest_irq %u/%u (broken user space?)\n",
			     guest_irq, irq_rt->nr_rt_entries);
		goto out;
	}

	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
		if (e->type != KVM_IRQ_ROUTING_MSI)
			continue;
		/*
		 * VT-d PI cannot support posting multicast/broadcast
		 * interrupts to a vCPU, we still use interrupt remapping
		 * for these kind of interrupts.
		 *
		 * For lowest-priority interrupts, we only support
		 * those with single CPU as the destination, e.g. user
		 * configures the interrupts via /proc/irq or uses
		 * irqbalance to make the interrupts single-CPU.
		 *
		 * We will support full lowest-priority interrupt later.
		 *
		 * In addition, we can only inject generic interrupts using
		 * the PI mechanism, refuse to route others through it.
		 */

		kvm_set_msi_irq(kvm, e, &irq);
		if (!kvm_intr_is_single_vcpu(kvm, &irq, &vcpu) ||
		    !kvm_irq_is_postable(&irq)) {
			/*
			 * Make sure the IRTE is in remapped mode if
			 * we don't handle it in posted mode.
			 */
			ret = irq_set_vcpu_affinity(host_irq, NULL);
			if (ret < 0) {
				printk(KERN_INFO
				   "failed to back to remapped mode, irq: %u\n",
				   host_irq);
				goto out;
			}

			continue;
		}

		vcpu_info.pi_desc_addr = __pa(vcpu_to_pi_desc(vcpu));
		vcpu_info.vector = irq.vector;

		trace_kvm_pi_irte_update(host_irq, vcpu->vcpu_id, e->gsi,
				vcpu_info.vector, vcpu_info.pi_desc_addr, set);

		if (set)
			ret = irq_set_vcpu_affinity(host_irq, &vcpu_info);
		else
			ret = irq_set_vcpu_affinity(host_irq, NULL);

		if (ret < 0) {
			printk(KERN_INFO "%s: failed to update PI IRTE\n",
					__func__);
			goto out;
		}
	}

	ret = 0;
out:
	srcu_read_unlock(&kvm->irq_srcu, idx);
	return ret;
}

struct vmx_keepalive_state {
	struct list_head list;
	int refcnt;
	int page_refcnt;
	struct page *page;
};

static unsigned long vmx_keepalive_state_count;
static LIST_HEAD(vmx_keepalive_state_list);
static DEFINE_MUTEX(vmx_keepalive_state_lock);

static int vmx_add_keepalive_pid_page(struct page *page)
{
	struct vmx_keepalive_state *state;

	mutex_lock(&vmx_keepalive_state_lock);
	list_for_each_entry(state, &vmx_keepalive_state_list, list) {
		if (state->page == page) {
			state->refcnt++;
			mutex_unlock(&vmx_keepalive_state_lock);
			return 0;
		}
	}
	state = kmalloc(sizeof(*state), GFP_KERNEL);
	if (!state) {
		mutex_unlock(&vmx_keepalive_state_lock);
		return -ENOMEM;
	}
	get_page(page);
	state->page = page;
	state->refcnt = 1;
	vmx_keepalive_state_count++;
	list_add(&state->list, &vmx_keepalive_state_list);
	mutex_unlock(&vmx_keepalive_state_lock);
	return 0;
}

static void vmx_remove_keepalive_pid_page(struct page *page)
{
	struct vmx_keepalive_state *state;

	mutex_lock(&vmx_keepalive_state_lock);
	list_for_each_entry(state, &vmx_keepalive_state_list, list) {
		if (state->page == page) {
			state->refcnt--;
			if (!state->refcnt) {
				put_page(page);
				list_del(&state->list);
				kfree(state);
				vmx_keepalive_state_count--;
			}
			break;
		}
	}
	mutex_unlock(&vmx_keepalive_state_lock);
}

static int __vmx_pkram_save(struct pkram_stream *ps)
{
	struct vmx_keepalive_state *state;
	PKRAM_ACCESS(pa_bytes, ps, bytes);
	PKRAM_ACCESS(pa_pages, ps, pages);
	ssize_t ret;

	ret = pkram_write(&pa_bytes, &vmx_keepalive_state_count,
			  sizeof(unsigned long));
	if (ret < 0)
		return ret;

	list_for_each_entry(state, &vmx_keepalive_state_list, list) {
		state->page_refcnt = page_ref_count(state->page);
		ret = pkram_write(&pa_bytes, state, sizeof(*state));
		if (ret < 0)
			return ret;
	}

	list_for_each_entry(state, &vmx_keepalive_state_list, list) {
		ret = pkram_save_file_page(&pa_pages, state->page);
		if (ret)
			return ret;
	}

	return 0;
}

int vmx_pkram_save(void)
{
	struct pkram_stream ps;
	int ret;

	ret = pkram_prepare_save(&ps, "vmx", GFP_KERNEL);
	if (ret)
		return ret;

	pkram_prepare_save_obj(&ps, PKRAM_DATA_pages | PKRAM_DATA_bytes);
	mutex_lock(&vmx_keepalive_state_lock);
	ret = __vmx_pkram_save(&ps);
	mutex_unlock(&vmx_keepalive_state_lock);
	pkram_finish_save_obj(&ps);

	if (!ret)
		pkram_finish_save(&ps);
	else
		pkram_discard_save(&ps);

	return ret;
}

static int __vmx_pkram_load(struct pkram_stream *ps)
{
	struct vmx_keepalive_state *state;
	PKRAM_ACCESS(pa_bytes, ps, bytes);
	PKRAM_ACCESS(pa_pages, ps, pages);
	struct page *page;
	ssize_t ret;
	int i;

	ret = pkram_read(&pa_bytes, &vmx_keepalive_state_count,
			 sizeof(unsigned long));
	if (ret < 0)
		return -1;

	for (i = 0; i < vmx_keepalive_state_count; i++) {
		state = kmalloc(sizeof(*state), GFP_KERNEL);
		if (!state)
			return -1;
		ret = pkram_read(&pa_bytes, state, sizeof(*state));
		if (ret < 0) {
			kfree(state);
			return -1;
		}
		state->page = NULL;
		list_add_tail(&state->list, &vmx_keepalive_state_list);
	}

	list_for_each_entry(state, &vmx_keepalive_state_list, list) {
		page = pkram_load_file_page(&pa_pages, NULL);
		if (!page)
			return -1;
		state->page = page;
	}

	list_for_each_entry(state, &vmx_keepalive_state_list, list)
		set_page_count(state->page, state->page_refcnt);

	return 0;
}

int vmx_pkram_load(void)
{
	struct vmx_keepalive_state *state;
	struct pkram_stream ps;
	int ret;

	ret = pkram_prepare_load(&ps, "vmx");
	if (ret)
		return ret;

	pkram_prepare_load_obj(&ps);
	mutex_lock(&vmx_keepalive_state_lock);
	ret = __vmx_pkram_load(&ps);

	if (ret) {
		while (!list_empty(&vmx_keepalive_state_list)) {
			state = list_first_entry(&vmx_keepalive_state_list,
						 struct vmx_keepalive_state,
						 list);
			if (state->page)
				__free_page(state->page);
			list_del(&state->list);
			kfree(state);
		}
		vmx_keepalive_state_count = 0;
	}
	mutex_unlock(&vmx_keepalive_state_lock);
	pkram_finish_load_obj(&ps);
	pkram_finish_load(&ps);
	return ret;
}

#define PAGE_PI_DESC_BITS	(PAGE_SIZE/sizeof(struct pi_desc))

static void pid_page_prepare(struct page *page)
{
	/* we can use the 5-word fields in struct page */
	INIT_LIST_HEAD(&page->lru);
	page->mapping = NULL;
	page->index = 0;
	page->private = 0;
}

/* use page->mapping as the pi_desc bitmap */
static unsigned long *page_pi_desc_bitmap(struct page *page)
{
	return (unsigned long *)&page->mapping;
}

static int pid_page_find_zero_bit(struct page *page)
{
	unsigned long *pi_desc_bitmap = page_pi_desc_bitmap(page);

	return find_first_zero_bit(pi_desc_bitmap, PAGE_PI_DESC_BITS);
}

static bool pid_page_empty(struct page *page)
{
	unsigned long *pi_desc_bitmap = page_pi_desc_bitmap(page);
	int num;

	num = find_first_bit(pi_desc_bitmap, PAGE_PI_DESC_BITS);
	return num >= PAGE_PI_DESC_BITS;
}

static void pid_page_set_bit(struct page *page, int num)
{
	unsigned long *pi_desc_bitmap = page_pi_desc_bitmap(page);

	set_bit(num, pi_desc_bitmap);
}

static void pid_page_clear_bit(struct page *page, int num)
{
	unsigned long *pi_desc_bitmap = page_pi_desc_bitmap(page);

	clear_bit(num, pi_desc_bitmap);
}

static bool pid_page_lru_linked(struct page *page)
{
	return !list_empty(&page->lru);
}

void vmx_init_pi_desc(struct kvm *kvm)
{
	struct kvm_vmx *kv = to_kvm_vmx(kvm);

	mutex_init(&kv->pid_page_lock);
	INIT_LIST_HEAD(&kv->pid_page_list);
}

int vmx_vcpu_alloc_pi_desc(struct kvm_vcpu *vcpu)
{
	struct kvm_vmx *kv = to_kvm_vmx(vcpu->kvm);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct page *page;
	int num;

	mutex_lock(&kv->pid_page_lock);

	list_for_each_entry(page, &kv->pid_page_list, lru) {
		num = pid_page_find_zero_bit(page);
		if (num < PAGE_PI_DESC_BITS) {
			get_page(page);
			goto found_pid;
		}
	}

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) {
		mutex_unlock(&kv->pid_page_lock);
		return -ENOMEM;
	}
	pid_page_prepare(page);
	list_add(&page->lru, &kv->pid_page_list);
	num = 0;
found_pid:
	pid_page_set_bit(page, num);
	vmx->pi_desc = page_to_virt(page) + num * sizeof(struct pi_desc);
	mutex_unlock(&kv->pid_page_lock);
	return 0;
}

static void __vmx_vcpu_free_pi_desc(struct vcpu_vmx *vmx)
{
	struct page *page;
	int num;

	page = virt_to_page((unsigned long)vmx->pi_desc & PAGE_MASK);
	num = ((unsigned long)vmx->pi_desc & ~PAGE_MASK) / sizeof(struct pi_desc);

	pid_page_clear_bit(page, num);
	if (pid_page_empty(page)) {
		list_del(&page->lru);
		INIT_LIST_HEAD(&page->lru);
	}
	put_page(page);
}

void vmx_vcpu_free_pi_desc(struct kvm_vcpu *vcpu)
{
	struct kvm_vmx *kv = to_kvm_vmx(vcpu->kvm);
	struct vcpu_vmx *vmx = to_vmx(vcpu);

	mutex_lock(&kv->pid_page_lock);

	__vmx_vcpu_free_pi_desc(vmx);

	mutex_unlock(&kv->pid_page_lock);
}

static int vmx_vcpu_save_pi_desc(struct kvm_vcpu *vcpu, void **data)
{
	struct kvm_vmx *kv = to_kvm_vmx(vcpu->kvm);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct page *page;
	int ret;

	mutex_lock(&kv->pid_page_lock);

	page = virt_to_page((unsigned long)vmx->pi_desc & PAGE_MASK);
	get_page(page);

	ret = vmx_add_keepalive_pid_page(page);
	if (ret) {
		mutex_unlock(&kv->pid_page_lock);
		return ret;
	}

	*data = (void *)virt_to_phys(vmx->pi_desc);
	pi_set_sn(vmx->pi_desc);

	mutex_unlock(&kv->pid_page_lock);
	return 0;
}

static void vmx_vcpu_load_pi_desc(struct kvm_vcpu *vcpu)
{
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	int cpu;

	cpu = get_cpu();
	vmx_vcpu_load(vcpu, cpu);
	if (kvm_vcpu_apicv_active(vcpu))
		vmcs_write64(POSTED_INTR_DESC_ADDR, __pa((vmx->pi_desc)));
	vmx_vcpu_put(vcpu);
	put_cpu();
}

static int vmx_vcpu_restore_pi_desc(struct kvm_vcpu *vcpu, void **data)
{
	struct kvm_vmx *kv = to_kvm_vmx(vcpu->kvm);
	struct vcpu_vmx *vmx = to_vmx(vcpu);
	struct pi_desc *pi_desc = phys_to_virt((phys_addr_t)*data);
	struct page *page;
	int num;

	page = virt_to_page((unsigned long)pi_desc & PAGE_MASK);
	num = ((unsigned long)pi_desc & ~PAGE_MASK) / sizeof(struct pi_desc);

	mutex_lock(&kv->pid_page_lock);

	if (vmx->pi_desc != pi_desc) {
		__vmx_vcpu_free_pi_desc(vmx);
		vmx->pi_desc = pi_desc;
		get_page(page);
	}

	pid_page_set_bit(page, num);
	if (!pid_page_lru_linked(page))
		list_add(&page->lru, &kv->pid_page_list);
	put_page(page);
	vmx_remove_keepalive_pid_page(page);

	mutex_unlock(&kv->pid_page_lock);

	vmx_vcpu_load_pi_desc(vcpu);

	return 0;
}

int pi_do_keepalive(struct kvm *kvm, int guest_irq, void **data, bool save)
{
	struct kvm_kernel_irq_routing_entry *e;
	struct kvm_irq_routing_table *irq_rt;
	struct kvm_lapic_irq irq;
	struct kvm_vcpu *vcpu;
	int idx, ret = 0;

	if (!kvm_arch_has_assigned_device(kvm) ||
		!irq_remapping_cap(IRQ_POSTING_CAP) ||
		!kvm_vcpu_apicv_active(kvm->vcpus[0]))
		return -ENOENT;

	idx = srcu_read_lock(&kvm->irq_srcu);
	irq_rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	if (guest_irq >= irq_rt->nr_rt_entries ||
	    hlist_empty(&irq_rt->map[guest_irq])) {
		pr_warn_once("no route for guest_irq %u/%u (broken user space?)\n",
			     guest_irq, irq_rt->nr_rt_entries);
		ret = -ENOENT;
		goto out;
	}

	hlist_for_each_entry(e, &irq_rt->map[guest_irq], link) {
		if (e->type != KVM_IRQ_ROUTING_MSI)
			continue;
		kvm_set_msi_irq(kvm, e, &irq);
		if (!kvm_intr_is_single_vcpu(kvm, &irq, &vcpu)) {
			ret = -EINVAL;
			goto out;
		}

		if (save)
			ret = vmx_vcpu_save_pi_desc(vcpu, data);
		else
			ret = vmx_vcpu_restore_pi_desc(vcpu, data);
		if (ret < 0) {
			printk(KERN_INFO "%s: failed to %s PID\n",
					__func__, save ? "save" : "restore");
			goto out;
		}
	}

	ret = 0;
out:
	srcu_read_unlock(&kvm->irq_srcu, idx);
	return ret;
}
