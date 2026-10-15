// SPDX-License-Identifier: GPL-2.0
/*
 * Legacy BPF trampoline manager.
 *
 * This file intentionally provides only the generic lifecycle/RCU layer.
 * An architecture backend must implement arch_prepare_bpf_trampoline(), and
 * the native-function ftrace adapter must be available before BTF fentry/fexit
 * programs are enabled on that architecture.
 */
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/hash.h>
#include <linux/init.h>
#include <linux/memory.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>

#define TRAMPOLINE_HASH_BITS	10
#define TRAMPOLINE_TABLE_SIZE	(1 << TRAMPOLINE_HASH_BITS)

static struct hlist_head trampoline_table[TRAMPOLINE_TABLE_SIZE];
static DEFINE_MUTEX(trampoline_mutex);

static int bpf_trampoline_update(struct bpf_trampoline *tr)
{
	void *old_image = tr->image +
		((tr->selector + 1) & 1) * (PAGE_SIZE / 2);
	void *new_image = tr->image +
		(tr->selector & 1) * (PAGE_SIZE / 2);
	struct bpf_prog *progs[BPF_MAX_TRAMP_PROGS];
	struct bpf_prog **fentry = progs;
	struct bpf_prog **fexit;
	struct bpf_prog_aux *aux;
	int fentry_cnt = tr->progs_cnt[BPF_TRAMP_FENTRY];
	int fexit_cnt = tr->progs_cnt[BPF_TRAMP_FEXIT];
	int total = fentry_cnt + fexit_cnt;
	u32 flags = BPF_TRAMP_F_RESTORE_REGS;
	int err = 0;

	if (!tr->func.addr)
		return -EINVAL;
	if (total > BPF_MAX_TRAMP_PROGS)
		return -E2BIG;

	if (!total) {
		if (!tr->selector)
			return 0;
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_CALL,
					 old_image, NULL);
		if (!err) {
			/* Do not reclaim an image while a task can still execute it. */
			synchronize_rcu_tasks();
			tr->selector = 0;
		}
		return err;
	}

	fentry = progs;
	hlist_for_each_entry(aux, &tr->progs_hlist[BPF_TRAMP_FENTRY],
			     tramp_hlist)
		*fentry++ = aux->prog;
	fexit = fentry;
	hlist_for_each_entry(aux, &tr->progs_hlist[BPF_TRAMP_FEXIT],
			     tramp_hlist)
		*fexit++ = aux->prog;

	if (fexit_cnt)
		flags = BPF_TRAMP_F_CALL_ORIG | BPF_TRAMP_F_SKIP_FRAME;
	if (tr->func.native_entry)
		flags |= BPF_TRAMP_F_NATIVE_ENTRY;

	/*
	 * The image halves are updated alternately. Wait for task-context
	 * users before reusing code that may have been selected previously.
	 */
	if (tr->selector)
		synchronize_rcu_tasks();

	err = arch_prepare_bpf_trampoline(new_image, &tr->func.model, flags,
					  progs, fentry_cnt, fexit,
					  fexit_cnt, tr->func.addr);
	if (err)
		return err;

	if (tr->selector)
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_CALL,
					 old_image, new_image);
	else
		err = bpf_arch_text_poke(tr->func.addr, BPF_MOD_CALL,
					 NULL, new_image);
	if (err)
		return err;

	tr->selector++;
	return 0;
}

struct bpf_trampoline *bpf_trampoline_lookup(u64 key)
{
	struct bpf_trampoline *tr;
	struct hlist_head *head;
	void *image;
	int i, err;

	mutex_lock(&trampoline_mutex);
	head = &trampoline_table[hash_64(key, TRAMPOLINE_HASH_BITS)];
	hlist_for_each_entry(tr, head, hlist) {
		if (tr->key == key) {
			refcount_inc(&tr->refcnt);
			goto out;
		}
	}

	tr = kzalloc(sizeof(*tr), GFP_KERNEL);
	if (!tr)
		goto out;

	image = bpf_jit_alloc_exec(PAGE_SIZE);
	if (!image) {
		kfree(tr);
		tr = NULL;
		goto out;
	}

	set_vm_flush_reset_perms(image);
	err = set_memory_x((unsigned long)image, 1);
	if (err) {
		bpf_jit_free_exec(image);
		kfree(tr);
		tr = NULL;
		goto out;
	}

	tr->key = key;
	tr->image = image;
	INIT_HLIST_NODE(&tr->hlist);
	refcount_set(&tr->refcnt, 1);
	mutex_init(&tr->mutex);
	for (i = 0; i < BPF_TRAMP_MAX; i++)
		INIT_HLIST_HEAD(&tr->progs_hlist[i]);
	hlist_add_head(&tr->hlist, head);
out:
	mutex_unlock(&trampoline_mutex);
	return tr;
}

struct bpf_trampoline *bpf_trampoline_get(u64 key,
					 struct btf_func_model *model, void *addr)
{
	struct bpf_trampoline *tr;
	int err = 0;

	if (!model || !addr || model->nr_args > MAX_BPF_FUNC_ARGS)
		return ERR_PTR(-EINVAL);

	tr = bpf_trampoline_lookup(key);
	if (!tr)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&tr->mutex);
	if (tr->func.addr) {
		if (tr->func.addr != addr || !tr->func.native_entry ||
		    tr->func.model.ret_size != model->ret_size ||
		    tr->func.model.nr_args != model->nr_args ||
		    memcmp(tr->func.model.arg_size, model->arg_size,
			   model->nr_args * sizeof(model->arg_size[0])))
			err = -EINVAL;
	} else {
		tr->func.model = *model;
		tr->func.addr = addr;
		tr->func.native_entry = true;
	}
	mutex_unlock(&tr->mutex);

	if (err) {
		bpf_trampoline_put(tr);
		return ERR_PTR(err);
	}

	return tr;
}

static enum bpf_tramp_prog_type bpf_attach_type_to_tramp(struct bpf_prog *prog)
{
	switch (prog->expected_attach_type) {
	case BPF_TRACE_FENTRY:
		return BPF_TRAMP_FENTRY;
	case BPF_TRACE_FEXIT:
		return BPF_TRAMP_FEXIT;
	default:
		return BPF_TRAMP_MAX;
	}
}

int bpf_trampoline_link_prog(struct bpf_prog *prog)
{
	struct bpf_trampoline *tr = prog->aux->trampoline;
	enum bpf_tramp_prog_type kind = bpf_attach_type_to_tramp(prog);
	int err;

	if (!tr || kind == BPF_TRAMP_MAX)
		return -EINVAL;

	mutex_lock(&tr->mutex);
	if (tr->progs_cnt[BPF_TRAMP_FENTRY] +
	    tr->progs_cnt[BPF_TRAMP_FEXIT] >= BPF_MAX_TRAMP_PROGS) {
		err = -E2BIG;
		goto out;
	}
	if (!hlist_unhashed(&prog->aux->tramp_hlist)) {
		err = -EBUSY;
		goto out;
	}

	hlist_add_head(&prog->aux->tramp_hlist, &tr->progs_hlist[kind]);
	tr->progs_cnt[kind]++;
	err = bpf_trampoline_update(tr);
	if (err) {
		hlist_del(&prog->aux->tramp_hlist);
		INIT_HLIST_NODE(&prog->aux->tramp_hlist);
		tr->progs_cnt[kind]--;
	}
out:
	mutex_unlock(&tr->mutex);
	return err;
}

int bpf_trampoline_unlink_prog(struct bpf_prog *prog)
{
	struct bpf_trampoline *tr = prog->aux->trampoline;
	enum bpf_tramp_prog_type kind = bpf_attach_type_to_tramp(prog);
	int err;

	if (!tr || kind == BPF_TRAMP_MAX)
		return -EINVAL;

	mutex_lock(&tr->mutex);
	if (hlist_unhashed(&prog->aux->tramp_hlist)) {
		err = -ENOENT;
		goto out;
	}
	hlist_del(&prog->aux->tramp_hlist);
	INIT_HLIST_NODE(&prog->aux->tramp_hlist);
	tr->progs_cnt[kind]--;
	err = bpf_trampoline_update(tr);
	if (err) {
		/* Keep the program alive if the previous image is still active. */
		hlist_add_head(&prog->aux->tramp_hlist, &tr->progs_hlist[kind]);
		tr->progs_cnt[kind]++;
	}
out:
	mutex_unlock(&tr->mutex);
	return err;
}

/*
 * Attach native fentry programs only after the verifier has resolved and
 * validated a core-kernel BTF function target. The per-program mutex makes
 * the trampoline reference and hlist membership a single attachment state.
 */
int bpf_trampoline_attach_prog(struct bpf_prog *prog)
{
	struct bpf_prog_aux *aux = prog->aux;
	struct bpf_trampoline *tr = NULL;
	int err;

	mutex_lock(&aux->trampoline_mutex);
	if (aux->trampoline || !hlist_unhashed(&aux->tramp_hlist)) {
		err = -EBUSY;
		goto out_unlock;
	}
	if (!aux->attach_func_addr || !aux->attach_func_key) {
		err = -EINVAL;
		goto out_unlock;
	}

	tr = bpf_trampoline_get(aux->attach_func_key,
				&aux->attach_func_model,
				aux->attach_func_addr);
	if (!tr) {
		err = -ENOMEM;
		goto out_unlock;
	}
	aux->trampoline = tr;
	err = bpf_trampoline_link_prog(prog);
	if (err)
		aux->trampoline = NULL;
	mutex_unlock(&aux->trampoline_mutex);

	if (err)
		bpf_trampoline_put(tr);
	return err;

out_unlock:
	mutex_unlock(&aux->trampoline_mutex);
	return err;
}

int bpf_trampoline_detach_prog(struct bpf_prog *prog)
{
	struct bpf_prog_aux *aux = prog->aux;
	struct bpf_trampoline *tr;
	int err;

	mutex_lock(&aux->trampoline_mutex);
	tr = aux->trampoline;
	if (!tr) {
		err = -ENOENT;
		goto out_unlock;
	}
	err = bpf_trampoline_unlink_prog(prog);
	if (!err)
		aux->trampoline = NULL;
	mutex_unlock(&aux->trampoline_mutex);

	/*
	 * unlink keeps the hlist reference when text restoration fails. Leave
	 * both the program and trampoline alive in that case, so a still-active
	 * entry patch cannot jump into freed BPF program memory.
	 */
	if (!err)
		bpf_trampoline_put(tr);
	return err;

out_unlock:
	mutex_unlock(&aux->trampoline_mutex);
	return err;
}

void bpf_trampoline_put(struct bpf_trampoline *tr)
{
	if (!tr)
		return;

	mutex_lock(&trampoline_mutex);
	if (!refcount_dec_and_test(&tr->refcnt))
		goto out;
	if (WARN_ON_ONCE(!hlist_empty(&tr->progs_hlist[BPF_TRAMP_FENTRY]) ||
			   !hlist_empty(&tr->progs_hlist[BPF_TRAMP_FEXIT]))) {
		/*
		 * A linked image must never be freed. Restore an anchor
		 * reference so a later lookup cannot increment a zero refcount.
		 * This deliberately leaks the object rather than risking use-after-free.
		 */
		refcount_set(&tr->refcnt, 1);
		goto out;
	}
	hlist_del(&tr->hlist);
	mutex_unlock(&trampoline_mutex);

	/* The site has been detached before the final reference is dropped. */
	synchronize_rcu_tasks();
	bpf_jit_free_exec(tr->image);
	kfree(tr);
	return;
out:
	mutex_unlock(&trampoline_mutex);
}

u64 notrace __bpf_prog_enter(void)
{
	preempt_disable();
	rcu_read_lock();
	return 0;
}

void notrace __bpf_prog_exit(struct bpf_prog *prog, u64 start)
{
	rcu_read_unlock();
	preempt_enable();
}

int __weak arch_prepare_bpf_trampoline(void *image,
				       struct btf_func_model *m, u32 flags,
				       struct bpf_prog **fentry_progs,
				       int fentry_cnt,
				       struct bpf_prog **fexit_progs,
				       int fexit_cnt,
				       void *orig_call)
{
	return -ENOTSUPP;
}

static int __init init_trampolines(void)
{
	int i;

	for (i = 0; i < TRAMPOLINE_TABLE_SIZE; i++)
		INIT_HLIST_HEAD(&trampoline_table[i]);
	return 0;
}
late_initcall(init_trampolines);
