/*
 * The Kyber I/O scheduler. Controls latency by throttling queue depths using
 * scalable techniques.
 *
 * Copyright (C) 2017 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/sbitmap.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"

/* Scheduling domains. */
enum {
	KYBER_READ,
	KYBER_SYNC_WRITE,
	KYBER_OTHER, /* Async writes, discard, etc. */
	KYBER_NUM_DOMAINS,
};

enum {
	KYBER_MIN_DEPTH = 256,

	/*
	 * In order to prevent starvation of synchronous requests by a flood of
	 * asynchronous requests, we reserve 25% of requests for synchronous
	 * operations.
	 */
	KYBER_ASYNC_PERCENT = 75,
};

/*
 * Initial device-wide depths for each scheduling domain.
 *
 * Even for fast devices with lots of tags like NVMe, you can saturate
 * the device with only a fraction of the maximum possible queue depth.
 * So, we cap these to a reasonable value.
 */
static const unsigned int kyber_depth[] = {
	[KYBER_READ] = 256,
	[KYBER_SYNC_WRITE] = 128,
	[KYBER_OTHER] = 64,
};

/*
 * Scheduling domain batch sizes. We favor reads.
 */
static const unsigned int kyber_batch_size[] = {
	[KYBER_READ] = 16,
	[KYBER_SYNC_WRITE] = 8,
	[KYBER_OTHER] = 8,
};

struct kyber_queue_data {
	struct request_queue *q;

	/*
	 * The device is divided into multiple scheduling domains based on the
	 * request type. Each domain has a fixed number of in-flight requests of
	 * that type device-wide, limited by these tokens.
	 */
	struct sbitmap_queue domain_tokens[KYBER_NUM_DOMAINS];

	/*
	 * Async request percentage, converted to per-word depth for
	 * sbitmap_get_shallow().
	 */
	unsigned int async_depth;

	/* Target latencies in nanoseconds. */
	u64 read_lat_nsec, write_lat_nsec;
};

struct kyber_hctx_data {
	spinlock_t lock;
	struct list_head rqs[KYBER_NUM_DOMAINS];
	unsigned int cur_domain;
	unsigned int batching;
	wait_queue_t domain_wait[KYBER_NUM_DOMAINS];
	atomic_t wait_index[KYBER_NUM_DOMAINS];
};

static int rq_sched_domain(const struct request *rq)
{
	if (rq_data_dir(rq) == READ)
		return KYBER_READ;
	else if (rq_data_dir(rq) == WRITE && (rq->cmd_flags & REQ_SYNC))
		return KYBER_SYNC_WRITE;
	else
		return KYBER_OTHER;
}

static struct kyber_queue_data *kyber_queue_data_alloc(struct request_queue *q)
{
	struct kyber_queue_data *kqd;
	unsigned int max_tokens;
	unsigned int shift;
	int ret = -ENOMEM;
	int i;

	kqd = kmalloc_node(sizeof(*kqd), GFP_KERNEL, q->node);
	if (!kqd)
		goto err;
	kqd->q = q;

	/*
	 * The maximum number of tokens for any scheduling domain is at least
	 * the queue depth of a single hardware queue. If the hardware doesn't
	 * have many tags, still provide a reasonable number.
	 */
	max_tokens = max_t(unsigned int, q->tag_set->queue_depth,
			   KYBER_MIN_DEPTH);
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		WARN_ON(!kyber_depth[i]);
		WARN_ON(!kyber_batch_size[i]);
		ret = sbitmap_queue_init_node(&kqd->domain_tokens[i],
					      max_tokens, -1, false, GFP_KERNEL,
					      q->node);
		if (ret) {
			while (--i >= 0)
				sbitmap_queue_free(&kqd->domain_tokens[i]);
			goto err_kqd;
		}
		sbitmap_queue_resize(&kqd->domain_tokens[i], kyber_depth[i]);
	}

	kqd->async_depth = max_t(unsigned int, 1U,
				 max_tokens * KYBER_ASYNC_PERCENT / 100U);

	kqd->read_lat_nsec = 2000000ULL;
	kqd->write_lat_nsec = 10000000ULL;

	return kqd;

err_kqd:
	kfree(kqd);
err:
	return ERR_PTR(ret);
}

static int kyber_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct kyber_queue_data *kqd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	kqd = kyber_queue_data_alloc(q);
	if (IS_ERR(kqd)) {
		kobject_put(&eq->kobj);
		return PTR_ERR(kqd);
	}

	eq->elevator_data = kqd;
	eq->uses_mq = 1;
	q->elevator = eq;

	return 0;
}

static void kyber_exit_sched(struct elevator_queue *e)
{
	struct kyber_queue_data *kqd = e->elevator_data;
	struct request_queue *q = kqd->q;
	int i;

	for (i = 0; i < KYBER_NUM_DOMAINS; i++)
		sbitmap_queue_free(&kqd->domain_tokens[i]);
	kfree(kqd);
}

static int kyber_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct kyber_hctx_data *khd;
	int i;

	khd = kmalloc_node(sizeof(*khd), GFP_KERNEL, hctx->numa_node);
	if (!khd)
		return -ENOMEM;

	spin_lock_init(&khd->lock);

	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		INIT_LIST_HEAD(&khd->rqs[i]);
		INIT_LIST_HEAD(&khd->domain_wait[i].task_list);
		atomic_set(&khd->wait_index[i], 0);
	}

	khd->cur_domain = 0;
	khd->batching = 0;

	hctx->sched_data = khd;

	return 0;
}

static void kyber_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	kfree(hctx->sched_data);
}

static int rq_get_domain_token(struct request *rq)
{
	return (long)rq->elv.priv[0];
}

static void rq_set_domain_token(struct request *rq, int token)
{
	rq->elv.priv[0] = (void *)(long)token;
}

static void rq_clear_domain_token(struct kyber_queue_data *kqd,
				  struct request *rq)
{
	unsigned int sched_domain;
	int nr;

	nr = rq_get_domain_token(rq);
	if (nr != -1) {
		sched_domain = rq_sched_domain(rq);
		sbitmap_queue_clear(&kqd->domain_tokens[sched_domain], nr,
				    rq->mq_ctx->cpu);
	}
}

static void kyber_insert_requests(struct blk_mq_hw_ctx *hctx,
				  struct list_head *list, bool at_head)
{
	struct request *rq;

	while (!list_empty(list)) {
		rq = list_first_entry(list, struct request, queuelist);
		list_del_init(&rq->queuelist);
		rq_set_domain_token(rq, -1);
		spin_lock(&rq->mq_ctx->lock);
		__blk_mq_insert_request(hctx, rq, at_head);
		spin_unlock(&rq->mq_ctx->lock);
	}
}

static void kyber_completed_request(struct request *rq)
{
	struct kyber_queue_data *kqd = rq->q->elevator->elevator_data;

	rq_clear_domain_token(kqd, rq);
}

static void kyber_flush_busy_ctxs(struct kyber_hctx_data *khd,
				  struct blk_mq_hw_ctx *hctx)
{
	LIST_HEAD(rq_list);
	struct request *rq, *next;

	blk_mq_flush_busy_ctxs(hctx, &rq_list);
	list_for_each_entry_safe(rq, next, &rq_list, queuelist) {
		unsigned int sched_domain;

		sched_domain = rq_sched_domain(rq);
		list_move_tail(&rq->queuelist, &khd->rqs[sched_domain]);
	}
}

static int kyber_domain_wake(wait_queue_t *wait, unsigned mode, int flags,
			     void *key)
{
	struct blk_mq_hw_ctx *hctx = READ_ONCE(wait->private);

	list_del_init(&wait->task_list);
	blk_mq_run_hw_queue(hctx, true);
	return 1;
}

static int kyber_get_domain_token(struct kyber_queue_data *kqd,
				  struct kyber_hctx_data *khd,
				  struct blk_mq_hw_ctx *hctx)
{
	unsigned int sched_domain = khd->cur_domain;
	struct sbitmap_queue *domain_tokens = &kqd->domain_tokens[sched_domain];
	wait_queue_t *wait = &khd->domain_wait[sched_domain];
	struct sbq_wait_state *ws;
	int nr;

	nr = __sbitmap_queue_get(domain_tokens);
	if (nr >= 0)
		return nr;

	/*
	 * If we failed to get a domain token, make sure the hardware queue is
	 * run when one becomes available. Note that this is serialized on
	 * khd->lock, but we still need to be careful about the waker.
	 */
	if (list_empty_careful(&wait->task_list)) {
		init_waitqueue_func_entry(wait, kyber_domain_wake);
		wait->private = hctx;
		ws = sbq_wait_ptr(domain_tokens,
				  &khd->wait_index[sched_domain]);
		add_wait_queue(&ws->wait, wait);

		/*
		 * Try again in case a token was freed before we got on the wait
		 * queue.
		 */
		nr = __sbitmap_queue_get(domain_tokens);
	}
	return nr;
}

static struct request *
kyber_dispatch_cur_domain(struct kyber_queue_data *kqd,
			  struct kyber_hctx_data *khd,
			  struct blk_mq_hw_ctx *hctx,
			  bool *flushed)
{
	struct list_head *rqs;
	struct request *rq;
	int nr;

	rqs = &khd->rqs[khd->cur_domain];
	rq = list_first_entry_or_null(rqs, struct request, queuelist);

	/*
	 * If there wasn't already a pending request and we haven't flushed the
	 * software queues yet, flush the software queues and check again.
	 */
	if (!rq && !*flushed) {
		kyber_flush_busy_ctxs(khd, hctx);
		*flushed = true;
		rq = list_first_entry_or_null(rqs, struct request, queuelist);
	}

	if (rq) {
		nr = kyber_get_domain_token(kqd, khd, hctx);
		if (nr >= 0) {
			khd->batching++;
			rq_set_domain_token(rq, nr);
			list_del_init(&rq->queuelist);
			return rq;
		}
	}

	/* There were either no pending requests or no tokens. */
	return NULL;
}

static struct request *kyber_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct kyber_queue_data *kqd = hctx->queue->elevator->elevator_data;
	struct kyber_hctx_data *khd = hctx->sched_data;
	bool flushed = false;
	struct request *rq;
	int i;

	spin_lock(&khd->lock);

	/*
	 * First, if we are still entitled to batch, try to dispatch a request
	 * from the batch.
	 */
	if (khd->batching < kyber_batch_size[khd->cur_domain]) {
		rq = kyber_dispatch_cur_domain(kqd, khd, hctx, &flushed);
		if (rq)
			goto out;
	}

	/*
	 * Either,
	 * 1. We were no longer entitled to a batch.
	 * 2. The domain we were batching didn't have any requests.
	 * 3. The domain we were batching was out of tokens.
	 *
	 * Start another batch. Note that this wraps back around to the original
	 * domain if no other domains have requests or tokens.
	 */
	khd->batching = 0;
	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		if (khd->cur_domain == KYBER_NUM_DOMAINS - 1)
			khd->cur_domain = 0;
		else
			khd->cur_domain++;

		rq = kyber_dispatch_cur_domain(kqd, khd, hctx, &flushed);
		if (rq)
			goto out;
	}

	rq = NULL;
out:
	spin_unlock(&khd->lock);
	return rq;
}

static bool kyber_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct kyber_hctx_data *khd = hctx->sched_data;
	int i;

	for (i = 0; i < KYBER_NUM_DOMAINS; i++) {
		if (!list_empty_careful(&khd->rqs[i]))
			return true;
	}
	return false;
}

#define KYBER_LAT_SHOW_STORE(op)					\
static ssize_t kyber_##op##_lat_show(struct elevator_queue *e,		\
				     char *page)			\
{									\
	struct kyber_queue_data *kqd = e->elevator_data;		\
									\
	return sprintf(page, "%llu\n", kqd->op##_lat_nsec);		\
}									\
									\
static ssize_t kyber_##op##_lat_store(struct elevator_queue *e,		\
				      const char *page, size_t count)	\
{									\
	struct kyber_queue_data *kqd = e->elevator_data;		\
	unsigned long long nsec;					\
	int ret;							\
									\
	ret = kstrtoull(page, 10, &nsec);				\
	if (ret)							\
		return ret;						\
									\
	kqd->op##_lat_nsec = nsec;					\
									\
	return count;							\
}
KYBER_LAT_SHOW_STORE(read);
KYBER_LAT_SHOW_STORE(write);
#undef KYBER_LAT_SHOW_STORE

#define KYBER_LAT_ATTR(op) __ATTR(op##_lat_nsec, 0644, kyber_##op##_lat_show, kyber_##op##_lat_store)
static struct elv_fs_entry kyber_sched_attrs[] = {
	KYBER_LAT_ATTR(read),
	KYBER_LAT_ATTR(write),
	__ATTR_NULL
};
#undef KYBER_LAT_ATTR


static struct elevator_type kyber_sched = {
	.mq = {
		.init_sched = kyber_init_sched,
		.exit_sched = kyber_exit_sched,
		.init_hctx = kyber_init_hctx,
		.exit_hctx = kyber_exit_hctx,
		.insert_requests = kyber_insert_requests,
		.completed_request = kyber_completed_request,
		.dispatch_request = kyber_dispatch_request,
		.has_work = kyber_has_work,
	},
	.uses_mq = true,
	.elevator_attrs = kyber_sched_attrs,
	.elevator_name = "kyber",
	.elevator_owner = THIS_MODULE,
};

static int __init kyber_init(void)
{
	return elv_register(&kyber_sched);
}

static void __exit kyber_exit(void)
{
	elv_unregister(&kyber_sched);
}

module_init(kyber_init);
module_exit(kyber_exit);

MODULE_AUTHOR("Omar Sandoval");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Kyber I/O scheduler");
