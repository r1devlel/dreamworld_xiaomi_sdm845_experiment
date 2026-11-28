/*
 * blk-mq scheduling framework
 *
 * Copyright (C) 2016 Jens Axboe
 *
 * 4.9 backport: schedulers share the device tag set with the block driver,
 * so there are no internal tags to juggle here.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/blk-mq.h>

#include <trace/events/block.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"

void blk_mq_sched_free_hctx_data(struct request_queue *q,
				 void (*exit)(struct blk_mq_hw_ctx *))
{
	struct blk_mq_hw_ctx *hctx;
	int i;

	queue_for_each_hw_ctx(q, hctx, i) {
		if (exit && hctx->sched_data)
			exit(hctx);
		kfree(hctx->sched_data);
		hctx->sched_data = NULL;
	}
}
EXPORT_SYMBOL_GPL(blk_mq_sched_free_hctx_data);

void blk_mq_sched_request_inserted(struct request *rq)
{
	trace_block_rq_insert(rq->q, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_request_inserted);

bool blk_mq_sched_try_merge(struct request_queue *q, struct bio *bio,
			    struct request **merged_request)
{
	struct request *rq;
	int el_ret;

	el_ret = elv_merge(q, &rq, bio);
	switch (el_ret) {
	case ELEVATOR_BACK_MERGE:
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
		if (!bio_attempt_back_merge(q, rq, bio))
			return false;
		if (attempt_back_merge(q, rq)) {
			*merged_request = rq;
			return true;
		}
		elv_merged_request(q, rq, ELEVATOR_BACK_MERGE);
		return true;
	case ELEVATOR_FRONT_MERGE:
		if (!blk_mq_sched_allow_merge(q, rq, bio))
			return false;
		if (!bio_attempt_front_merge(q, rq, bio))
			return false;
		if (attempt_front_merge(q, rq)) {
			*merged_request = rq;
			return true;
		}
		elv_merged_request(q, rq, ELEVATOR_FRONT_MERGE);
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(blk_mq_sched_try_merge);

bool __blk_mq_sched_bio_merge(struct request_queue *q, struct bio *bio)
{
	struct elevator_queue *e = q->elevator;

	if (e && e->uses_mq && e->type->mq.bio_merge) {
		struct blk_mq_ctx *ctx = blk_mq_get_ctx(q);
		struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

		blk_mq_put_ctx(ctx);
		return e->type->mq.bio_merge(hctx, bio);
	}

	return false;
}

bool blk_mq_sched_try_insert_merge(struct request_queue *q, struct request *rq)
{
	if (!rq_mergeable(rq))
		return false;

	return elv_attempt_insert_merge(q, rq);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_try_insert_merge);

static void blk_mq_sched_mark_restart_hctx(struct blk_mq_hw_ctx *hctx)
{
	set_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);
}

static bool blk_mq_sched_restart_hctx(struct blk_mq_hw_ctx *hctx)
{
	if (test_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state)) {
		clear_bit(BLK_MQ_S_SCHED_RESTART, &hctx->state);
		if (blk_mq_hctx_has_pending(hctx)) {
			blk_mq_run_hw_queue(hctx, true);
			return true;
		}
	}
	return false;
}

/*
 * Called after a driver tag has been freed to check whether a hctx needs to
 * be restarted.
 */
void blk_mq_sched_restart(struct blk_mq_hw_ctx *const hctx)
{
	struct blk_mq_tag_set *const set = hctx->queue->tag_set;
	struct request_queue *const queue = hctx->queue, *q;
	struct blk_mq_hw_ctx *hctx2;
	struct blk_mq_tags *const tags = hctx->tags;
	unsigned int i, j;

	if (set->flags & BLK_MQ_F_TAG_SHARED) {
		rcu_read_lock();
		list_for_each_entry_rcu(q, &set->tag_list, tag_set_list) {
			queue_for_each_hw_ctx(q, hctx2, i)
				if (hctx2->tags == tags &&
				    blk_mq_sched_restart_hctx(hctx2))
					goto done;
		}
		j = hctx->queue_num + 1;
		for (i = 0; i < queue->nr_hw_queues; i++, j++) {
			if (j == queue->nr_hw_queues)
				j = 0;
			hctx2 = queue->queue_hw_ctx[j];
			if (hctx2->tags == tags &&
			    blk_mq_sched_restart_hctx(hctx2))
				break;
		}
done:
		rcu_read_unlock();
	} else {
		blk_mq_sched_restart_hctx(hctx);
	}
}

void blk_mq_sched_insert_request(struct request *rq, bool at_head,
				 bool run_queue, bool async)
{
	struct request_queue *q = rq->q;
	struct elevator_queue *e = q->elevator;
	struct blk_mq_ctx *ctx = rq->mq_ctx;
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);

	if (e && e->uses_mq && e->type->mq.insert_requests) {
		LIST_HEAD(list);

		list_add(&rq->queuelist, &list);
		e->type->mq.insert_requests(hctx, &list, at_head);
	} else {
		spin_lock(&ctx->lock);
		__blk_mq_insert_request(hctx, rq, at_head);
		spin_unlock(&ctx->lock);
	}

	if (run_queue)
		blk_mq_run_hw_queue(hctx, async);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_insert_request);

void blk_mq_sched_insert_requests(struct request_queue *q,
				  struct blk_mq_ctx *ctx,
				  struct list_head *list, bool run_queue_async)
{
	struct blk_mq_hw_ctx *hctx = blk_mq_map_queue(q, ctx->cpu);
	struct elevator_queue *e = q->elevator;

	if (e && e->uses_mq && e->type->mq.insert_requests)
		e->type->mq.insert_requests(hctx, list, false);
	else
		blk_mq_insert_requests(hctx, ctx, list);

	blk_mq_run_hw_queue(hctx, run_queue_async);
}
EXPORT_SYMBOL_GPL(blk_mq_sched_insert_requests);

void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
{
	struct request_queue *q = hctx->queue;
	struct elevator_queue *e = q->elevator;
	const bool has_sched_dispatch = e && e->uses_mq &&
					e->type->mq.dispatch_request;
	bool did_work = false;
	LIST_HEAD(rq_list);

	if (unlikely(blk_mq_hctx_stopped(hctx)))
		return;

	hctx->run++;

	/*
	 * If we have previous entries on our dispatch list, grab them first
	 * for more fair dispatch.
	 */
	if (!list_empty_careful(&hctx->dispatch)) {
		spin_lock(&hctx->lock);
		if (!list_empty(&hctx->dispatch))
			list_splice_init(&hctx->dispatch, &rq_list);
		spin_unlock(&hctx->lock);
	}

	/*
	 * Only ask the scheduler for requests if we didn't have residual
	 * requests from the dispatch list. Mark hctx for a restart in that
	 * case, as we can no longer merge or sort them.
	 */
	if (!list_empty(&rq_list)) {
		blk_mq_sched_mark_restart_hctx(hctx);
		did_work = blk_mq_dispatch_rq_list(hctx, &rq_list);
	} else if (!has_sched_dispatch) {
		blk_mq_flush_busy_ctxs(hctx, &rq_list);
		blk_mq_dispatch_rq_list(hctx, &rq_list);
	}

	if (!did_work && has_sched_dispatch) {
		do {
			struct request *rq;

			rq = e->type->mq.dispatch_request(hctx);
			if (!rq)
				break;
			list_add(&rq->queuelist, &rq_list);
		} while (blk_mq_dispatch_rq_list(hctx, &rq_list));
	}
}
EXPORT_SYMBOL_GPL(blk_mq_sched_dispatch_requests);

int blk_mq_sched_init_hctx(struct request_queue *q, struct blk_mq_hw_ctx *hctx,
			   unsigned int hctx_idx)
{
	struct elevator_queue *e = q->elevator;
	int ret = 0;

	if (!e || !e->uses_mq)
		return 0;

	if (e->type->mq.init_hctx) {
		ret = e->type->mq.init_hctx(hctx, hctx_idx);
		if (ret)
			hctx->sched_data = NULL;
	}

	return ret;
}

void blk_mq_sched_exit_hctx(struct request_queue *q, struct blk_mq_hw_ctx *hctx,
			    unsigned int hctx_idx)
{
	struct elevator_queue *e = q->elevator;

	if (!e || !e->uses_mq)
		return;

	if (e->type->mq.exit_hctx && hctx->sched_data) {
		e->type->mq.exit_hctx(hctx, hctx_idx);
		hctx->sched_data = NULL;
	}
}

int blk_mq_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;
	int ret;

	if (!e)
		return 0;

	ret = e->mq.init_sched(q, e);
	if (ret)
		return ret;

	if (e->mq.init_hctx) {
		queue_for_each_hw_ctx(q, hctx, i) {
			ret = e->mq.init_hctx(hctx, i);
			if (ret)
				goto err;
		}
	}

	ret = elv_register_queue(q);
	if (ret)
		goto err;

	return 0;
err:
	blk_mq_exit_sched(q, q->elevator);
	return ret;
}
EXPORT_SYMBOL_GPL(blk_mq_init_sched);

void blk_mq_exit_sched(struct request_queue *q, struct elevator_queue *e)
{
	struct blk_mq_hw_ctx *hctx;
	unsigned int i;

	if (!e)
		return;

	if (e->type->mq.exit_hctx) {
		queue_for_each_hw_ctx(q, hctx, i) {
			if (hctx->sched_data) {
				e->type->mq.exit_hctx(hctx, i);
				hctx->sched_data = NULL;
			}
		}
	}
	if (e->type->mq.exit_sched)
		e->type->mq.exit_sched(e);

	if (e->registered)
		elv_unregister_queue(q);
	kobject_put(&e->kobj);
	q->elevator = NULL;
}
EXPORT_SYMBOL_GPL(blk_mq_exit_sched);

int blk_mq_sched_init(struct request_queue *q)
{
	int ret;

	mutex_lock(&q->sysfs_lock);
	ret = elevator_init(q, NULL);
	mutex_unlock(&q->sysfs_lock);

	return ret;
}
