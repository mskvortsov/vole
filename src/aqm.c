/*
 * Codel - The Controlled-Delay Active Queue Management algorithm
 *
 *  Copyright (C) 2011-2012 Kathleen Nichols <nichols@pollere.com>
 *  Copyright (C) 2011-2012 Van Jacobson <van@pollere.net>
 *  Copyright (C) 2012 Michael D. Taht <dave.taht@bufferbloat.net>
 *  Copyright (C) 2012,2015 Eric Dumazet <edumazet@google.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 */

/* Controlling Queue Delay (CoDel) algorithm
 * =========================================
 * Source : Kathleen Nichols and Van Jacobson
 * http://queue.acm.org/detail.cfm?id=2209336
 *
 * Implemented on linux by Dave Taht and Eric Dumazet
 */

#include <stdint.h>
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(codel, LOG_LEVEL_INF);

#include <zephyr/kernel.h>
#include <zephyr/net/net_pkt.h>

#include "aqm.h"
#include "wifi.h"

static inline codel_time_t pkt_time(struct net_pkt *pkt);
static inline struct net_pkt *pkt_dequeue(struct codel_vars *vars, void *ctx, k_timeout_t timeout);

static void codel_params_init(struct codel_params *params)
{
	params->interval = MS2TIME(100);
	params->target = MS2TIME(5);
}

static void codel_vars_init(struct codel_vars *vars)
{
	memset(vars, 0, sizeof(*vars));
}

static void codel_stats_init(struct codel_stats *stats)
{
	stats->maxpacket = 0;
}

/*
 * http://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Iterative_methods_for_reciprocal_square_roots
 * new_invsqrt = (invsqrt / 2) * (3 - count * invsqrt^2)
 *
 * Here, invsqrt is a fixed point number (< 1.0), 32bit mantissa, aka Q0.32
 */
static void codel_Newton_step(struct codel_vars *vars)
{
	uint32_t invsqrt = ((uint32_t)vars->rec_inv_sqrt) << REC_INV_SQRT_SHIFT;
	uint32_t invsqrt2 = ((uint64_t)invsqrt * invsqrt) >> 32;
	uint64_t val = (3LL << 32) - ((uint64_t)vars->count * invsqrt2);

	val >>= 2; /* avoid overflow in following multiply */
	val = (val * invsqrt) >> (32 - 2 + 1);

	vars->rec_inv_sqrt = val >> REC_INV_SQRT_SHIFT;
}

/*
 * CoDel control_law is t + interval/sqrt(count)
 * We maintain in rec_inv_sqrt the reciprocal value of sqrt(count) to avoid
 * both sqrt() and divide operation.
 */
static codel_time_t codel_control_law(codel_time_t t,
				      codel_time_t interval,
				      uint32_t rec_inv_sqrt)
{
	return t + reciprocal_scale(interval, rec_inv_sqrt << REC_INV_SQRT_SHIFT);
}

static bool codel_should_drop(struct net_pkt *pkt, struct codel_vars *vars,
			      struct codel_params *params, struct codel_stats *stats,
			      uint32_t backlog, codel_time_t now)
{
	bool ok_to_drop;
	uint32_t pkt_len;

	if (!pkt) {
		vars->first_above_time = 0;
		return false;
	}

	pkt_len = net_pkt_get_len(pkt);
	vars->ldelay = now - pkt_time(pkt);

	if (unlikely(pkt_len > stats->maxpacket)) {
		stats->maxpacket = pkt_len;
	}

	if (codel_time_before(vars->ldelay, params->target) || backlog <= params->mtu) {
		/* went below - stay below for at least interval */
		vars->first_above_time = 0;
		return false;
	}
	ok_to_drop = false;
	if (vars->first_above_time == 0) {
		/* just went above from below. If we stay above
		 * for at least interval we'll say it's ok to drop
		 */
		vars->first_above_time = now + params->interval;
	} else if (codel_time_after(now, vars->first_above_time)) {
		ok_to_drop = true;
	}
	return ok_to_drop;
}

static struct net_pkt *codel_dequeue(void *ctx, uint32_t backlog, struct codel_params *params,
				     struct codel_vars *vars, struct codel_stats *stats)
{
	struct net_pkt *pkt = pkt_dequeue(vars, ctx, K_FOREVER);
	codel_time_t now;
	bool drop;

	if (!pkt) {
		vars->dropping = false;
		return pkt;
	}
	now = codel_get_time();
	drop = codel_should_drop(pkt, vars, params, stats, backlog, now);
	if (vars->dropping) {
		if (!drop) {
			/* sojourn time below target - leave dropping state */
			vars->dropping = false;
		} else if (codel_time_after_eq(now, vars->drop_next)) {
			/* It's time for the next drop. Drop the current
			 * packet and dequeue the next. The dequeue might
			 * take us out of dropping state.
			 * If not, schedule the next drop.
			 * A large backlog might result in drop rates so high
			 * that the next drop should happen now,
			 * hence the while loop.
			 */
			while (vars->dropping &&
			       codel_time_after_eq(now, vars->drop_next)) {
				vars->count++; /* dont care of possible wrap
						* since there is no more divide
						*/
				codel_Newton_step(vars);

				stats->drop_len += net_pkt_get_len(pkt);
				net_pkt_unref(pkt);
				stats->drop_count++;
				pkt = pkt_dequeue(vars, ctx, K_NO_WAIT);
				if (!codel_should_drop(pkt, vars, params, stats, backlog, now)) {
					/* leave dropping state */
					vars->dropping = false;
				} else {
					/* and schedule the next drop */
					vars->drop_next =
						codel_control_law(vars->drop_next, params->interval,
								  vars->rec_inv_sqrt);
				}
			}
		}
	} else if (drop) {
		uint32_t delta;

		stats->drop_len += net_pkt_get_len(pkt);
		net_pkt_unref(pkt);
		stats->drop_count++;

		pkt = pkt_dequeue(vars, ctx, K_NO_WAIT);
		drop = codel_should_drop(pkt, vars, params, stats, backlog, now);

		vars->dropping = true;
		/* if min went above target close to when we last went below it
		 * assume that the drop rate that controlled the queue on the
		 * last cycle is a good starting point to control it now.
		 */
		delta = vars->count - vars->lastcount;
		if (delta > 1 && codel_time_before(now - vars->drop_next, 16 * params->interval)) {
			vars->count = delta;
			/* we dont care if rec_inv_sqrt approximation
			 * is not very precise :
			 * Next Newton steps will correct it quadratically.
			 */
			codel_Newton_step(vars);
		} else {
			vars->count = 1;
			vars->rec_inv_sqrt = ~0U >> REC_INV_SQRT_SHIFT;
		}
		vars->lastcount = vars->count;
		vars->drop_next = codel_control_law(now, params->interval, vars->rec_inv_sqrt);
	}

	return pkt;
}



static atomic_t backlog;
static uint32_t max_backlog;
static struct codel_params params;
static struct codel_vars vars;
static struct codel_stats stats;

static inline codel_time_t pkt_time(struct net_pkt *pkt)
{
	return net_pkt_timestamp_ns(pkt) >> CODEL_SHIFT;
}

static inline struct net_pkt *pkt_dequeue(struct codel_vars *vars, void *ctx, k_timeout_t timeout)
{
	ARG_UNUSED(vars);
	struct k_fifo *fifo = ctx;
	struct net_pkt *pkt = k_fifo_get(fifo, timeout);
	if (pkt) {
		size_t len = net_pkt_get_len(pkt);
		size_t prev = atomic_sub(&backlog, len);
		if (prev < len) {
			LOG_ERR("backlog underflow");
			atomic_set(&backlog, 0);
		}
	}
	return pkt;
}

/* Called from net_tc_try_submit_to_tx_queue() at zephyr/subsys/net/ip/net_tc.c */
void aqm_backlog(size_t size)
{
	atomic_add(&backlog, size);
	size_t cur_backlog = atomic_get(&backlog);
	if (max_backlog < cur_backlog) {
		max_backlog = cur_backlog;
	}
}

void aqm_init(uint16_t mtu)
{
	codel_params_init(&params);
	params.target = MS2TIME(CONFIG_CODEL_TARGET_MS);
	params.interval = MS2TIME(CONFIG_CODEL_INTERVAL_MS);
	params.mtu = mtu;

	codel_vars_init(&vars);
	codel_stats_init(&stats);
}

void aqm_stats_print(void)
{
	printk("tx_q max backlog %u\n", max_backlog);
	printk("codel max_packet %u\n", stats.maxpacket);
	printk("codel drop count %u\n", stats.drop_count);
	printk("codel drop bytes %u\n", stats.drop_len);
}

void aqm_stats_get(struct aqm_stats *aqm_stats)
{
	aqm_stats->codel_stats = &stats;
	aqm_stats->backlog = atomic_get(&backlog);
}

/* Called from tc_tx_handler() at zephyr/subsys/net/ip/net_tc.c */
struct net_pkt *aqm_dequeue(struct k_fifo *fifo)
{
	return codel_dequeue(fifo, atomic_get(&backlog), &params, &vars, &stats);
}



static atomic_t sojourn_hist_sta[SOJOURN_HIST_SIZE];
static atomic_t sojourn_hist_sap[SOJOURN_HIST_SIZE];

static inline net_time_t sojourn_calc(struct net_pkt *pkt)
{
	net_time_t rx_timestamp = net_pkt_timestamp_ns(pkt);
	if (rx_timestamp > 0) {
		net_time_t tx_timestamp = get_time_ns();
		net_time_t sojourn_us = (tx_timestamp - rx_timestamp) / 1000;
		return sojourn_us;
	}
	return 0;
}

static inline void sojourn_hist_update(atomic_t *hist, net_time_t sojourn_us)
{
	size_t bin = MIN(LOG2CEIL(sojourn_us / 100), SOJOURN_HIST_SIZE - 1);
	atomic_val_t prev = atomic_inc(&hist[bin]);
	if (prev == UINT16_MAX) {
		atomic_set(&hist[bin], UINT16_MAX);
	}
}

atomic_t *sojourn_hist_get(struct net_if *iface)
{
	if (iface == wan_get_iface()) {
		return sojourn_hist_sta;
	} else if (iface == lan_get_iface()) {
		return sojourn_hist_sap;
	} else {
		return NULL;
	}
}

void sojourn_hist_reset(void)
{
	for (size_t i = 0; i < SOJOURN_HIST_SIZE; ++i) {
		atomic_set(&sojourn_hist_sta[i], 0);
		atomic_set(&sojourn_hist_sap[i], 0);
	}
}

/* Called from zephyr/drivers/wifi/esp32/src/esp_wifi_drv.c */
void esp_wifi_rx_cb(struct net_pkt *pkt)
{
	net_time_t rx_timestamp = get_time_ns();
	net_pkt_set_timestamp_ns(pkt, rx_timestamp);
}

/* Called from zephyr/drivers/wifi/esp32/src/esp_wifi_drv.c */
void esp_wifi_tx_cb(struct net_pkt *pkt)
{
	net_time_t sojourn_us = sojourn_calc(pkt);
	if (sojourn_us > 0) {
		atomic_t *hist = sojourn_hist_get(net_pkt_iface(pkt));
		if (hist) {
			sojourn_hist_update(hist, sojourn_us);
		}
	}
}

static void sojourn_hist_print(atomic_t *hist)
{
	printk("| millis |    count |\n");
	printk("+--------+----------+\n");
	for (size_t bin = 0; bin < SOJOURN_HIST_SIZE - 1; ++bin) {
		atomic_val_t count = atomic_get(&hist[bin]);
		size_t bound_10th_ms = 1U << bin;
		printk("| %4zu.%zu | %8ld |\n", bound_10th_ms / 10, bound_10th_ms % 10, count);
	}
	printk("|   tail | %8ld |\n", atomic_get(&hist[SOJOURN_HIST_SIZE - 1]));
	printk("+--------+----------+\n");
}

void sojourn_print(void)
{
	atomic_t *hist_wan = sojourn_hist_get(wan_get_iface());
	printk("+------ STA --------+\n");
	sojourn_hist_print(hist_wan);

#if defined(CONFIG_ESP32_WIFI_AP_STA_MODE)
	atomic_t *hist_lan = sojourn_hist_get(lan_get_iface());
	printk("+------ SAP --------+\n");
	sojourn_hist_print(hist_lan);
#endif
}
