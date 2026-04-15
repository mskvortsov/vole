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

#ifndef _AQM_H_
#define _AQM_H_

#include <stdint.h>
#include <zephyr/kernel.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_time.h>

static inline uint32_t reciprocal_scale(uint32_t val, uint32_t ep_ro)
{
	return ((uint64_t)val * ep_ro) >> 32;
}

/* CoDel uses a 1024 nsec clock, encoded in u32
 * This gives a range of 2199 seconds, because of signed compares
 */
typedef uint32_t codel_time_t;
typedef int32_t codel_tdiff_t;
#define CODEL_SHIFT 10
#define MS2TIME(a) ((a * NSEC_PER_MSEC) >> CODEL_SHIFT)

static inline net_time_t get_time_ns(void)
{
#if defined(CONFIG_TIMER_HAS_64BIT_CYCLE_COUNTER)
	return k_cyc_to_ns_floor64(k_cycle_get_64());
#else
	return k_cyc_to_ns_floor64(k_cycle_get_32());
#endif
}

static inline codel_time_t codel_get_time(void)
{
	return get_time_ns() >> CODEL_SHIFT;
}

/* Dealing with timer wrapping, according to RFC 1982, as desc in wikipedia:
 *  https://en.wikipedia.org/wiki/Serial_number_arithmetic#General_Solution
 * codel_time_after(a,b) returns true if the time a is after time b.
 */
#define codel_time_after(a, b)  ((int32_t)((a) - (b)) > 0)
#define codel_time_before(a, b) codel_time_after(b, a)

#define codel_time_after_eq(a, b)  ((int32_t)((a) - (b)) >= 0)
#define codel_time_before_eq(a, b) codel_time_after_eq(b, a)

/**
 * struct codel_params - contains codel parameters
 * @target:	target queue size (in time units)
 * @ce_threshold:  threshold for marking packets with ECN CE
 * @interval:	width of moving time window
 * @mtu:	device mtu, or minimal queue backlog in bytes.
 * @ecn:	is Explicit Congestion Notification enabled
 * @ce_threshold_selector: apply ce_threshold to packets matching this value
 *                         in the diffserv/ECN byte of the IP header
 * @ce_threshold_mask: mask to apply to ce_threshold_selector comparison
 */
struct codel_params {
	codel_time_t target;
	codel_time_t interval;
	uint32_t mtu;
};

/**
 * struct codel_vars - contains codel variables
 * @count:		how many drops we've done since the last time we
 *			entered dropping state
 * @lastcount:		count at entry to dropping state
 * @dropping:		set to true if in dropping state
 * @rec_inv_sqrt:	reciprocal value of sqrt(count) >> 1
 * @first_above_time:	when we went (or will go) continuously above target
 *			for interval
 * @drop_next:		time to drop next packet, or when we dropped last
 * @ldelay:		sojourn time of last dequeued packet
 */
struct codel_vars {
	uint32_t count;
	uint32_t lastcount;
	bool dropping;
	uint16_t rec_inv_sqrt;
	codel_time_t first_above_time;
	codel_time_t drop_next;
	codel_time_t ldelay;
};

#define REC_INV_SQRT_BITS (8 * sizeof(uint16_t)) /* or sizeof_in_bits(rec_inv_sqrt) */
/* needed shift to get a Q0.32 number from rec_inv_sqrt */
#define REC_INV_SQRT_SHIFT (32 - REC_INV_SQRT_BITS)

/**
 * struct codel_stats - contains codel shared variables and stats
 * @maxpacket:	largest packet we've seen so far
 * @drop_count:	temp count of dropped packets in dequeue()
 * @drop_len:	bytes of dropped packets in dequeue()
 */
struct codel_stats {
	uint32_t maxpacket;
	uint32_t drop_count;
	uint32_t drop_len;
};

struct aqm_stats {
	struct codel_stats *codel_stats;
	size_t backlog;
};

void aqm_stats_get(struct aqm_stats *aqm_stats);

#define SOJOURN_HIST_SIZE 13

atomic_t *sojourn_hist_get(struct net_if *iface);
void sojourn_print(void);
void sojourn_hist_reset(void);

#endif
