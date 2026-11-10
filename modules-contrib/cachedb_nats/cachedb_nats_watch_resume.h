/*
 * Copyright (C) 2025 OpenSIPS Solutions
 * Copyright (C) 2025 Norm Brandinger <n.brandinger@gmail.com>
 *
 * This file is part of opensips, a free SIP server.
 *
 * opensips is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * opensips is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * Where a (re)built KV watcher starts reading the bucket stream.
 *
 * A watcher created with UpdatesOnly only sees changes made after it
 * subscribed, so everything written while the connection was down -- and
 * during the second or so the watcher takes to notice the reconnect --
 * never reached E_NATS_KV_CHANGE.  The watcher instead keeps the next
 * revision it has not seen and resumes from it (ResumeFromRevision).
 */

#ifndef CACHEDB_NATS_WATCH_RESUME_H
#define CACHEDB_NATS_WATCH_RESUME_H

#include <stdint.h>

struct watch_resume {
	uint64_t next;	/* first revision not seen yet; 0 = no anchor yet */
};

/* the revision after @rev, saturating instead of wrapping to 0 */
static inline uint64_t watch_resume_next(uint64_t rev)
{
	return rev == UINT64_MAX ? UINT64_MAX : rev + 1;
}

/* Revision to start the watcher from: >= 1, or 0 for "updates only".
 * @have_last is 0 when the stream's last sequence could not be read;
 * @reset is set to 1 when the stream went backwards (bucket recreated). */
static inline uint64_t watch_resume_start(struct watch_resume *wr,
		int have_last, uint64_t stream_last, int *reset)
{
	uint64_t end = watch_resume_next(stream_last);

	*reset = 0;
	if (!have_last)
		return wr->next;	/* 0 before the first anchor: updates only */
	if (wr->next == 0)
		wr->next = end;		/* first build: new changes only */
	else if (wr->next > end) {
		*reset = 1;		/* the revisions we expect no longer exist */
		wr->next = end;
	}
	return wr->next;
}

/* Record that the entry with revision @rev was delivered. */
static inline void watch_resume_seen(struct watch_resume *wr, uint64_t rev)
{
	if (rev && watch_resume_next(rev) > wr->next)
		wr->next = watch_resume_next(rev);
}

#endif
