/*****************************************************************************
 *
 * Copyright 2013 Chun Liu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ****************************************************************************/
#include <pthread.h>
#include "queue.h"
#include "mbox.h"
#include "util.h"

#define MAX_MSGS 32

#ifdef LOCK_FREE_MBOX

struct mailbox {
	volatile void *msg;
} __attribute__ ((aligned CACHELINESZ));

struct mailbox inbox[MAX_CORES];

void
mboxinit(int c)
{
	inbox[c].msg = NULL;
}

int
mboxenq(int c, void *payload)
{
	volatile void *oldvalue = inbox[c].msg;
	/* __sync_bool_compare_and_swap(&inbox[c].msg, oldvalue, payload); */
	inbox[c].msg = payload;

	return (oldvalue == NULL);
}

void *
mboxdeq(int c)
{
	volatile void *oldvalue = inbox[c].msg;
#if 0
	int match;
	match = __sync_bool_compare_and_swap(&inbox[c].msg, oldvalue, 0);
#endif
	inbox[c].msg = 0;

	return (void*)oldvalue;
}

#else

struct msg {
	void *payload;
	TAILQ_ENTRY(msg) next;
};

/*
 * separate this from tasklist, this will be r/w by all pthreads,
 * lock required before any access
 */
struct mailbox {
	TAILQ_HEAD(msgq, msg) msgs;
	struct msgq freq;
	pthread_mutex_t lock;
} __attribute__ ((aligned CACHELINESZ));

struct mailbox inbox[MAX_CORES];
struct msg message[MAX_CORES * MAX_MSGS];

/* mbox functions can be called by any pthread */
void mboxinit(int c)
{
	int i;

	pthread_mutex_init(&inbox[c].lock, NULL);
	TAILQ_INIT(&inbox[c].freq);
	TAILQ_INIT(&inbox[c].msgs);
	for (i = 0; i < MAX_MSGS; i ++)
		TAILQ_INSERT_HEAD(&inbox[c].freq,
		    &message[c * MAX_MSGS + i], next);
}

int
mboxenq(int c, void *payload)
{
	struct msg *n;

	pthread_mutex_lock(&inbox[c].lock);

	n = TAILQ_FIRST(&inbox[c].freq);
	if (n != NULL) {
		TAILQ_REMOVE(&inbox[c].freq, n, next);
		n->payload = payload;
		TAILQ_INSERT_TAIL(&inbox[c].msgs, n, next);
	}

	pthread_mutex_unlock(&inbox[c].lock);

	return (n == NULL);
}

void *
mboxdeq(int c)
{
	struct msg *n;
	void *payload;

	if (TAILQ_EMPTY(&inbox[c].msgs))
		return NULL;

	pthread_mutex_lock(&inbox[c].lock);

	n = TAILQ_FIRST(&inbox[c].msgs);
	TAILQ_REMOVE(&inbox[c].msgs, n, next);
	payload = n->payload;
	TAILQ_INSERT_TAIL(&inbox[c].msgs, n, next);

	pthread_mutex_unlock(&inbox[c].lock);

	return payload;
}

#endif /* LOCK_FREE_MBOX */

struct pipebox {
	volatile unsigned int head;
	void *fifo[MAX_MSGS];
	volatile unsigned int tail;
} __attribute__ ((aligned CACHELINESZ));

struct pipebox pipes[MAX_CORES];

void
pboxinit(int c)
{
	pipes[c].head = pipes[c].tail = 0;
}

#define NEXT(x, m) (((x) + 1) & ((m) - 1))
int
pboxenq(int c, void *payload)
{
	unsigned int curr_head, curr_tail, next_tail;

	curr_head = (unsigned int)pipes[c].head;
	curr_tail = (unsigned int)pipes[c].tail;
	next_tail = NEXT(curr_tail, MAX_MSGS);

	if (next_tail != curr_head) {
		pipes[c].fifo[curr_tail] = payload;
		pipes[c].tail = next_tail;
		return 0;
	}

	return 1;
}

void *
pboxdeq(int c)
{
	unsigned int curr_head, next_head, curr_tail;
	void *payload;

	curr_head = (unsigned int)pipes[c].head;
	curr_tail = (unsigned int)pipes[c].tail;
	next_head = NEXT(curr_head, MAX_MSGS);

	if (curr_head == curr_tail) {
		return NULL;
	}

	payload = pipes[c].fifo[curr_head];
	pipes[c].head = next_head;

	return payload;
}

