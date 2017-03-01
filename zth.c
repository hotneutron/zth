/*****************************************************************************
 *
 * Copyright 2013 Silei Zhang
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

/* Add pthread support Chun Liu */

#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#define __USE_GNU
#include <dlfcn.h>
#include <assert.h>
#include <stdlib.h>
#include <execinfo.h>
#include "queue.h"
#include "zth.h"
#include "mbox.h"
#include "util.h"
#include "cmd.h"

struct task task_store[MAX_TASKS];
#define SLP_BIN (256)
#define _K(k) (1024UL * (k))

/* each pthread maintains its own tasklist, no locks required */
struct tasklist {
	TAILQ_HEAD(taskq, task) runq, tmrq, slpq[SLP_BIN];
	pthread_t zthread;
	struct taskq freq;
	struct task* running;
	intptr_t return_address;
}  __attribute__ ((aligned CACHELINESZ));

struct tasklist ct[MAX_CORES];

pthread_key_t zcore;
pthread_once_t zonce = PTHREAD_ONCE_INIT;

void _zthwakeup(void *addr, int c);

static inline uint8_t
hash(uint32_t addr)
{
	int i;
	uint8_t hash = 0;

	for (i = 0; i < 4; i ++, addr >>= 8)
		hash ^= addr & 0xff;
	return (hash);
}

void *
ztharg(void)
{
	int c;
	c = (intptr_t) pthread_getspecific(zcore);
	return (ct[c].running->arg);
}

void
_zthinit(void)
{
	int i, c;

	for (c = 0; c < MAX_CORES; c ++) {
		TAILQ_INIT(&ct[c].runq);
		TAILQ_INIT(&ct[c].freq);
		for (i = 0; i < SLP_BIN; i ++)
			TAILQ_INIT(&ct[c].slpq[i]);
		pboxinit(c);
	}
	for (i = 0; i < MAX_TASKS; i ++) {
		c = i / (MAX_TASKS/MAX_CORES);
		TAILQ_INSERT_HEAD(&ct[c].freq, &task_store[i], next);
		task_store[i].core = c;
	}

	pthread_key_create(&zcore, NULL);
}

void
zthinit(void)
{
	pthread_once(&zonce, _zthinit);
}

void _t_exit(intptr_t);
void _t_start(void (*)(void), void *, struct task *);
void _t_swtch(intptr_t **, intptr_t **, int);
void _t_stopped(struct task *);
void _sched_start(intptr_t *);

#define NEXT(x, c) do {                       \
	x = TAILQ_NEXT(x, next);              \
	if (!x)                               \
		x = TAILQ_FIRST(&ct[c].runq); \
} while (0)

void
dump_memory(void *mem, size_t size)
{
	int i;
	uint32_t *pmem = (uint32_t *)mem;

	for (i = 0; i < size / sizeof(uint32_t); i ++) {
		if (i % 8 == 0) {
			LOG("\n");
			LOG("%08lx: ", i * sizeof(uint32_t));
		}
		LOG("%08x ", pmem[i]);
	}
	LOG("\n");
}

void
task_stack(int taskid)
{
	int *s, *e;
	struct task *t;

	if (taskid >= MAX_TASKS)
		return;
	t = &task_store[taskid];
	s = (int *)t->sp;
	e = (int *)((intptr_t)(t->stack) + t->stksize);
	dump_memory(s, (e - s) * sizeof(int));
}

#define STACK_MARK (0x5A)

void
task_info_one(struct task *t, uint64_t wkup, void *handle)
{
	Dl_info info;
	uint64_t i;
	char *p;

	if (dladdr((void *)(t->ent), &info) != 0)
		p = (char *)info.dli_sname;
	else
		p = NULL;
	LOG("TASK[%lu] %8p (%s) ", t - task_store, t, p ? p : "");
	LOG("STACK %p-%p ", t->stack, (int *)((intptr_t)(t->stack) + t->stksize));
	LOG("SP %p ", t->sp);
	for (p = (char *)t->stack, i = 0; i < t->stksize; i ++, p ++)
		if (*p != STACK_MARK)
			break;
	LOG("STACK HWM %8lu ", i);
	switch (t->status) {
	case TASK_READY:
	case TASK_START:
		LOG("R");
                break;
	case TASK_RUNNING:
		LOG("*");
                break;
	case TASK_SLEEP:
		if (wkup != ~0UL)
			LOG("T@%lu", wkup);
		else
			LOG("S@%p", t->slpaddr);
		break;
	default:
		LOG("?");
                break;
	}
	LOG("\n");
}

void
task_info(void)
{
	int i, c;
	struct task *t;
	uint64_t now;
	void *handle;

	handle = dlopen(NULL, RTLD_LAZY);
	if (handle == NULL)
		return;
	for (i = 0; i < MAX_TASKS; i ++)
		if (task_store[i].status == TASK_SUSPEND)
				task_info_one(&task_store[i], ~0UL, handle);
	for (c = 0; c < MAX_CORES; c ++) {
		for (i = 0; i < SLP_BIN; i ++)
			TAILQ_FOREACH(t, &ct[c].slpq[i], next)
				task_info_one(t, ~0UL, handle);
		TAILQ_FOREACH(t, &ct[c].runq, next)
			task_info_one(t, ~0UL, handle);
		t = TAILQ_FIRST(&ct[c].tmrq);
		if (!t)
			goto exit;
		now = rdtsc();
		if (now > t->wkup_time)
			now = 0;
		else
			now = t->wkup_time - now;
		task_info_one(t, now, handle);
		t = TAILQ_NEXT(t, next_tmo);
		while (t) {
			now += t->wkup_time;
			task_info_one(t, now, handle);
			t = TAILQ_NEXT(t, next_tmo);
		}
	}
exit:
	dlclose(handle);
}

void
check_timer(int c)
{
	uint64_t tm, tm1;
	struct task *elm;
	void *msg;

	if ((msg = pboxdeq(c)) != NULL) {
		_zthwakeup(msg, c);
	}

	if (!TAILQ_EMPTY(&ct[c].tmrq)) {
		tm = rdtsc();
		while (!TAILQ_EMPTY(&ct[c].tmrq)) {
			elm = TAILQ_FIRST(&ct[c].tmrq);
			tm1 = elm->wkup_time;
			if (tm1 > tm)
				break;
			TAILQ_REMOVE(&ct[c].tmrq, elm, next_tmo);
			if (elm->slptmo == SLPTMO_PENDING) {
				TAILQ_REMOVE((struct taskq *)(elm->sleep_queue),
				    elm, next);
				elm->slptmo = SLPTMO_TMO;
			}
			elm->status = TASK_READY;
			TAILQ_INSERT_TAIL(&ct[c].runq, elm, next);
			if (!TAILQ_EMPTY(&ct[c].tmrq)) {
				elm = TAILQ_FIRST(&ct[c].tmrq);
				elm->wkup_time += tm1;
			}
		}
	}
}

void
sched_next(intptr_t **last, int c)
{
	int firsttime;
	int me = (intptr_t) pthread_getspecific(zcore);
	assert(me == c);

	while (TAILQ_EMPTY(&ct[c].runq)) {
		check_timer(c);
		ct[c].running = TAILQ_FIRST(&ct[c].runq);
	}
	assert(ct[c].running->status == TASK_READY ||
	       ct[c].running->status == TASK_START ||
	       ct[c].running->status == TASK_STOP);
	firsttime = ct[c].running->status == TASK_START;
	ct[c].running->status = TASK_RUNNING;
	_t_swtch(last, &ct[c].running->sp, firsttime);
}

void
add_tmrq(struct task *task, uint64_t us)
{
	uint64_t tm;
	struct task *elm;
	int c = task->core;

	tm = rdtsc() + usafter(us);

	if (TAILQ_EMPTY(&ct[c].tmrq))
		TAILQ_INSERT_HEAD(&(ct[c].tmrq), task, next_tmo);
	else {
		TAILQ_FOREACH(elm, &(ct[c].tmrq), next_tmo) {
			if (elm->wkup_time > tm) {
				elm->wkup_time -= tm;
				TAILQ_INSERT_BEFORE(elm, task, next_tmo);
				break;
			}
			tm -= elm->wkup_time;
		}
		if (!elm)
			TAILQ_INSERT_TAIL(&(ct[c].tmrq), task, next_tmo);
	}
	task->wkup_time = tm;
}

void
remove_tmrq(struct task *task)
{
	struct task *elm = TAILQ_NEXT(task, next_tmo);

	if (elm != NULL)
		elm->wkup_time += task->wkup_time;
	TAILQ_REMOVE(&(ct[elm->core].tmrq), task, next_tmo);
}

void
zthwkafter(uint64_t us)
{
	intptr_t **last;
	int c;

	c = (intptr_t) pthread_getspecific(zcore);
	assert(ct[c].running != NULL);
	assert(ct[c].running->status == TASK_RUNNING);

	last = (intptr_t **)&(ct[c].running->sp);

	TAILQ_REMOVE(&ct[c].runq, ct[c].running, next);
	ct[c].running->status = TASK_SLEEP;

	add_tmrq(ct[c].running, us);

	while (TAILQ_EMPTY(&ct[c].runq))
		check_timer(c);
	ct[c].running = TAILQ_FIRST(&ct[c].runq);

	sched_next(last, c);
}

void
_zthwakeup(void *addr, int c)
{
	uint32_t value = (uint32_t)(intptr_t)addr;
	struct task *slptsk, *n;
	uint8_t q;

	q = hash(value);
	slptsk = TAILQ_FIRST(&ct[c].slpq[q]);
	while (slptsk) {
		n = TAILQ_NEXT(slptsk, next);
		if (slptsk->slpaddr == (int *)addr) {
			slptsk->status = TASK_READY;
			if (slptsk->slptmo == SLPTMO_PENDING) {
				remove_tmrq(slptsk);
				slptsk->slptmo = SLPTMO_WKUP;
			}
			TAILQ_REMOVE(&ct[c].slpq[q], slptsk, next);
			TAILQ_INSERT_TAIL(&ct[c].runq, slptsk, next);
		}
		slptsk = n;
	}
}

void
zthwakeup(void *addr)
{
	int i, c;

	c = (intptr_t) pthread_getspecific(zcore);
	_zthwakeup(addr, c);
	for (i = 0; i < MAX_CORES; i ++)
		if (i != c) pboxenq(i, addr);
}

void
zthswitch(void *t)
{
	struct task *task = (struct task *)t, *old;
	intptr_t **last;
	int c;

	c = (intptr_t) pthread_getspecific(zcore);
	old = ct[c].running;

	if (task->status != TASK_SUSPEND)
		return;
	assert(task->status == TASK_SUSPEND);
	assert(task->core == c);
	task->status = TASK_READY;

	if (ct[c].running)
		ct[c].running->status = TASK_READY;

	TAILQ_INSERT_HEAD(&ct[c].runq, task, next);
	ct[c].running = task;

	if (old)
		last = (intptr_t **)&old->sp;
	else
		last = NULL;

	sched_next(last, c);
}

int
zthsleep(void *addr, uint64_t tmo)
{
	intptr_t **last;
	struct task *old;
	uint32_t value = (uint32_t)(intptr_t)addr;
	int      return_value;
	uint8_t  q = hash(value);
	int c;

	c = (intptr_t) pthread_getspecific(zcore);

	assert(ct[c].running != NULL);
	assert(ct[c].running->status == TASK_RUNNING);

	last = (intptr_t **)&(ct[c].running->sp);

	ct[c].running->status = TASK_SLEEP;
	ct[c].running->slpaddr = (int *)addr;
	old = ct[c].running;
	TAILQ_REMOVE(&ct[c].runq, ct[c].running, next);
	assert(!(TAILQ_EMPTY(&ct[c].runq) && TAILQ_EMPTY(&ct[c].tmrq)));
	check_timer(c);
	ct[c].running = TAILQ_FIRST(&ct[c].runq);

	TAILQ_INSERT_HEAD(&ct[c].slpq[q], old, next);

	if (tmo > 0UL) {
		add_tmrq(old, tmo);
		old->slptmo = SLPTMO_PENDING;
		old->sleep_queue = &ct[c].slpq[q];
	} else
		old->slptmo = SLPTMO_NONE;

	sched_next(last, c);
	return_value = old->slptmo;
	old->slptmo  = SLPTMO_NONE;
	old->sleep_queue = NULL;
	return (return_value);
}

void
zthsuspend(void)
{
	intptr_t **last;
	int c;

	c = (intptr_t) pthread_getspecific(zcore);

	assert(ct[c].running != NULL);
	assert(ct[c].running->status == TASK_RUNNING);

	last = (intptr_t **)&(ct[c].running->sp);

	ct[c].running->status = TASK_SUSPEND;
	TAILQ_REMOVE(&ct[c].runq, ct[c].running, next);
	assert(!(TAILQ_EMPTY(&ct[c].runq) && TAILQ_EMPTY(&ct[c].tmrq)));
	check_timer(c);
	ct[c].running = TAILQ_FIRST(&ct[c].runq);

	sched_next(last, c);
	return;
}

void *
zthgettask(void)
{
	int c;
	c = (intptr_t) pthread_getspecific(zcore);
	return ((void *)ct[c].running);
}

void
zthyield(void)
{
	struct task *old, *tmp;
	intptr_t **last;
	int c;

	c = (intptr_t) pthread_getspecific(zcore);
	old = ct[c].running;

	check_timer(c);

	if (!ct[c].running) {
		if (TAILQ_EMPTY(&ct[c].runq))
			return;
	} else if (ct[c].running->status == TASK_RUNNING) {
		tmp = ct[c].running;
		NEXT(tmp, c);
		if (tmp == ct[c].running)
			return;
		ct[c].running->status = TASK_READY;

		TAILQ_REMOVE(&ct[c].runq, ct[c].running, next);
		TAILQ_INSERT_TAIL(&ct[c].runq, ct[c].running, next);
	}

	ct[c].running = TAILQ_FIRST(&ct[c].runq);

	if (old)
		last = (intptr_t **)&old->sp;
	else
		last = NULL;

	sched_next(last, c);
}

int
zthcid(void)
{
	int c;
	c = (intptr_t) pthread_getspecific(zcore);
	return c;
}

struct task *
zthcreate(void *stack, uint32_t size, int c, void (*entry)(void), void *arg)
{
	uint32_t size_qw = size / sizeof(intptr_t);
	struct task *tsk;

	if (TAILQ_EMPTY(&ct[c].freq))
		return (NULL);
	memset(stack, STACK_MARK, size);

	tsk = TAILQ_FIRST(&ct[c].freq);
	TAILQ_REMOVE(&ct[c].freq, tsk, next);
	tsk->stack   = (intptr_t *)stack;
	tsk->sp      = tsk->stack + size_qw;
	tsk->sp     -= STACK_RESERVE;
	tsk->status  = TASK_START;
	tsk->ent     = entry;
	tsk->stksize = size;
	tsk->arg     = arg;
	assert(tsk->core == c);
	TAILQ_INSERT_TAIL(&ct[c].runq, tsk, next);
	_t_start(entry, &tsk->stack[size_qw], tsk);
	return (tsk);
}

void
_t_stopped(struct task *tsk)
{
	int q, c;
	tsk->status = TASK_STOP;
	c = tsk->core;
	TAILQ_REMOVE(&ct[c].runq, tsk, next);
	TAILQ_INSERT_HEAD(&ct[c].freq, tsk, next);
	if (TAILQ_EMPTY(&ct[c].runq) && !TAILQ_EMPTY(&ct[c].tmrq))
		while (TAILQ_EMPTY(&ct[c].runq))
			check_timer(c);
	if (TAILQ_EMPTY(&ct[c].runq)) {
		/* taskss in sleep queue are stuck! */
		for (q = 0; q < SLP_BIN; q ++)
			assert(TAILQ_EMPTY(&ct[c].slpq[q]));
		ct[c].running = NULL;
		_t_exit(ct[c].return_address);
	} else
		zthyield();
}

void *
_zthstart(void *arg)
{
	long int c = ((intptr_t)arg);
	assert(pthread_setspecific(zcore, (void*)c) == 0);
	ct[c].running = NULL;
	_sched_start(&ct[c].return_address);
	return NULL;
}

void
zthstart()
{
	long int c = 0;

#if MAX_CORES==1
	_zthstart((void*)c);
#else
	void *res;
	pthread_attr_t attr;

	assert(pthread_attr_init(&attr) == 0);

	for (c = 0; c < MAX_CORES; c ++) {
		pthread_create(&ct[c].zthread, &attr, &_zthstart, (void*)c);
	}
	for (c = 0; c < MAX_CORES; c ++) {
		pthread_join(ct[c].zthread, &res);
	}
#endif
}


void
stack_backtrace(int taskid)
{
	extern int get_task_trace(void **, int, void *);
	uint64_t context[6];
	int nptrs, j;
#define SIZE 100
	void *buffer[100];
	char **strings;
	int  *s;
	struct task *t;

	if (taskid >= MAX_TASKS)
		return;
	t = &task_store[taskid];
	if (t->status == TASK_NONE)
		return;
	if (t->status == TASK_RUNNING) {
		nptrs = backtrace(buffer, SIZE);
		if (nptrs < 0)
			return;
		strings = backtrace_symbols(buffer, nptrs);
		if (strings == NULL)
			return;
		for (j = 0; j < nptrs; j ++)
			LOG("%s\n", strings[j]);
		free(strings);
	}
	s = (int *)t->sp;
	memcpy(context, s, sizeof(context));
	nptrs = get_task_trace(buffer, SIZE, s + 12);
	if (nptrs < 0)
		return;

	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL)
		return;
	for (j = 0; j < nptrs; j ++)
		LOG("%s\n", strings[j]);
	free(strings);
	memcpy(s, context, sizeof(context));
	return;
}

COMMAND(task)
{
	task_info();
	return (0);
}

COMMAND(stack)
{
	int taskid = (int)strtoul(argv[1], NULL, 10);
	task_stack(taskid);

	return (0);
}

COMMAND(backtrace)
{
	int taskid = (int)strtoul(argv[1], NULL, 10);
	stack_backtrace(taskid);
	return (0);
}

#ifdef ZTH_TEST

#include <time.h>
#include <stdlib.h>
uint8_t stack[_K(4) * 33];
int wkup_address[MAX_CORES], done[MAX_CORES];

void
test_task(void)
{
	int id = (int)(intptr_t)ztharg();
	int i, c = zthcid();
	for (i = 0; i < 4; i ++) {
		LOG("ID <%d> %d\n", id, i);
		zthwkafter(random() % 1000000);
	}
	done[c] ++;
	zthwakeup(&done[c]);
	zthsleep(&wkup_address[c], 0);
}

void
wkup_task(void)
{
	int c = zthcid();
	while (done[c] < (32/MAX_CORES))
		zthsleep(&done[c], 0);
	zthwakeup(&wkup_address[c]);
}

void
test2(void)
{
	int id = (int)(intptr_t)ztharg();
	LOG("id = %d return = %d\n", id,
	    zthsleep((void *)(intptr_t)(id + 1), 100000UL * 16));
}

void
testmon2(void)
{
	int i, id = (int)(intptr_t)ztharg();
	for (i = id; i < 16; i += 2 ) {
		zthwkafter(100000);
		zthwakeup((void *)(intptr_t)(i + 1));
	}
}

int
main(void)
{
	long int i;

	srandom(time(NULL));
	sysinit();
	zthinit();

	for (i = 0; i < 32; i ++)
		zthcreate(&stack[i * _K(4)], _K(4), i%MAX_CORES, test_task,
		    (void *)i);
	for (i = 0; i < MAX_CORES; i ++)
		zthcreate(&stack[(32 + i) * _K(4)], _K(4), i, wkup_task, NULL);
	zthstart();

	for (i = 0; i < 32; i ++)
		zthcreate(&stack[i * _K(4)], _K(4), i%MAX_CORES, test2,
		    (void *)i);
	for (i = 0; i < MAX_CORES; i ++)
		zthcreate(&stack[(32 + i) * _K(4)], _K(4), i, testmon2,
		    (void *)(MAX_CORES-1-i));

	zthstart();

	return (0);
}

#endif /* ZTH_TEST */
