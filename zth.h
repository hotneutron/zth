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
#ifndef _ZTH_H_
#define _ZTH_H_

#include <stdint.h>
#include "queue.h"
#include "util.h"

/* An ultra-light-weight, non-preemtive thread library */

struct task {
	uint64_t wkup_time;
	TAILQ_ENTRY(task) next;
	TAILQ_ENTRY(task) next_tmo;
	/* bottom stack */
	intptr_t *stack;
	/* top stack */
	intptr_t *sp;
	void (*ent)(void);
	size_t stksize;
	int *slpaddr;
	/* used when sleeper times out */
	void*sleep_queue;
	int slptmo;
	int core;
#define SLPTMO_TMO     (-1)
#define SLPTMO_WKUP    (0)
#define SLPTMO_PENDING (1)
#define SLPTMO_NONE    (2)
	int status;
	void *arg;
#define TASK_NONE    0
#define TASK_START   1
#define TASK_RUNNING 2
#define TASK_READY   3
#define TASK_SLEEP   4
#define TASK_STOP    5
#define TASK_SUSPEND 6
} __attribute__ ((aligned CACHELINESZ));

void zthinit(void);
void zthyield(void);
void zthstart(void);
int  zthsleep(void *, uint64_t);
void zthwakeup(void *);
void zthwakeup_highprio(void *);
void zthwkafter(uint64_t);
void *ztharg(void);
struct task *zthcreate(void *, uint32_t, int, void (*)(void), void *);
void task_stack(int);
void *zthgettask(void);
void zthswitch(void *);
void zthsuspend(void);
int zthcid(void);

/* reserve 9 qwords */
#define STACK_RESERVE (9)

#endif /* ZTH_H_ */
