#ifndef _UTIL_H_
#define _UTIL_H_

#include "stdint.h"

#define NUMBER_OF_FLOWS (256)
#define IO_QUEUE_DEPTH  (32)

#define CMD_TASKS (NUMBER_OF_FLOWS)

#define MAX_TASKS (CMD_TASKS + 32)

#define NR_PCBS   (NUMBER_OF_FLOWS)

/* Multi core */
#define MAX_CORES (1)
#define CACHELINESZ (64)

extern uint64_t ticks_us;
void sysinit(void);
#define usafter(us) ((uint64_t)(us) * ticks_us)
static __inline__ uint64_t rdtsc(void)
{
	unsigned hi, lo;
	__asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
	return ( (uint64_t)lo)|( ((uint64_t)hi)<<32 );
}

int LOG(char *, ...);
#define CONSOLE_OUTPUT (0)
#define LOGBUF_OUTPUT  (1)
void setoutput(int);
char *getlogbuf(size_t *);

#endif /* _UTIL_H_ */
