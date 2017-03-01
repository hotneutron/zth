/*****************************************************************************
 * utils, supporting functions.
 ****************************************************************************/
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <cpuid.h>
#include <assert.h>
#include "util.h"

uint64_t ticks_us;
uint32_t cpuid_feature_ecx, cpuid_feature_edx;

/*
 * depends on tsc clock being constant.
 * See http://en.wikipedia.org/wiki/Time_Stamp_Counter
 * check constant_tsc flag in /proc/cpuinfo
 */
void
sysinit(void)
{
	struct timespec tp;
	uint64_t t;
	uint32_t eax, ebx;
	int r;

	assert(__get_cpuid(1, &eax, &ebx, &cpuid_feature_ecx,
	    &cpuid_feature_edx) != 0);

	while (1) {
		tp.tv_sec  = 1;
		tp.tv_nsec = 0;
		t = rdtsc();
		r = nanosleep(&tp, NULL);
		t = rdtsc() - t;
		if (r == 0)
			break;
	}
	/* to us accuracy */
	ticks_us = t / 10000000 * 10;
}

int output_destination;
char log_buf[1024 * 1024];
int plog_buf;

void
setoutput(int out)
{
	output_destination = out;
	plog_buf = 0;
}

int
LOG(char *fmt, ...)
{
	int result = 0;

	va_list args;
	va_start(args, fmt);
	switch (output_destination) {
	case CONSOLE_OUTPUT:
		result = vfprintf(stdout, fmt, args);
		break;
	case LOGBUF_OUTPUT:
		result = vsnprintf(log_buf + plog_buf, sizeof(log_buf) -
		    plog_buf, fmt, args);
		plog_buf += strlen(log_buf + plog_buf);
		break;
	}
	va_end(args);
	return (result);
}

char *
getlogbuf(size_t *size)
{
	*size = plog_buf;
	return (log_buf);
}
