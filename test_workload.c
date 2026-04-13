/*
 * test_workload.c - test program with both CPU work and blocking
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

/* Do some CPU work */
static volatile double sink;

static void cpu_work(int iterations)
{
	double x = 1.0;
	for (int i = 0; i < iterations; i++) {
		x = sin(x) + cos(x * 0.5);
		sink = x;
	}
}

/* Do blocking I/O */
static void do_sleep(int ms)
{
	struct timespec ts = {
		.tv_sec = ms / 1000,
		.tv_nsec = (ms % 1000) * 1000000L,
	};
	nanosleep(&ts, NULL);
}

int main(int argc, char **argv)
{
	int rounds = 10;
	if (argc > 1)
		rounds = atoi(argv[1]);

	printf("test_workload: %d rounds of CPU work + sleep\n", rounds);

	for (int i = 0; i < rounds; i++) {
		/* ~50ms of CPU work */
		cpu_work(2000000);
		/* ~50ms of sleep */
		do_sleep(50);
	}

	printf("test_workload: done\n");
	return 0;
}
