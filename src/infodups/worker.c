/*
 * worker.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "worker.h"
#include "dups.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <limits.h>

/**
 * Job struct
 */
typedef struct {
	unsigned int 		id;								/**< thread identifier */
	workerPool_t 		*pool;							/**< pointer to the pool */

	buffer_t 			*buffer;						/**< list of tasks */
	node_t 				*cur;							/**< current task */

	int 				tube[2];						/**< pipe */

	pthread_mutex_t 	kill_mutex;						/**< kill mutex */
} job_t;

/**
 * Pool of workers
 */
struct workerPool {
	pthread_t 			threads	[BUFFER_MAX_WORKERS];	/**< array of threads */
	job_t 				jobs	[BUFFER_MAX_WORKERS];	/**< array of jobs */
	struct pollfd 		pollin	[BUFFER_MAX_WORKERS];	/**< array of poll structs for POLLIN event (ready to read) */
	struct pollfd 		pollhup	[BUFFER_MAX_WORKERS];	/**< array of poll structs for POLLHUP event (closed pipe) */

	unsigned int 		num;							/**< number of threads */
	unsigned int 		next;							/**< next thread*/

	int 				debug;							/**< debug flag */
};

/**
 * @brief Waits for a signal
 *
 * @param job thread's job
 */
static inline void worker_wait(job_t *job) {
	while (!job->cur){
		// check kill mutex
		if (!pthread_mutex_trylock(&job->kill_mutex)) {
			pthread_mutex_unlock(&job->kill_mutex);

			// close writer side and exit
			close(job->tube[1]);
			pthread_exit(NULL);
		}

		// wait for another task or kill signal
		buffer_wait(job->buffer);

		// next task
		job->cur = buffer_get_first(job->buffer);
	}
}

/**
 * @brief Thread function
 *
 * @param arg a job
 * @return NULL
 */
void *worker_searcher(void *arg) {
	UTILS_CHECK(!arg, EINVAL, exit(EXIT_FAILURE));

	job_t *job = (job_t *)arg;
	char line[PIPE_BUF];
	int bufSize = 0;

	while (1) {
		// no work to do
		worker_wait(job);

		// do job
		dups_search((node_t *)job->cur->load, job->id, line, &bufSize);
		if (bufSize) {
			write(job->tube[1], &bufSize, sizeof(bufSize));
			write(job->tube[1], line, bufSize+1);
		}

		// clean
		buffer_lock(job->buffer);
		buffer_remove(job->cur);
		job->cur = buffer_get_first(job->buffer);
		buffer_unlock(job->buffer);
	}

	return NULL;
}

/**
 * @brief Initializes the library
 *
 * @param num 		number of workers (default: 2)
 * @param prefix	prefix for the temp files
 * @param debug		debug mode (!=0 to enable)
 * @return a pointer to a new pool of workers or NULL
 */
workerPool_t *worker_init(unsigned int num, int debug) {
	workerPool_t *newPool = (workerPool_t *) malloc(sizeof(workerPool_t));
	if (!newPool) {
		perror("Error: worker_init > malloc");
		exit(EXIT_FAILURE);
	}

	pthread_attr_t attr;
	int ret;

	if (num > 1 && num <= BUFFER_MAX_WORKERS) newPool->num = num;
	else newPool->num = 2;
	newPool->next = 0;
	newPool->debug = debug;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (int i=0; i<newPool->num; i++) {
		newPool->jobs[i].id = i;
		newPool->jobs[i].pool = newPool;
		newPool->jobs[i].buffer = buffer_init(0, 0);
		newPool->jobs[i].cur = NULL;
		pthread_mutex_init(&newPool->jobs[i].kill_mutex, NULL);
		pthread_mutex_lock(&newPool->jobs[i].kill_mutex);

		// create a pipe
		ret = pipe(newPool->jobs[i].tube);
		if (ret) {
			perror("Error: worker_init > pipe");
			exit(ret);
		}
		// reader side monitoring
		newPool->pollin[i].fd = newPool->jobs[i].tube[0];
		newPool->pollin[i].events = POLLIN;
		newPool->pollin[i].revents = 0;

		newPool->pollhup[i].fd = newPool->jobs[i].tube[0];
		newPool->pollhup[i].events = POLLHUP;
		newPool->pollhup[i].revents = 0;

		ret = pthread_create(&newPool->threads[i], &attr, worker_searcher, (void *)(&newPool->jobs[i]));
		if (ret) {
			perror("Error: worker_init > pthread_create");
			exit(ret);
		}
	}
	pthread_attr_destroy(&attr);

	return newPool;
}

/**
 * @brief Output multiplexer
 *
 * @param pool 		the pool
 * @param finish	last lines
 */
inline void worker_mux(workerPool_t *pool, int finish) {
	static unsigned long long next[BUFFER_MAX_WORKERS];
	static char line[BUFFER_MAX_WORKERS][PIPE_BUF];
	int min, flag=1, bufSize;

	// mux while a line from each thread is available
	while (flag) {
		// select the minimum number
		min = 0;
		for (int i=0; i<pool->num; i++) {
			// if there is no line read and there are data in the pipe, get the next line
			if (!next[i] && poll(&pool->pollin[i], 1, 0) && read(pool->jobs[i].tube[0], &bufSize, sizeof(bufSize))) {
				read(pool->jobs[i].tube[0], line[i], bufSize+1);
				next[i] = strtoull(line[i], NULL, 10);
			}

			if (next[i] < next[min]) min = i;
		}

		// output
		if (next[min]) {
			fputs(line[min], stdout);

			// reset
			line[min][0] = '\0';
			next[min] = 0;
		} else flag = 0;
	}

	// mux the last lines
	while (finish) {
		// select the minimum number
		min = -1;
		for (int i=0; i<pool->num; i++) {
			if (next[i] && (min < 0 || (min >= 0 && next[i] < next[min])))
				min = i;
		}

		// output
		if (min >= 0) {
			fputs(line[min], stdout);

			// reset
			line[min][0] = '\0';
			next[min] = 0;

			// read another line if available
			if (poll(&pool->pollin[min], 1, 0) && read(pool->jobs[min].tube[0], &bufSize, sizeof(bufSize))) {
				read(pool->jobs[min].tube[0], line[min], bufSize+1);
				next[min] = strtoull(line[min], NULL, 10);
			}
		} else finish = 0;
	}
}

/**
 * @brief Cleaner
 *
 * @param pool the pool
 */
void worker_destroy(workerPool_t *pool) {
	UTILS_CHECK(!pool, EINVAL, return);

	// signal
	for (int i=0; i<pool->num; i++) {
		pthread_mutex_unlock(&pool->jobs[i].kill_mutex);
		buffer_signal(pool->jobs[i].buffer);
	}

	// wait POLLHUP and mux last lines
	while (poll(pool->pollhup, pool->num, 0) != pool->num)
		worker_mux(pool, 0);
	worker_mux(pool, 1);

	// join
	for (int i=0; i<pool->num; i++) {
		pthread_join(pool->threads[i], NULL);

		// destroy
		pthread_mutex_destroy(&pool->jobs[i].kill_mutex);
		buffer_destroy(pool->jobs[i].buffer);
	}

	free(pool);
}

/**
 * @brief Adds a new task to a worker
 *
 * @param pool the pool
 * @param load task content
 * @return 0 on success, -1 on error
 */
inline int worker_add_task(workerPool_t *pool, void *load) {
	UTILS_CHECK(!pool || !load, EINVAL, return -1);

	// next worker
	unsigned int n = pool->next++;
	if (pool->next == pool->num) pool->next = 0;

	// new task
	buffer_lock(pool->jobs[n].buffer);
	buffer_t *buffer = pool->jobs[n].buffer;
	node_t * task_new = buffer_new(buffer);
	if (!task_new) {
		perror("Error: worker_add_task > buffer_new");
		buffer_unlock(pool->jobs[n].buffer);
		return -1;
	}
	task_new->load = load;

	// append task
	buffer_append(buffer, task_new);
	buffer_unlock(pool->jobs[n].buffer);

	// signal
	buffer_signal(pool->jobs[n].buffer);

	//if (pool->debug) buffer_debug(buffer, pkt_print);
	//if (pool->debug) buffer_print(buffer);
	return 0;
}
