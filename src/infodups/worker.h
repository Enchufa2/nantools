/*
 * worker.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef WORKER_H_
#define WORKER_H_

typedef struct workerPool workerPool_t;

// initializer
workerPool_t *worker_init(unsigned int num, int debug);

// free all memory
void worker_destroy(workerPool_t *pool);

// add a new task
int worker_add_task(workerPool_t *pool, void *load);

// output multiplexer
void worker_mux(workerPool_t *pool, int finish);

#endif /* WORKER_H_ */
