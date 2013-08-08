/*
 * buffer.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef BUFFER_H_
#define BUFFER_H_

#define BUFFER_MAX_WORKERS 64   /**< maximum number of workers */

#include <pthread.h>

typedef struct node node_t;
typedef struct buffer buffer_t;

/**
 * Double-linked list
 */
struct node {
    unsigned long long  inUse;      /**< this flag can be used to mark the lower bound of a thread's window */
    void                *load;      /**< Pointer to the node's content */
    node_t              *prev;      /**< previous node */
    node_t              *next;      /**< next node */
    buffer_t            *buffer;    /**< pointer to the buffer */
    pthread_mutex_t     mutex;      /**< node mutex */
};

// with threads
int buffer_lock(buffer_t *buffer);
int buffer_unlock(buffer_t *buffer);
void buffer_wait(buffer_t *buffer);
void buffer_signal(buffer_t *buffer);

// initializer
buffer_t *buffer_init(unsigned int workers, unsigned long long max_count);

// delete buffer and free the associated obstack
void buffer_destroy(buffer_t *buffer);

// create a new node
node_t *buffer_new(buffer_t *buffer);

// append the new node
int buffer_append(buffer_t *buffer, node_t *node);

// remove node (move to resources)
int buffer_remove(node_t *node);

// set/get markers
int buffer_init_markers(node_t *node);
int buffer_set_marker(node_t *node, unsigned int id);
node_t *buffer_get_marker(buffer_t *buffer, unsigned int id);

// remove old nodes from buffer
int buffer_trim(buffer_t *buffer);

// debugging
void buffer_print(buffer_t *buffer);
void buffer_debug(buffer_t *buffer, void (*print_node)(void *load));

// first node
node_t *buffer_get_first(buffer_t *buffer);
int buffer_is_first(node_t *node);

// last node
node_t *buffer_get_last(buffer_t *buffer);
int buffer_is_last(node_t *node);

// number of nodes in buffer
unsigned long long buffer_get_count(buffer_t *buffer);

// count reaches max_count
int buffer_is_full(buffer_t *buffer);

// number of free nodes
unsigned long long buffer_get_free(buffer_t *buffer);

#endif /* BUFFER_H_ */
