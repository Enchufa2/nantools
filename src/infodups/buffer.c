/*
 * buffer.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "buffer.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <obstack.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

/**
 * Private buffer structure
 */
struct buffer {
	unsigned int 		id; 						/**< buffer/obstack identifier */
	unsigned int 		workers;					/**< number of threads that works with the node.inUse flag */

	node_t 				*first;						/**< first node */
	node_t 				*last;						/**< last node */
	node_t 				*res;						/**< resources: pointer to a list of free nodes */
	node_t				*mark[BUFFER_MAX_WORKERS];	/**< markers for workers */

	unsigned long long 	count;						/**< number of nodes in the buffer */
	unsigned long long 	max_count;					/**< maximum number of nodes allowed */
	unsigned long long 	free;						/**< number of free nodes */

	pthread_mutex_t 	mutex;						/**< buffer mutex */
	pthread_mutex_t 	cond_mutex;					/**< buffer condition mutex */
	pthread_cond_t 		cond;						/**< buffer condition */
};

static struct obstack **buffer_obstack;		/**< array of obstacks (one obstack per buffer) */
static unsigned int buffer_obstack_size;	/**< number of obstacks (or buffers) */

/**
 * @brief Locks a buffer (wrapper for pthread_mutex_lock())
 * @param buffer the buffer
 * @return the result of pthread_mutex_lock() call
 */
inline int buffer_lock(buffer_t *buffer) {
	return pthread_mutex_lock(&buffer->mutex);
}

/**
 * @brief Unlocks a buffer (wrapper for pthread_mutex_unlock())
 * @param buffer the buffer
 * @return the result of pthread_mutex_unlock() call
 */
inline int buffer_unlock(buffer_t *buffer) {
	return pthread_mutex_unlock(&buffer->mutex);
}

/**
 * @brief Waits until the buffer.cond is signaled
 * @param buffer the buffer
 */
inline void buffer_wait(buffer_t *buffer) {
	pthread_mutex_lock(&buffer->cond_mutex);
	pthread_cond_wait(&buffer->cond, &buffer->cond_mutex);
	pthread_mutex_unlock(&buffer->cond_mutex);
}

/**
 * @brief Signals the buffer.cond
 * @param buffer the buffer
 */
inline void buffer_signal(buffer_t *buffer) {
	pthread_mutex_lock(&buffer->cond_mutex);
	pthread_cond_signal(&buffer->cond);
	pthread_mutex_unlock(&buffer->cond_mutex);
}

/**
 * @brief Initializes a new buffer
 *
 * This library is intended for sliding windows and uses GNU obstack.h in order to efficiently allocate large chunks of memory.
 * Each buffer is internally allocated in a separate obstack.
 *
 * @param workers number of concurrent threads
 * @see BUFFER_MAX_WORKERS
 * @param max_count maximum number of nodes allowed (in order to control memory usage with threads)
 * @return a pointer to the buffer (NULL if error)
 */
buffer_t *buffer_init(unsigned int workers, unsigned long long max_count) {
	UTILS_CHECK(workers > BUFFER_MAX_WORKERS, EINVAL, return NULL);

	/* new pointer to struct obstack */
	unsigned int i = buffer_obstack_size++;
	void *tmp = realloc(buffer_obstack, buffer_obstack_size*sizeof(struct obstack *));
	if (!tmp) {
		perror("Error: buffer_init > realloc");
		return NULL;
	}

	/* alloc a new obstack */
	buffer_obstack = (struct obstack **)tmp;
	buffer_obstack[i] = (struct obstack *) malloc(sizeof(struct obstack));
	if (!buffer_obstack[i]) {
		perror("Error: buffer_init > malloc");
		return NULL;
	}
	obstack_init(buffer_obstack[i]);
	obstack_chunk_size(buffer_obstack[i]) = 1048576;

	/* alloc a new buffer within its obstack */
	buffer_t *buffer = obstack_alloc(buffer_obstack[i], sizeof(buffer_t));
	if (!buffer) {
		perror("Error: buffer_init > obstack_alloc");
		return NULL;
	}
	buffer->id = i;
	buffer->workers = workers;
	buffer->count = 0;
	buffer->max_count = max_count;
	buffer->free = 0;
	buffer->first = NULL;
	buffer->last = NULL;
	buffer->res = NULL;
	pthread_mutex_init(&buffer->mutex, NULL);
	pthread_mutex_init(&buffer->cond_mutex, NULL);
	pthread_cond_init(&buffer->cond, NULL);

	return buffer;
}

/**
 * @brief Creates a node (without modifying the current buffer)
 * @see buffer_append()
 *
 * This function pulls a node from resources (if available) or allocates a new one.
 *
 * @param buffer the buffer
 * @return a pointer to the node (NULL if error)
 */
inline node_t *buffer_new(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return NULL);

	node_t *node_new;
	if (!buffer->free) {
		node_new = obstack_alloc(buffer_obstack[buffer->id], sizeof(node_t));
		if (!node_new) {
			perror("Error: buffer_new > obstack_alloc");
			return NULL;
		}
		node_new->buffer = buffer;
		node_new->load = NULL;
		node_new->prev = NULL;
		pthread_mutex_init(&node_new->mutex, NULL);
	} else {
		node_new = buffer->res;
		buffer->res = buffer->res->next;
		if (buffer->res) buffer->res->prev = NULL;
		buffer->free--;
	}
	node_new->next = NULL;
	node_new->inUse = 0;

	return node_new;
}

/**
 * @brief Appends a node previously created
 * @see buffer_new()
 *
 * This function doesn't check if the node passed belongs to the buffer.
 *
 * @param buffer the buffer
 * @param node the node to append
 * @return 0 on success, -1 on error
 */
inline int buffer_append(buffer_t *buffer, node_t *node) {
	UTILS_CHECK(!buffer || !node, EINVAL, return -1);

	if (!buffer->count) buffer->first = node;
	else {
		buffer->last->next = node;
		node->prev = buffer->last;
	}
	buffer->last = node;
	buffer->count++;

	return 0;
}

/**
 * @brief Removes a node
 *
 * Its memory is not freed: the node is pushed to the resources list.
 *
 * @param node the node
 * @return 0 on success, -1 on error
 */
inline int buffer_remove(node_t *node) {
	UTILS_CHECK(!node || !node->buffer->count, EINVAL, return -1);

	buffer_t *buffer = node->buffer;
	if (buffer->count==1) {
		buffer->first = NULL;
		buffer->last = NULL;
	} else {
		if (node == buffer->first) {
			buffer->first = buffer->first->next;
			buffer->first->prev = NULL;
		}
		else if (node == buffer->last) {
			buffer->last = buffer->last->prev;
			buffer->last->next = NULL;
		} else {
			node->prev->next = node->next;
			node->next->prev = node->prev;
		}
	}
	node->prev = NULL;
	node->next = buffer->res;
	if (buffer->free) buffer->res->prev = node;
	buffer->res = node;
	buffer->free++;
	buffer->count--;

	return 0;
}

/**
 * @brief Shows info about the current state of the buffer
 *
 * @param buffer the buffer
 */
inline void buffer_print(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return);

	fprintf(stderr, "#bufferID: %u count: %llu free: %llu\n", buffer->id, buffer->count, buffer->free);
}

/**
 * @brief Sets the node.inUse flag
 *
 * @param node the node
 * @param id thread identifier
 * @return 0 on success, -1 on error
 */
static inline void buffer_set_inUse(node_t *node, unsigned int id) {
	pthread_mutex_lock(&node->mutex);
	node->inUse |= (1<<id);
	//node->inUse++;
	pthread_mutex_unlock(&node->mutex);
}

/**
 * @brief Unsets the node.inUse flag
 *
 * @param node the node
 * @param id thread identifier
 * @return 0 on success, -1 on error
 */
static inline void buffer_unset_inUse(node_t *node, unsigned int id) {
	pthread_mutex_lock(&node->mutex);
	node->inUse &= ~(1<<id);
	//node->inUse--;
	pthread_mutex_unlock(&node->mutex);
}

/**
 * @brief Sets this node in use for all workers
 * @see buffer_trim()
 *
 * @param node the node
 * @return 0 on success, -1 on error
 */
int buffer_init_markers(node_t *node) {
	UTILS_CHECK(!node, EINVAL, return -1);

	buffer_t *buffer = node->buffer;
	if (buffer->workers)
		for (int i=0; i<buffer->workers; i++) {
			buffer_set_inUse(node, i);
			buffer->mark[i] = node;
		}
	else {
		buffer_set_inUse(node, 0);
		buffer->mark[0] = node;
	}

	return 0;
}

/**
 * @brief Stores a marker for a particular worker
 *
 * @param node the node
 * @param id thread identifier
 * @return 0 on success, -1 on error
 */
inline int buffer_set_marker(node_t *node, unsigned int id) {
	UTILS_CHECK(!node, EINVAL, return -1);

	buffer_set_inUse(node, id);
	buffer_unset_inUse(node->buffer->mark[id], id);
	node->buffer->mark[id] = node;

	return 0;
}

/**
 * @brief Gets the stored marker for a particular worker
 *
 * @param buffer the buffer
 * @param id thread identifier
 * @return a pointer to a node or NULL
 */
inline node_t *buffer_get_marker(buffer_t *buffer, unsigned int id) {
	UTILS_CHECK(!buffer, EINVAL, return NULL);

	return buffer->mark[id];
}

/**
 * @brief Trims the buffer starting from the first node until the first node in use
 *
 * @param buffer the buffer
 * @return 0 on success, -1 on error, 1 if there are no nodes
 */
inline int buffer_trim(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return -1);

	if (!buffer->count) return 1;

	node_t *node = buffer->first;
	while (!node->inUse) {
		node = node->next;
		buffer_remove(node->prev);
	}

	return 0;
}

// private
static inline void buffer_obstack_free(unsigned int id) {
	obstack_free(buffer_obstack[id], NULL);
	free(buffer_obstack[id]);
	buffer_obstack[id] = NULL;
}

/**
 * @brief Destroys a buffer and frees the associated obstack
 *
 * @param buffer the buffer
 */
void buffer_destroy(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return);

	node_t *node = buffer->first;
	while (node) {
		pthread_mutex_destroy(&node->mutex);
		node = node->next;
	}

	node = buffer->res;
	while (node) {
		pthread_mutex_destroy(&node->mutex);
		node = node->next;
	}

	pthread_mutex_destroy(&buffer->mutex);
	pthread_mutex_destroy(&buffer->cond_mutex);
	pthread_cond_destroy(&buffer->cond);
	buffer_obstack_free(buffer->id);
}

/**
 * @brief Shows more info about the current state of the buffer
 *
 * @param buffer the buffer
 * @param print_node (optional) a callback function for printing the node's content
 */
inline void buffer_debug(buffer_t *buffer, void (*print_node)(void *load)) {
	UTILS_CHECK(!buffer, EINVAL, return);

	buffer_print(buffer);

	node_t *node = buffer->first;
	fprintf(stderr, "########################");
	for (int i=0; i<buffer->count; i++) {
		if (i%4 == 0) fprintf(stderr, "\n");
		fprintf(stderr, "|%llu|", node->inUse);
		if (print_node) print_node(node->load);
		fprintf(stderr, "| <--> ");
		node = node->next;
	}

	node = buffer->res;
	fprintf(stderr, "\n########################");
	for (int i=0; i<buffer->free; i++) {
		if (i%4 == 0) fprintf(stderr, "\n");
		fprintf(stderr, "|%llu|", node->inUse);
		if (print_node) print_node(node->load);
		fprintf(stderr, "| <--> ");
		node = node->next;
	}
	fprintf(stderr, "\n\n");
}

/**
 * @brief Gets the first node of a buffer
 *
 * @param buffer the buffer
 * @return a pointer to the first node or NULL
 */
inline node_t *buffer_get_first(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return NULL);

	return buffer->first;
}

/**
 * @brief Checks if this node is the first of its buffer
 *
 * @param node the node
 * @return 1 if TRUE, 0 if FALSE, -1 on error
 */
inline int buffer_is_first(node_t *node) {
	UTILS_CHECK(!node, EINVAL, return -1);

	if (node != node->buffer->first) return 0;
	return 1;
}

/**
 * @brief Gets the last node of a buffer
 *
 * @param buffer the buffer
 * @return a pointer to the last node or NULL
 */
inline node_t *buffer_get_last(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return NULL);

	return buffer->last;
}

/**
 * @brief Checks if this node is the last of its buffer
 *
 * @param node the node
 * @return 1 if TRUE, 0 if FALSE, -1 on error
 */
inline int buffer_is_last(node_t *node) {
	UTILS_CHECK(!node, EINVAL, return -1);

	if (node != node->buffer->last) return 0;
	return 1;
}

/**
 * @brief Gets the number of nodes in a buffer
 *
 * @param buffer the buffer
 * @return the number of nodes
 */
inline unsigned long long buffer_get_count(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return 0);

	return buffer->count;
}

/**
 * @brief Checks if the buffer is full
 *
 * @param node the node
 * @return 1 if TRUE, 0 if FALSE, -1 on error
 */
inline int buffer_is_full(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return -1);

	if (buffer->count == buffer->max_count) return 1;
	return 0;
}

/**
 * @brief Gets the number of resources in a buffer
 *
 * @param buffer the buffer
 * @return the number of free nodes
 */
inline unsigned long long buffer_get_free(buffer_t *buffer) {
	UTILS_CHECK(!buffer, EINVAL, return 0);

	return buffer->free;
}
