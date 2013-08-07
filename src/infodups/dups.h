/*
 * dups.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef DUPS_H_
#define DUPS_H_

#include "buffer.h"
#include "pkt.h"
#include <stdio.h>

#define DUPS_COMPARATORS 6	/**< Number of types of duplicates */

/**
 * Statistics
 */
typedef struct {
	unsigned long long 	numSuspicious;				/**< number of suspicious pairs (same payload but not identified as duplicates) */
	unsigned long long 	numDup[DUPS_COMPARATORS];	/**< number of duplicates of each type */
	pktStats_t		 	pkts;						/**< packet statistics */
} stats_t;

/**
 * Type of duplicate
 */
typedef struct {
	const char 	*description;		/**< description */
	int 		(*comparator)();	/**< specific comparator */
} dup_t;

dup_t DUPS_TYPE[DUPS_COMPARATORS]; /**< Array of types */

// initializer
// fast mode: only IP packets + switching duplicates + routing duplicates
void dups_init(unsigned int dupMask, int fast, int mode, char *value, int extendedOutput, int suspicious, stats_t *stats);

/**
 * @brief Searches for duplicates
 *
 * @param node		current node
 * @param id		thread identifier
 * @param output 	output stream or NULL
 * @param bufSize 	number of bytes written to the stream
 * @return 1 if a duplicate was found, 0 if not, -1 on error
 */
int (*dups_search)(node_t *node, unsigned int id, char *output, int *bufSize);

// cleaner
void dups_destroy();

#endif /* DUPS_H_ */
