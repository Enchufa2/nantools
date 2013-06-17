/*
 * utils.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef UTILS_H
#define UTILS_H

#ifndef UTILS_MAXTIME_SHOWPROGRESS
#define UTILS_MAXTIME_SHOWPROGRESS 5 // seconds
#endif

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <pcap/pcap.h>

double utils_timeval2float(struct timeval *tv);

long double utils_timespec2float(struct timespec *tv);

// get formatted MAC: AA:AA:AA:AA:AA:AA (always in the same buffer)
void utils_mac2txt(const char *mac, char *txt);

unsigned long long utils_fsize(char *file);

void utils_print_progress(pcap_t *cap, unsigned long long size);

#endif /* UTILS_H_ */
