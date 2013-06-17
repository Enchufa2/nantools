/*
 * utils.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "utils.h"
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <ctype.h>

inline double utils_timeval2float(struct timeval *tv) {
    if (!tv) return -1;
    double ret = tv->tv_sec+tv->tv_usec/1000000.0;
    return ret;
}

inline long double utils_timespec2float(struct timespec *tv) {
    if (!tv) return -1;
    long double ret = tv->tv_sec+tv->tv_nsec/1000000000.0L;
    return ret;
}

inline void utils_mac2txt(const char *macAddress, char *txt) {
    //static char txt[20];
    unsigned char   *mac = (unsigned char*)macAddress;    
    char    aux[5];
    int i = 0;
    
    txt[0] = 0;
    for (i = 0; i < 5; i++) {
        if (mac[i] < 16) sprintf(aux, "0%x:", mac[i]&0xFF);
        else sprintf(aux, "%x:", mac[i]&0xFF);
        strcat(txt, aux);
    }
    if (mac[i] < 16) sprintf(aux, "0%x", mac[i]&0xFF);
    else sprintf(aux, "%x", mac[i]&0xFF);
    strcat(txt, aux);
}

unsigned long long utils_fsize(char *file) {
	struct stat buf;
	stat(file, &buf);
	return (unsigned long long)buf.st_size;
}

inline void utils_print_progress(pcap_t *cap, unsigned long long size) {
	static double realTimeLastLog = 0;
	static int lastPercent = -1;
	
	struct timeval  presentTime_tv;
	gettimeofday(&presentTime_tv, NULL);
	double presentTime = presentTime_tv.tv_sec+presentTime_tv.tv_usec/1000000.0;

	if (realTimeLastLog == 0) realTimeLastLog = presentTime;
	if (presentTime-realTimeLastLog <= UTILS_MAXTIME_SHOWPROGRESS) return;
	realTimeLastLog = presentTime;

	// Calculate the ratio of complete-to-incomplete.
	unsigned long long x = (unsigned long long)ftello(pcap_file(cap));
	int percent = (int)(x * 10000 / (float)size);
	if (percent <= lastPercent) return;
	lastPercent = percent;

	fprintf(stderr, "Progress: %0.2f %% (%llu of %llu)\n", percent/(float)100, x, size);
}
