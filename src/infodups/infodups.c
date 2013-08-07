/*
 * infodups.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#define INFODUPS_VERSION "1.1.0"

#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include "../common/utils.h"
#include "worker.h"
#include "dups.h"

void print_options() {
	fprintf(stderr, "\ninfodups %s\n", INFODUPS_VERSION);
	fputs(	"Identifies and marks duplicate packets in PCAP files.\n"
			"http://github.com/Enchufa2/nantools\n\n"
			"Usage: infodups [options] -i <file>\n"
			"  -i <file>        PCAP file\n\n"
			"Options:\n"
			"  -h               show help\n"
			"  -v               show progress\n"
			"  -x               show extended output\n"
			"  -s               print suspicious duplicates\n"
			"  -b               (debug) show window state for every packet\n\n"

			"  -F               fast mode\n"
			"  [-0] [-1] ...    deactivate duplicates of each type\n\n"

			"  -t <timeout>     window length in seconds (default: 0.1)\n"
			"  -n <maxPos>      window length in positions\n\n"

			"  -T <threads>     number of threads to use [2-64] (default: no threads)\n"
			"  -M <mem>         memory limit (GB) with multithreading (default: 2)\n\n"

			"Copyright (C) 2013 Iñaki Úcar <i.ucar86@gmail.com>\n"
			"Distributed under the GNU General Public License v3.0\n"
			"This is free software: you are free to change and redistribute it.\n"
			"There is NO WARRANTY, to the extent permitted by law.\n\n",
	stderr);
}

void print_help() {
	fputs(	"Types of duplicates:\n"
			"  -1               Suspicious, possible duplicates (with option '-s')\n",
	stderr);
	for (int i=0; i<DUPS_COMPARATORS; i++)
		fprintf(stderr, "   %i               %s\n", i, DUPS_TYPE[i].description);
	fputs(	"\nOutput: <dupNo> <diffNo> <type> <nullPay> <vlan> <dscp> <diffTs> <diffTTL>\n"
			"   1 <dupNo>       duplicate position\n"
			"   2 <diffNo>      position difference between copies\n"
			"   3 <type>        type of duplicate\n"
			"   4 <nullPay>     NULL payload flag\n"
			"   5 <vlan>        does the VLAN tag change between copies?\n"
			"   6 <dscp>        does the DSCP tag change between copies?\n"
			"   7 <diffTs>      timestamp difference between copies\n"
			"   8 <diffTTL>     TTL difference between copies\n\n"

			"Extended output ('-x'): <dupTs> <dupTTL> <dupSrcMAC> > <dupDstMAC> <dupSrcIP> > <dupDstIP> | <fromSrcMAC> > <fromDstMAC> <fromSrcIP> > <fromDstIP>\n"
			"   9 <dupTs>       duplicate timestamp\n"
			"  10 <dupTTL>      duplicate TTL\n"
			"  11 <dupSrcMAC>   duplicate source MAC\n"
			"  13 <dupDstMAC>   duplicate destination MAC\n"
			"  14 <dupSrcIP>    duplicate source IP\n"
			"  16 <dupDstIP>    duplicate destination IP\n"
			"  18 <fromSrcMAC>  first copy source MAC (if it changed)\n"
			"  20 <fromDstMAC>  first copy destination MAC (if it changed)\n"
			"  21 <fromSrcIP>   first copy source IP (if it changed)\n"
			"  23 <fromDstIP>   first copy destination IP (if it changed)\n\n",
	stderr);
}

// globals
static buffer_t *buffer;
static workerPool_t *pool;
static pcap_t *traceFile;
static unsigned long long fileSize;
static int showProgress, debug, threads;
static stats_t stats;

// final statistics
static void print_stats() {
	fprintf(stderr, "\n----------- statistics -----------\n");
	fprintf(stderr, "%llu packets (%llu IP, %llu TCP, %llu UDP, %llu errors), ", stats.pkts.numPkts, stats.pkts.numIP, stats.pkts.numTCP, stats.pkts.numUDP, stats.pkts.numErrors);
	fprintf(stderr, "%.6lf seconds elapsed\n", utils_timeval2float(&stats.pkts.endTime)-utils_timeval2float(&stats.pkts.startTime));
	for (int i=0; i<DUPS_COMPARATORS; i++)
		fprintf(stderr, "%10llu duplicates of type %i (%s)\n", stats.numDup[i], i, DUPS_TYPE[i].description);
	fprintf(stderr, "%10llu duplicates of type -1 (suspicious)\n", stats.numSuspicious);
}

void update(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
	if (!stats.pkts.numPkts) stats.pkts.startTime = header->ts;
	stats.pkts.numPkts++;
	stats.pkts.endTime = header->ts;

	// create packet
	node_t *node_new = buffer_new(buffer);
	if (!node_new) {
		stats.pkts.numErrors++;
		return;
	}
	node_new->load = (void *) pkt_fill(node_new, stats.pkts.numPkts, (void*)bytes, header->len, header->caplen, (struct timeval*)&header->ts);
	if (!node_new->load) {
		stats.pkts.numErrors++;
		return;
	}
	pkt_dissect((pkt_t *)node_new->load);
	buffer_append(buffer, node_new);
	if (stats.pkts.numPkts == 1) buffer_init_markers(node_new);

	// search for duplicates
	if (threads) worker_add_task(pool, (void *)node_new);
	else dups_search(node_new, 0, NULL, NULL);

	// debug
	if (debug) buffer_debug(buffer, pkt_print);

	// mux output
	if (threads) worker_mux(pool, 0);

	// trim window
	buffer_trim(buffer);
	while (buffer_is_full(buffer)) {
		buffer_print(buffer);
		worker_mux(pool, 0);
		sleep(3);
		buffer_trim(buffer);
	}

	// show progress
	if (showProgress) utils_print_progress(traceFile, fileSize);

	return;
}

int main (int argc, char **argv) {
	char errbuf[5000], option;
	char *pcapFilePath = NULL;
	char *value = NULL;
	int ret, mode=0, fast=0, showExtOut=0, showSuspicious=0;
	unsigned int dupMask=0;
	double memory=2;
	unsigned long long max_count;

	while ((option = getopt(argc, argv, "hvxbi:t:n:s012345FT:M:")) != -1) {
		switch (option) {
			case 'h':
				print_options();
				print_help();
				exit(0);
			case 'v':
				showProgress = 1;
				fprintf(stderr, "infodups %s\n\n", INFODUPS_VERSION);
				break;
			case 'x':
				showExtOut = 1;
				break;
			case 'b':
				debug = 1;
				break;
			case 'i':
				pcapFilePath = optarg;
				break;
			case 't':
				mode = 0;
				value = optarg;
				break;
			case 'n':
				mode = 1;
				value = optarg;
				break;
			case 's':
				showSuspicious = 1;
				break;
			case 'F':
				fast = 1;
				break;
			case 'T':
				threads = atoi(optarg);
				break;
			case 'M':
				memory = atof(optarg);
				break;
			default:
				dupMask = dupMask | (0x0001 << ((int)option - 48));
				break;
		}
	}
	if (pcapFilePath == NULL) {
		print_options();
		return EXIT_FAILURE;
	}

	max_count = memory*1000000000/(PKT_BYTES+100);

	// init
	buffer = buffer_init(threads, max_count);
	if (!buffer) return EXIT_FAILURE;
	pkt_init(fast, &stats.pkts);
	dups_init(dupMask, fast, mode, value, showExtOut, showSuspicious, &stats);
	if (threads) {
		pool = worker_init(threads, debug);
		if (!pool) return EXIT_FAILURE;
	}

	if (showProgress) fileSize = utils_fsize(pcapFilePath);
	
	// loop
	traceFile = pcap_open_offline(pcapFilePath, errbuf);
	if (!traceFile) {
		fprintf(stderr, "Error: cannot open trace file %s\n", pcapFilePath);
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}
	ret = pcap_loop(traceFile, -1, update, NULL);

	if (threads && showProgress) fputs("*********** WAITING FOR THREADS ***********\n", stderr);

	// clean
	pcap_close(traceFile);
	if (threads) worker_destroy(pool);
	buffer_destroy(buffer);
	pkt_destroy();
	dups_destroy();
	
	print_stats();
	return ret;
}
