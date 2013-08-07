/*
 * tseries.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

// TODO: translate comments

#define TSERIES_VERSION "1.0.0"

#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include "../common/utils.h"
#include "series.h"

#define MAX_LINE 1000

void print_options() {
	fprintf(stderr, "\ntseries %s\n", TSERIES_VERSION);
	fputs(	"Computes multiple time series, one per input filter, from PCAP files.\n"
			"http://github.com/Enchufa2/nantools\n\n"
			"Usage: tseries [options] -i <file> -f <filters>\n"
			"  -i <file>        PCAP file\n"
			"  -f <filters>     TXT file with one filter per line (default: BPF filters, see '-N')\n\n"
			"Options:\n"
			"  -h               show help\n"
			"  -v               show progress\n\n"

			"  -p <filter>      BPF pre-filter\n\n"

			"  -n <msecs>       bucket length (default: 1000)\n"
			"  -z               do not dump zeros\n"
			"  -t <ts>          reference timestamp (ms)\n\n"

			"  -x               [BPF mode] break at first match (by default, every packet checks all filters)\n"
			"  -s <len>         [BPF mode] snaplen (default: 65535)\n\n"

			"  -N               activate NETS mode: each filter has the form <srcNet srcMask dstNet dstMask>\n\n"

			"Copyright (C) 2013 Iñaki Úcar <i.ucar86@gmail.com>\n"
			"Distributed under the GNU General Public License v3.0\n"
			"This is free software: you are free to change and redistribute it.\n"
			"There is NO WARRANTY, to the extent permitted by law.\n\n",
	stderr);
}

void print_help() {
	fputs(	"BPF mode:\n"
			"  Calcula la serie temporal para múltiples filtros BPF. Si todas las series comparten algo en común\n"
			"  (p. ej.: todas están restringidas a un determinado puerto), puede realizarse un prefiltrado mediante\n"
			"  la opción '-p' (con el filtro entrecomillado). Las series se calculan sincronizadas con el timestamp\n"
			"  del primer paquete de la traza, o con el timestamp que se le indique manualmente mediante la opción '-t'.\n\n"

			"  En principio, se contempla la posibilidad de que los filtros no sean excluyentes. Por ello, cada paquete\n"
			"  pasa por todos los filtros especificados. Si se tiene seguridad de que los filtros son excluyentes (un\n"
			"  paquete no puede verificar más de un filtro), incluir la opción '-x' acelera el procesado. También resulta\n"
			"  conveniente, en la medida de lo posible, ordenar los filtros en el archivo de texto del más común (el que\n"
			"  más paquetes lo verifican) al menos.\n\n"

			"NETS mode:\n"
			"  Calcula la serie temporal para múltiples subredes origen-destino. Dichas subredes se especifican mediante\n"
			"  un fichero de filtros con el formato del siguiente ejemplo:\n\n"

			"    8.8.0.0   255.255.0.0   0.0.0.0   0.0.0.0\n\n"

			"  que se lee como 'el tráfico con origen en la red 8.8. y cualquier destino'. El filtrado se realiza por\n"
			"  direcciones IP mediante un algoritmo de complejidad constante denominado 'grid of tries'. Los filtros\n"
			"  pueden estar incluidos unos dentro de otros sin problemas: a la salida las series están completas sin\n"
			"  necesidad de procesado adicional.\n\n"

			"  Como en el modo BPF, las series se calculan sincronizadas con el timestamp del primer paquete de la traza,\n"
			"  o con el timestamp que se le indique manualmente mediante la opción '-t'. Adicionalmente, se puede realizar\n"
			"  un pre-filtrado con un filtro BPF (p. ej.: 'tcp 80') mediante la opción '-p' (con el filtro entrecomillado).\n\n"

			"Output:\n"
			"  <#filter> <timestamp> <#bytes> <#packets>\n\n",
	stderr);
}

// globals
static int showProgress;
static pcap_t *traceFile;
static unsigned long long fileSize;

void update(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes) {
	static unsigned long long pos;
	pos++;
	if (pos == 1 && !series_initTime)
		series_initTime = header->ts.tv_sec*1000.0+header->ts.tv_usec/1000.0;

	// filter
	series_filter(header, bytes);

	// progress
	if (showProgress) utils_print_progress(traceFile, fileSize);
	return;
}

int main (int argc, char **argv) {
	char errbuf[5000], option;
	char *pcapFilePath = NULL;
	char *prefilter = NULL;
	char *filtersPath = NULL;
	char filter[MAX_LINE];
	struct bpf_program fp;
	FILE *fileOfFilters = NULL;
	int	ret, snaplen = 65535;

	while ((option = getopt(argc, argv, "hvi:p:f:xs:n:zt:N")) != -1) {
		switch (option) {
			case 'h':
				print_options();
				print_help();
				exit(0);
			case 'v':
				showProgress = 1;
				break;
			case 'i':
				pcapFilePath = optarg;
				break;
			case 'p':
				prefilter = optarg;
				break;
			case 'f':
				filtersPath = optarg;
				break;
			case 'x':
				series_breakAtFirstMatch = 1;
				break;
			case 's':
				snaplen = atoi(optarg);
				break;
			case 'n':
				series_msecsPointInTimeSeries = atoi(optarg);
				break;
			case 'z':
				series_dumpZeros = 0;
				break;
			case 't':
				series_initTime = atoll(optarg);
				break;
			case 'N':
				series_mode = SERIES_NETS;
				break;
		}
	}
	if (pcapFilePath == NULL || filtersPath == NULL) {
		print_options();
		return EXIT_FAILURE;
	}
	
	fileOfFilters = fopen(filtersPath, "r");
	if (fileOfFilters == NULL) {
		fprintf(stderr, "Error abriendo fichero de filtros: %s\n", filtersPath);
		return EXIT_FAILURE;
	}
	while (!feof(fileOfFilters)) {
		if(!fgets(filter, MAX_LINE, fileOfFilters)) break;
		if (filter[strlen(filter)-1] == '\n') filter[strlen(filter)-1] = '\0';
		if (strlen(filter)) {
			if (series_add_filter(filter, snaplen, DLT_EN10MB))
				return EXIT_FAILURE;
		}
	}
	fclose(fileOfFilters);

	if (series_init()) return EXIT_FAILURE;

	if (showProgress) fileSize = utils_fsize(pcapFilePath);
	
	// open
	traceFile = pcap_open_offline(pcapFilePath, errbuf);
	if (!traceFile) {
		fprintf(stderr, "Error: cannot open trace file %s\n", pcapFilePath);
		fprintf(stderr, "%s\n", errbuf);
		return EXIT_FAILURE;
	}
	
	// prefilter
	if (pcap_compile(traceFile, &fp, prefilter, 1, 0)) {
		fprintf(stderr, "Error: couldn't parse filter %s: %s\n", prefilter, pcap_geterr(traceFile));
		return EXIT_FAILURE;
	}
	if (pcap_setfilter(traceFile, &fp)) {
		fprintf(stderr, "Error: couldn't install filter %s: %s\n", prefilter, pcap_geterr(traceFile));
		return EXIT_FAILURE;
	}
	
	// loop
	ret = pcap_loop(traceFile, -1, update, NULL);
	
	// clean
	pcap_freecode(&fp);
	pcap_close(traceFile);
	series_destroy();
	
	return ret;
}
