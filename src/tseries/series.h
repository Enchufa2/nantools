/*
 * series.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef SERIES_H_
#define SERIES_H_

#define SERIES_BPF  0
#define SERIES_NETS 1

#include <pcap/pcap.h>

unsigned int        series_mode;
unsigned long long  series_initTime;
unsigned int        series_msecsPointInTimeSeries;  // Anchura del cubo de la serie temporal en milisegundos
unsigned int        series_dumpZeros;               // Volcar en la serie temporal todas muestras que se queden a 0 entre dos muestras con valor
unsigned int        series_breakAtFirstMatch;

int series_init();

void series_destroy();

int series_add_filter(char *filter, int snaplen, int linktype);

void series_compute(void *arg, int i);

void series_filter(const struct pcap_pkthdr *header, const u_char *bytes);

#endif /* SERIES_H_ */
