/*
 * series.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "series.h"
#include "DSTries.h"
#include "../common/eth.h"
#include "../common/ip.h"
#include <stdio.h>
#include <stdlib.h>

unsigned int series_mode = SERIES_BPF;
unsigned int series_msecsPointInTimeSeries = 1000;
unsigned int series_dumpZeros = 1;

typedef struct {
    int                 id;
    filter_t            *filter;
    struct bpf_program  bpf;
    long long           intervalStartTime;
    long long           bytesInInterval;
    long long           packetsInInterval;
} series_t;

typedef struct {
    const struct timeval    *time;
    int                     bytes;
    int                     endSeries;
} seriesData_t;

// private
static series_t     *series;
static int          num_series;
static ethFrame_t   *eth;
static IPPacket_t   *ip;
static filterList_t *filterList;
static dstNode_t    *triesTree;

static inline ethFrame_t *series_new_eth(ethFrame_t *frame, void *bytes, int size, int caplen, struct timeval *timestamp) {
    if (!frame) frame = malloc(sizeof(ethFrame_t));

    // init
    if (frame) {
        frame->bytes = bytes;
        frame->size = size;
        frame->caplen = caplen;
        frame->frameType = ETH_FRAMETYPE_NOTCHECKED;
        if (timestamp) frame->timestamp = *timestamp;
    } else
        perror("Error: series_new_eth > malloc");

    return frame;
}

static inline IPPacket_t *series_new_ipPkt(IPPacket_t *ipPkt, void *bytes, int caplen) {
    if (!ipPkt) ipPkt = malloc(sizeof(IPPacket_t));

    // init
    if (ipPkt) {
        ipPkt->bytes = bytes;
        ipPkt->caplen = caplen;
    } else
        perror("Error: series_new_ipPkt > malloc");

    return ipPkt;
}

// Extrae las IPs de un paquete Ethernet a las variables srcIP y dstIP. Devuelve 1 en caso de éxito, 0 en caso contrario.
static inline int series_unpack_addresses(void *header, const u_char *bytes, unsigned int *srcIP, unsigned int *dstIP) {
    if (!header || !bytes) return 0;

    eth = series_new_eth(eth, (void *)bytes, ((const struct pcap_pkthdr *)header)->len, ((const struct pcap_pkthdr *)header)->caplen, (struct timeval *)&((const struct pcap_pkthdr *)header)->ts);
    if (eth_get_ethertype(eth) != ETH_PROTO_IPv4) return 0;

    int bufSize;
    void *ipData = (void *)eth_get_data(eth, &bufSize);
    ip = series_new_ipPkt(ip, ipData, bufSize);

    *srcIP = ip_get_src(ip);
    *dstIP = ip_get_dst(ip);

    return 1;
}

int series_init() {
    if (series_mode == SERIES_NETS) {
        triesTree = DSTries_new_tree();
        int ret = DSTries_insert_filterList(triesTree, &filterList);
        if (!ret) {
            perror("Error: series_init > DSTries_insert_filterList");
            return -1;
        }

        eth = series_new_eth(NULL, NULL, 0, 0, NULL);
        ip = series_new_ipPkt(NULL, NULL, 0);
    }
    return 0;
}

void series_destroy() {
    seriesData_t data;
    data.time = NULL;
    data.bytes = 0;
    data.endSeries = 1;

    for (int i=0; i<num_series; i++) {
        series_compute((void *)&data, i);
        if (series_mode == SERIES_BPF) pcap_freecode(&series[i].bpf);
    }

    if (series_mode == SERIES_NETS) {
        free(eth);
        free(ip);
        DSTries_destroy_tree(triesTree);
        DSTries_destroy_filterList(filterList);
    }
    free(series);
}

int series_add_filter(char *filter, int snaplen, int linktype) {
    int ret, i = num_series++;
    void *tmp = realloc(series, num_series*sizeof(series_t));
    if (!tmp) {
        fprintf(stderr, "Error reservando memoria para el filtro: %s\n", filter);
        return -1;
    }
    series = (series_t *)tmp;

    if (series_mode == SERIES_NETS) {
        ret = DSTries_add_filter(&filterList, filter, i);
        series[i].filter = filterList->filter;
    } else
        ret = pcap_compile_nopcap(snaplen, linktype, &series[i].bpf, filter, 1, 0);
    if (ret) {
        fprintf(stderr, "Error procesando filtro: %s\n", filter);
        return -1;
    }

    series[i].intervalStartTime = -1;
    series[i].bytesInInterval = 0;
    series[i].packetsInInterval = 0;
    fprintf(stderr, "Filtro %i procesado: %s\n", i, filter);

    return 0;
}

// Se le pasa el instante de llegada de un paquete y su longitud a nivel fisico para que calcule la serie temporal
inline void series_compute(void *arg, int i) {
    seriesData_t *data = (seriesData_t *) arg;

    if ((data->endSeries)&&(series[i].bytesInInterval>0)&&(series[i].intervalStartTime>-1)) {
        fprintf(stdout, "%i %llu %llu %llu\n", i, series[i].intervalStartTime, series[i].bytesInInterval, series[i].packetsInInterval);
        return;
    }

    if (data->time == NULL) return;

    double  pktTime = data->time->tv_sec*1000.0+data->time->tv_usec/1000.0;

    if (series[i].intervalStartTime == -1) series[i].intervalStartTime = series_initTime;

    if (pktTime >= series[i].intervalStartTime + series_msecsPointInTimeSeries) {
        // Cambio de intervalo
        fprintf(stdout, "%i %llu %llu %llu\n", i, series[i].intervalStartTime, series[i].bytesInInterval, series[i].packetsInInterval);
        series[i].intervalStartTime += series_msecsPointInTimeSeries;

        while (pktTime > series[i].intervalStartTime + series_msecsPointInTimeSeries) {
            if (series_dumpZeros) fprintf(stdout, "%i %llu %llu %llu\n", i, series[i].intervalStartTime, 0LL, 0LL);
            series[i].intervalStartTime += series_msecsPointInTimeSeries;
        }

        series[i].bytesInInterval = data->bytes;
        series[i].packetsInInterval = 1;
    }
    else {
        series[i].bytesInInterval += data->bytes;
        series[i].packetsInInterval++;
    }
}

static inline int _filter(struct bpf_program *fp, const struct pcap_pkthdr *h, const u_char *pkt) {
    struct bpf_insn *fcode = fp->bf_insns;

    if (fcode != NULL) 
        return bpf_filter(fcode, (u_char*)pkt, h->len, h->caplen);
    else
        return 0;
}

inline void series_filter(const struct pcap_pkthdr *header, const u_char *bytes) {
    static seriesData_t data;
    data.time = &header->ts;
    data.bytes = header->len+4;

    if (series_mode == SERIES_BPF) {
        for (int i=0; i<num_series; i++) {
            if (_filter(&series[i].bpf, header, bytes)) {
                series_compute((void *)&data, i);
                if (series_breakAtFirstMatch) break;
            }
        }
    } else
        DSTries_filter(triesTree, (void *)header, bytes, series_unpack_addresses, series_compute, (void *)&data);
}
