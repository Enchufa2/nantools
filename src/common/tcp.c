/*
 * tcp.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "tcp.h"
#include <stdlib.h>
#include <arpa/inet.h>

int tcp_get_src(TCPSegment_t *sgmt) {
    if (!sgmt) return -1;
    if (sgmt->caplen < 2) return -1;
    return ntohs(sgmt->bytes->srcPort);
}

int tcp_get_dst(TCPSegment_t *sgmt) {
    if (!sgmt) return -1;
    if (sgmt->caplen < 4) return -1;
    return ntohs(sgmt->bytes->dstPort);
}

int tcp_get_seq(TCPSegment_t *sgmt) {
    if (!sgmt) return -1;
    if (sgmt->caplen < 8) return -1;
    return ntohl(sgmt->bytes->seqNumber);
}

int tcp_get_ack(TCPSegment_t *sgmt) {
    if (!sgmt) return -1;
    if (sgmt->caplen < 12) return -1;
    return ntohl(sgmt->bytes->ackNumber);
}

int tcp_get_window(TCPSegment_t *sgmt) {
    if (!sgmt) return -1;
    if (sgmt->caplen < 16) return -1;
    return ntohs(sgmt->bytes->window);
}

const char *tcp_get_data(TCPSegment_t *sgmt, int *newSize, int *tcpDataLength) {
    if (newSize) *newSize = 0;
    if (tcpDataLength) *tcpDataLength = 0;
    if (!sgmt) return NULL;
    
    if (sgmt->caplen < 13) return NULL; // No llega hasta el campo de longitud
    
    unsigned char   headerLength = ((sgmt->bytes->dataOffset_Reserved >> 4)&0x0F)*4;

    if (sgmt->caplen < headerLength) return NULL;
    
    if (tcpDataLength) {
        *tcpDataLength = sgmt->size - headerLength;
        if (*tcpDataLength<=0) return NULL;
    }
    if (newSize) {
        *newSize = sgmt->caplen - headerLength;
        if (*newSize<=0) return NULL;
    }
    
    return (const char*)(((char*)sgmt->bytes)+headerLength);
}
