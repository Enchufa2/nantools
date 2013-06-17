/*
 * udp.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "udp.h"
#include <stdlib.h>
#include <arpa/inet.h>

int udp_get_src(UDPDatagram_t *datagrama) {
    if (!datagrama) return -1;
    if (datagrama->caplen < 2) return -1;
    return ntohs(datagrama->bytes->srcPort);
}

int udp_get_dst(UDPDatagram_t *datagrama) {
    if (!datagrama) return -1;
    if (datagrama->caplen < 4) return -1;
    return ntohs(datagrama->bytes->dstPort);
}

const char *udp_get_data(UDPDatagram_t *datagrama, int *newSize, int *udpDataLength) {
    if (!datagrama) return NULL;
    
    if (datagrama->caplen < 6) return NULL; // No llega hasta el campo de longitud
    
    unsigned char   headerLength = 8;

    if (datagrama->caplen < headerLength) return NULL;
    
    *udpDataLength = datagrama->size - headerLength;
    *newSize = datagrama->caplen - headerLength;
    
    if ((*newSize<=0)||(*udpDataLength<=0)) return NULL;
    return (const char*)(((char*)datagrama->bytes)+headerLength);
}
