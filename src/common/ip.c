/*
 * ip.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "ip.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int ip_is_header_complete(IPPacket_t *pkt) {
    if (!pkt) return 0;
    if (pkt->caplen < 20) return 0;
    int ihl = pkt->bytes->version_HeaderLength&0x0F;
    if (4*ihl > pkt->caplen) return 0;
    return 1;
}

int ip_is_basic_header_complete(IPPacket_t *pkt) {
    if (!pkt) return 0;
    if (pkt->caplen < 20) return 0;
    return 1;
}

char *ip_get_src_txt(IPPacket_t *pkt) {
    if (pkt->caplen < 16) return NULL;
    return inet_ntoa(*(struct in_addr*)&pkt->bytes->srcAddr);
}

char *ip_get_dst_txt(IPPacket_t *pkt) {
    if (!ip_is_basic_header_complete(pkt)) return NULL;
    return inet_ntoa(*(struct in_addr*)&pkt->bytes->dstAddr);
}

int ip_get_src(IPPacket_t *pkt) {
    if (pkt->caplen < 16) return -1;
    return pkt->bytes->srcAddr;
}

int ip_get_dst(IPPacket_t *pkt) {
    if (pkt->caplen < 20) return -1;
    return pkt->bytes->dstAddr;
}

int ip_get_proto(IPPacket_t *pkt) {
    if (pkt->caplen < 10) return -1;
    return pkt->bytes->protocol;
}

int ip_get_length(IPPacket_t *pkt) {
    if (pkt->caplen < 4) return -1;
    return ntohs(pkt->bytes->totalLength);
}

int ip_get_offset(IPPacket_t *pkt) {
    if (pkt->caplen < 8) return -1;
    return ntohs(pkt->bytes->flags_Offset&htons(0x1FFF))*8;
}

int ip_get_TTL(IPPacket_t *pkt) {
    if (pkt->caplen < 9) return -1;
    return pkt->bytes->ttl;
}


char ip_get_flags(IPPacket_t *pkt) {
    if (!pkt) return -1;
    return (pkt->bytes->flags_Offset&0xE0)>>5;
}

char ip_get_MF(IPPacket_t *pkt) {
    if (!pkt) return -1;
    return (pkt->bytes->flags_Offset&0x20)>>5;  
}

const char *ip_get_data(IPPacket_t *pkt, int *newSize, int *ipDataLength) {
    if (!pkt) return NULL;
    
    if (pkt->caplen < 4) { // No se puede calcular la longitud de los datos asi que se devuelve NULL y longitudes a -1 para marcar que no es que no hubiera sino que ni se sabe los que habia
        *newSize = *ipDataLength = -1;
        return NULL;
    }
    
    unsigned char   headerLength = pkt->bytes->version_HeaderLength & 0x0F;
    unsigned short  totalLength = ntohs(pkt->bytes->totalLength);
    
    *ipDataLength = totalLength-headerLength*4;

    if (pkt->caplen <= headerLength*4) {
        *newSize = 0;
        return NULL;
    }
    
    *newSize = (pkt->caplen-headerLength*4 < *ipDataLength)?(pkt->caplen-headerLength*4):*ipDataLength;
    
    return (const char*)(((char*)pkt->bytes)+headerLength*4);
}

int ip_is_fragment(IPPacket_t *pkt) {
    if (!pkt) return -1;
    if (pkt->caplen < 8) return -1;
    
    unsigned char   flags = ((unsigned char*)pkt->bytes)[6];
    return ((flags&0x20)==0x20)||(pkt->bytes->flags_Offset&htons(0x1FFF));
}

int ip_is_first_fragment(IPPacket_t *pkt) {
    if (!pkt) return -1;
    if (pkt->caplen < 8) return -1;

    return ((pkt->bytes->flags_Offset&ntohs(0x1FFF))==0);
}
