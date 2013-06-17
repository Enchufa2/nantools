/*
 * eth.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "eth.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

char LLCSNAPHEADERSTART[6] = { 1, 1, 1, 0, 0, 0};

struct timeval eth_get_timestamp(ethFrame_t *frame) {
    struct timeval tstamp = {0,0};
    if (frame) return frame->timestamp;
    return tstamp;
}

int eth_get_type(ethFrame_t *frame) {
    unsigned short  ethertype;
    
    if (!frame) return ETH_FRAMETYPE_ERROR;
    if (!frame->bytes) return ETH_FRAMETYPE_ERROR;
    if (frame->caplen < 14) return ETH_FRAMETYPE_ERROR;
    
    ethertype = ntohs(*(unsigned short*)(frame->bytes+12));

    switch (ethertype) {
        case 0x8100: 
            frame->frameType = ETH_FRAMETYPE_8021Q;
            return ETH_FRAMETYPE_8021Q;
        case 0x88a8: 
            frame->frameType = ETH_FRAMETYPE_8021ad;
            return ETH_FRAMETYPE_8021ad;
        case 0x88e7: 
            frame->frameType = ETH_FRAMETYPE_8021ah;
            return ETH_FRAMETYPE_8021ah;
        default:
            if (ethertype>0x05DC) {
                frame->frameType = ETH_FRAMETYPE_DIX;
                return ETH_FRAMETYPE_DIX;
            }
            else {
                frame->frameType = ETH_FRAMETYPE_8023;
                return ETH_FRAMETYPE_8023;
            }
            // Faltan los formatos "raros"
    }
}

int eth_is_8021Q(ethFrame_t *frame) {
    if (!frame) return -1;
    if (frame->frameType == ETH_FRAMETYPE_NOTCHECKED)
        return (eth_get_type(frame) == ETH_FRAMETYPE_8021Q);
    else return (frame->frameType == ETH_FRAMETYPE_8021Q);
}

int eth_is_8021ad(ethFrame_t *frame) {
    if (!frame) return -1;
    if (frame->frameType == ETH_FRAMETYPE_NOTCHECKED)
        return (eth_get_type(frame) == ETH_FRAMETYPE_8021ad);
    else return (frame->frameType == ETH_FRAMETYPE_8021ad);
}

int eth_is_8021ah(ethFrame_t *frame) {
    if (!frame) return -1;
    if (frame->frameType == ETH_FRAMETYPE_NOTCHECKED)
        return (eth_get_type(frame) == ETH_FRAMETYPE_8021ah);
    else return (frame->frameType == ETH_FRAMETYPE_8021ah);
}

int eth_has_VLANID(ethFrame_t *frame) {
    int     frameType;
    
    if (!frame) return -1;
    frameType = frame->frameType;
    if (frameType == ETH_FRAMETYPE_NOTCHECKED) frameType = eth_get_type(frame);
    return ((frameType == ETH_FRAMETYPE_8021Q)||(frameType == ETH_FRAMETYPE_8021ad)||(frameType == ETH_FRAMETYPE_8021ah));
}

unsigned short eth_get_VLANID(ethFrame_t *frame) {
    int     frameType;
    
    if (!frame) return -1;
    frameType = frame->frameType;
    if (frameType == ETH_FRAMETYPE_NOTCHECKED) frameType = eth_get_type(frame);
    
    switch (frameType) {
        case ETH_FRAMETYPE_8021Q:
            if (frame->caplen < 16) return -1;
            return (*(unsigned short*)(frame->bytes+14))&0x0FFF;
        case ETH_FRAMETYPE_8021ad:
            if (frame->caplen < 20) return -1;
            return (*(unsigned short*)(frame->bytes+18))&0x0FFF;
        case ETH_FRAMETYPE_8021ah:
            if (frame->caplen < 38) return -1;
            return (*(unsigned short*)(frame->bytes+36))&0x0FFF;
    }
    
    return 0;
}

const char *eth_get_src(ethFrame_t *frame) {
    int     frameType;

    if (!frame) return NULL;
    frameType = frame->frameType;
    if (frameType == ETH_FRAMETYPE_NOTCHECKED) frameType = eth_get_type(frame);
    
    switch (frameType) {
        case ETH_FRAMETYPE_ERROR: return NULL;
        case ETH_FRAMETYPE_8021Q: return (frame->caplen >= 6)?frame->bytes + 6:NULL;
        case ETH_FRAMETYPE_8021ad: return (frame->caplen >= 6)?frame->bytes + 6:NULL;
        case ETH_FRAMETYPE_8021ah: return (frame->caplen >= 30)?frame->bytes + 24:NULL;
    }

    return frame->bytes+6;
}

const char *eth_get_dst(ethFrame_t *frame) {
    int     frameType;
    
    if (!frame) return NULL;
    frameType = frame->frameType;
    if (frameType == ETH_FRAMETYPE_NOTCHECKED) frameType = eth_get_type(frame);
    
    switch (frameType) {
        case ETH_FRAMETYPE_ERROR: return NULL;
        case ETH_FRAMETYPE_8021Q: return frame->bytes;
        case ETH_FRAMETYPE_8021ad: return frame->bytes;
        case ETH_FRAMETYPE_8021ah: return frame->bytes + 18;
    }
    
    return frame->bytes;
}

unsigned short eth_get_ethertype(ethFrame_t *frame) {
    int     frameType;
    
    if (!frame) return 0;
    frameType = frame->frameType;
    if (frameType == ETH_FRAMETYPE_NOTCHECKED) frameType = eth_get_type(frame);
    
    switch (frameType) {
        case ETH_FRAMETYPE_DIX: return ntohs(*(unsigned short*)(frame->bytes+12));
        case ETH_FRAMETYPE_8021Q: return ntohs(*(unsigned short*)(frame->bytes+16));
        case ETH_FRAMETYPE_8021ad: return ntohs(*(unsigned short*)(frame->bytes+20));
        case ETH_FRAMETYPE_8021ah: return ntohs(*(unsigned short*)(frame->bytes+38));
        case ETH_FRAMETYPE_8023:
            if (frame->caplen < 20) return 0;
            if (memcmp(frame->bytes+14, LLCSNAPHEADERSTART, 6)==0) return ntohs(*(unsigned short*)(frame->bytes+20));
    }
    
    return 0;
}

const char *eth_get_data(ethFrame_t *frame, int *newSize) {
    int     frameType;
    int     headerSize = 0;
    
    if (!frame) return NULL;
    frameType = frame->frameType;
    if (frameType == ETH_FRAMETYPE_NOTCHECKED) frameType = eth_get_type(frame);
    
    switch (frameType) {
        case ETH_FRAMETYPE_ERROR: return NULL;
        case ETH_FRAMETYPE_DIX: 
            headerSize = 14;
            break;
        case ETH_FRAMETYPE_8021Q: 
            headerSize = 18;
            break;
        case ETH_FRAMETYPE_8021ad: 
            headerSize = 22;
            break;
        case ETH_FRAMETYPE_8021ah: 
            headerSize = 40;
            break;
        case ETH_FRAMETYPE_8023: 
            headerSize = 14;
            break;
        default:
            if ((frame->caplen <= headerSize)||(headerSize == 0)) return NULL;
    }
    *newSize = frame->caplen - headerSize;
    return frame->bytes + headerSize;

}
