/*
 * eth.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef ETH_H
#define ETH_H

#define ETH_PROTO_IPv4 0x0800

#include <sys/time.h>

// frame types
#define ETH_FRAMETYPE_ERROR 		-1
#define ETH_FRAMETYPE_NOTCHECKED	0
#define ETH_FRAMETYPE_8021Q 		1
#define ETH_FRAMETYPE_8021ad 		2
#define ETH_FRAMETYPE_8021ah 		3
#define ETH_FRAMETYPE_DIX   		4
#define ETH_FRAMETYPE_8023 			5
#define ETH_FRAMETYPE_MAXVALUE  	5

// frame
typedef struct {
    const char *bytes;       	// frame bytes
    int size;               	// real size, without CRC (> 60)
    int caplen;             	// captured size
    int frameType;          	// frame type (default: ETH_FRAMETYPE_NOTCHECKED)
    struct timeval timestamp;	// timestamp
} ethFrame_t;

struct timeval eth_get_timestamp(ethFrame_t *frame);

// get the frame type
int eth_get_type(ethFrame_t *frame);

// true, false (error: -1)
int eth_is_8021Q(ethFrame_t *frame);

// true, false (error: -1)
int eth_is_8021ad(ethFrame_t *frame);

// true, false (error: -1)
int eth_is_8021ah(ethFrame_t *frame);

// true, false (error: -1)
int eth_has_VLANID(ethFrame_t *frame);

// get the VLAN identifier (error: 0)
unsigned short eth_get_VLANID(ethFrame_t *frame);

// get a pointer to the source MAC
const char *eth_get_src(ethFrame_t *frame);

// get a pointer to the destination MAC
const char *eth_get_dst(ethFrame_t *frame);

// get the ethertype (error: 0)
unsigned short eth_get_ethertype(ethFrame_t *frame);

// get ethernet payload and its captured size
const char *eth_get_data(ethFrame_t *frame, int *newSize);

#endif /* ETH_H_ */
