/*
 * pkt.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef PKT_H_
#define PKT_H_

#include "../common/eth.h"
#include "../common/ip.h"
#include "buffer.h"

#ifndef PKT_BYTES
#define PKT_BYTES 5000  /**< maximum packet size allowed */
#endif

/**
 * Packet statistics
 */
typedef struct {
    struct timeval      startTime;  /**< time of the first packet */
    struct timeval      endTime;    /**< time of the last packet */

    unsigned long long  numPkts;    /**< total number of packets */
    unsigned long long  numErrors;  /**< number of errors */
    unsigned long long  numIP;      /**< number of IP packets */
    unsigned long long  numTCP;     /**< number of TCP packets */
    unsigned long long  numUDP;     /**< number of UDP packets */
} pktStats_t;

typedef struct pkt pkt_t;
typedef struct dissector dissector_t;

/**
 * Packet dissector
 */
struct dissector {
    const char      *src;           /**< pointer to the source MAC */
    const char      *dst;           /**< pointer to the destination MAC */
    unsigned short  ethertype;      /**< ethertype */
    void            *data;          /**< pointer to the upper level data */
    int             bufSize;        /**< size of captured data */
    int             pktSize;        /**< real size of data */

    IPPacket_t      *ipPkt;         /**< pointer to the IP header */
    unsigned int    protocol;       /**< transport protocol */
    int             offset;         /**< IP offset */
    const char      *ipData;        /**< pointer to IP data */
    int             ipBufSize;      /**< size of captured IP data */
    int             ipPktSize;      /**< real size of IP data */

    void            *sgmt;          /**< pointer to the transport header */
    unsigned short  srcPort;        /**< source port */
    unsigned short  dstPort;        /**< destination port */
    const char      *sgmtData;      /**< pointer to transport level data */
    int             sgmtBufSize;    /**< size of captured transport data */
    int             sgmtPktSize;    /**< real size of transport data */
};

/**
 * Packet struct
 */
struct pkt {
    unsigned long long  pos;        /**< position */
    long double         time;       /**< decoded timestamp */
    ethFrame_t          *frame;     /**< pointer to ethernet header */
    dissector_t         dis;        /**< packet dissector */
    node_t              *container; /**< pointer to the container node */
};

// initializer
void pkt_init(int fast, pktStats_t *stats);

// constructors
ethFrame_t *pkt_new_ethFrame(ethFrame_t *frame, void *bytes, int size, int caplen, struct timeval *timestamp);
IPPacket_t *pkt_new_ipPkt(IPPacket_t *ipPkt, void *bytes, int caplen);
void *pkt_new_segment(void *sgmt, void *bytes, int size, int caplen);

// fill pkt_t
pkt_t *pkt_fill(node_t *node, unsigned long long pos, void *bytes, int size, int caplen, struct timeval *timestamp);

/**
 * @brief Dissects a packet
 *
 * @param pkt the packet
 * @return 0 on success, -1 on error
 */
extern int (*pkt_dissect)(pkt_t *pkt);

// copy the contents of pkt1 in pkt2 with (copyTs=1) or without (copyTs=0) changing the timestamp
int pkt_copy(pkt_t *src, pkt_t *dst, int copyTs);

// free all memory
void pkt_destroy();

// debugging
void pkt_print(void *load);

#endif /* PKT_H_ */
