/*
 * dups.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "dups.h"
#include "../common/ip.h"
#include "../common/tcp.h"
#include "../common/udp.h"
#include "../common/utils.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// private variables
static int dups_window_mode = 0;            /**< window mode (0=time, 1=pos) */
static float dups_window_time = 0.1;        /**< window size in seconds */
static unsigned int dups_window_pos = 0;    /**< window size in positions */

static int dups_extended;                   /**< extended output flag */
static int dups_suspicious;                 /**< suspcious duplicates flag */

static stats_t *dups_stats;                 /**< statistics */
static pthread_mutex_t dups_mutex;          /**< statistics mutex */

dup_t DUPS_TYPE[DUPS_COMPARATORS] = {
    {.description = "Switching",                        .comparator = NULL},
    {.description = "Routing",                          .comparator = NULL},
    {.description = "NAT Routing",                      .comparator = NULL},
    {.description = "Proxying",                         .comparator = NULL},
    {.description = "Routing with fragmentation",       .comparator = NULL},
    {.description = "NAT Routing with fragmentation",   .comparator = NULL}
};

/**
 * @brief Compares source and destination MACs of two packets
 *
 * @param cur one packet
 * @param pkt another packet
 * @return
 * - 2 if src1=src2 & dst1=dst2
 * - 1 if src1=src2 ^ dst1=dst2
 * - 0 if src1!=src2 & dst1!=dst2
 */
static inline int compareMacs(pkt_t *cur, pkt_t *pkt) {
    int src = memcmp(cur->dis.src, pkt->dis.src, 6);
    int dst = memcmp(cur->dis.dst, pkt->dis.dst, 6);

    if (!src && !dst)
        return 2;
    else if (src && dst)
        return 0;
    else
        return 1;
}

/**
 * @brief Compares two buffers
 *
 * @param data1 first buffer
 * @param size1 size of the first buffer
 * @param data2 second buffer
 * @param size2 size of the second buffer
 * @return
 * - 0 if not equal
 * - 1 if equal
 * - -1 if NULL buffers
 */
static inline int sameData(void *data1, size_t size1, void *data2, size_t size2) {
    if (size1 != size2) return 0;
    //if (size1 <= 0) return -1;
    if (data1 == NULL || data2 == NULL) return -1;
    if (memcmp(data1, data2, size1)) return 0;
    return 1;
}

/**
 * @brief Searches for a fragment inside a buffer
 *
 * @param data      the buffer
 * @param size      size of the buffer
 * @param dataFrag  fragment of data
 * @param sizeFrag  size of the fragment
 * @param offset    fragment offset
 * @return
 * - 0 if not present
 * - 1 if present
 */
static inline int fragmentInData(void *data, size_t size, void *dataFrag, size_t sizeFrag, size_t offset) {
    if (size < offset+sizeFrag) return 0;
    if (data != NULL && dataFrag != NULL)
        if (memcmp((char *)(data)+offset, dataFrag, sizeFrag)) return 0;
    return 1;
}

/**
 * @brief Switching comparator
 *
 * @param cur         one packet
 * @param pkt         another packet
 * @param dataCmp     output from sameData()
 * @return            1 (TRUE) or 0 (FALSE)
 */
static inline int comparator_0(pkt_t *cur, pkt_t *pkt, int dataCmp) {
    // is IP?
    if (cur->dis.ethertype == ETH_PROTO_IPv4) {
        // compare IP ID
        if (cur->dis.ipPkt->bytes->identification != pkt->dis.ipPkt->bytes->identification) return 0;
        // compare protocol
        if (cur->dis.protocol != pkt->dis.protocol) return 0;
        // compare TCP/UDP fields
        if (cur->dis.protocol == IP_PROTO_TCP || cur->dis.protocol == IP_PROTO_UDP) {
            if (cur->dis.srcPort != pkt->dis.srcPort || cur->dis.dstPort != pkt->dis.dstPort) return 0;
            if (cur->dis.protocol == IP_PROTO_TCP) {
                if (cur->dis.ipPkt->bytes->totalLength != pkt->dis.ipPkt->bytes->totalLength) return 0;
                if (((TCPSegment_t *)cur->dis.sgmt)->bytes->checksum != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->checksum) return 0;
                if (((TCPSegment_t *)cur->dis.sgmt)->bytes->seqNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->seqNumber) return 0;
                if (((TCPSegment_t *)cur->dis.sgmt)->bytes->ackNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->ackNumber) return 0;
                if (((TCPSegment_t *)cur->dis.sgmt)->bytes->window != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->window) return 0;
            }
        }
        // compare IP addresses
        if (cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr || cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr) return 0;
        // compare TTL
        if ((u_int)cur->dis.ipPkt->bytes->ttl != (u_int)pkt->dis.ipPkt->bytes->ttl) return 0;
        // compare offset
        if (cur->dis.offset != pkt->dis.offset) return 0;
    }
    return 1;
}

/**
 * @brief Routing comparator
 *
 * @param cur         one packet
 * @param pkt         another packet
 * @param dataCmp     output from sameData()
 * @return            1 (TRUE) or 0 (FALSE)
 */
static inline int comparator_1(pkt_t *cur, pkt_t *pkt, int dataCmp) {
    // compare TCP/UDP fields
    if (cur->dis.protocol == IP_PROTO_TCP || cur->dis.protocol == IP_PROTO_UDP) {
        if (cur->dis.srcPort != pkt->dis.srcPort || cur->dis.dstPort != pkt->dis.dstPort) return 0;
        if (cur->dis.protocol == IP_PROTO_TCP) {
            if (cur->dis.ipPkt->bytes->totalLength != pkt->dis.ipPkt->bytes->totalLength) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->seqNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->seqNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->ackNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->ackNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->window != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->window) return 0;
        }
    }
    // compare IP addresses
    if (cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr || cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr) return 0;
    // compare TTL
    //if ((u_int)cur->dis.ipPkt->bytes->ttl < (u_int)pkt->dis.ipPkt->bytes->ttl) return 0;
    // compare offset
    if (cur->dis.offset != pkt->dis.offset) return 0;
    return 1;
}

/**
 * @brief NAT Routing comparator
 *
 * @param cur         one packet
 * @param pkt         another packet
 * @param dataCmp     output from sameData()
 * @return            1 (TRUE) or 0 (FALSE)
 */
static inline int comparator_2(pkt_t *cur, pkt_t *pkt, int dataCmp) {
    // compare TCP/UDP fields
    if (cur->dis.protocol == IP_PROTO_TCP || cur->dis.protocol == IP_PROTO_UDP) {
        if ((cur->dis.srcPort == pkt->dis.srcPort && cur->dis.dstPort == pkt->dis.dstPort) ||
            (cur->dis.srcPort != pkt->dis.srcPort && cur->dis.dstPort != pkt->dis.dstPort)) return 0;
        // port and IP matching
        if ((cur->dis.srcPort == pkt->dis.srcPort && cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr) ||
            (cur->dis.dstPort == pkt->dis.dstPort && cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr)) return 0;
        if (cur->dis.protocol == IP_PROTO_TCP) {
            if (cur->dis.ipPkt->bytes->totalLength != pkt->dis.ipPkt->bytes->totalLength) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->seqNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->seqNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->ackNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->ackNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->window != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->window) return 0;
        }
    } else {
        // compare IP addresses
        if ((cur->dis.ipPkt->bytes->srcAddr == pkt->dis.ipPkt->bytes->srcAddr && cur->dis.ipPkt->bytes->dstAddr == pkt->dis.ipPkt->bytes->dstAddr) ||
            (cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr && cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr)) return 0;
    }
    // compare offset
    if (cur->dis.offset != pkt->dis.offset) return 0;
    return 1;
}

/**
 * @brief Proxying comparator
 *
 * @param cur         one packet
 * @param pkt         another packet
 * @param dataCmp     output from sameData()
 * @return            1 (TRUE) or 0 (FALSE)
 */
static inline int comparator_3(pkt_t *cur, pkt_t *pkt, int dataCmp) {
    // compare TCP/UDP fields
    if (cur->dis.protocol == IP_PROTO_TCP || cur->dis.protocol == IP_PROTO_UDP) {
        if (cur->dis.srcPort != pkt->dis.srcPort || cur->dis.dstPort != pkt->dis.dstPort) return 0;
        if (cur->dis.protocol == IP_PROTO_TCP) {
            if (cur->dis.ipPkt->bytes->totalLength != pkt->dis.ipPkt->bytes->totalLength) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->seqNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->seqNumber &&
                ((TCPSegment_t *)cur->dis.sgmt)->bytes->ackNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->ackNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->window != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->window) return 0;
        }
    }
    // compare IP addresses
    if ((cur->dis.ipPkt->bytes->srcAddr == pkt->dis.ipPkt->bytes->srcAddr && cur->dis.ipPkt->bytes->dstAddr == pkt->dis.ipPkt->bytes->dstAddr) ||
        (cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr && cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr)) return 0;
    // compare offset
    if (cur->dis.offset != pkt->dis.offset) return 0;
    return 1;
}

/**
 * @brief Routing (with fragmentation) comparator
 *
 * @param cur         one packet
 * @param pkt         another packet
 * @param dataCmp     output from sameData()
 * @return            1 (TRUE) or 0 (FALSE)
 */
static inline int comparator_4(pkt_t *cur, pkt_t *pkt, int dataCmp) {
    // compare TCP/UDP fields
    if ((cur->dis.protocol == IP_PROTO_TCP || cur->dis.protocol == IP_PROTO_UDP) && ip_is_first_fragment(pkt->dis.ipPkt)) {
        if (cur->dis.srcPort != pkt->dis.srcPort || cur->dis.dstPort != pkt->dis.dstPort) return 0;
        if (cur->dis.protocol == IP_PROTO_TCP) {
            if (cur->dis.ipPkt->bytes->totalLength != pkt->dis.ipPkt->bytes->totalLength) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->seqNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->seqNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->ackNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->ackNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->window != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->window) return 0;
        }
    }
    // compare IP addresses
    if (cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr || cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr) return 0;
    return 1;
}

/**
 * @brief NAT Routing (with fragmentation) comparator
 *
 * @param cur         one packet
 * @param pkt         another packet
 * @param dataCmp     output from sameData()
 * @return            1 (TRUE) or 0 (FALSE)
 */
static inline int comparator_5(pkt_t *cur, pkt_t *pkt, int dataCmp) {
    // compare TCP/UDP fields
    if ((cur->dis.protocol == IP_PROTO_TCP || cur->dis.protocol == IP_PROTO_UDP) && ip_is_first_fragment(pkt->dis.ipPkt)) {
        if ((cur->dis.srcPort == pkt->dis.srcPort && cur->dis.dstPort == pkt->dis.dstPort) ||
            (cur->dis.srcPort != pkt->dis.srcPort && cur->dis.dstPort != pkt->dis.dstPort)) return 0;
        // port and IP matching
        if ((cur->dis.srcPort == pkt->dis.srcPort && cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr) ||
            (cur->dis.dstPort == pkt->dis.dstPort && cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr)) return 0;
        if (cur->dis.protocol == IP_PROTO_TCP) {
            if (cur->dis.ipPkt->bytes->totalLength != pkt->dis.ipPkt->bytes->totalLength) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->seqNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->seqNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->ackNumber != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->ackNumber) return 0;
            if (((TCPSegment_t *)cur->dis.sgmt)->bytes->window != ((TCPSegment_t *)pkt->dis.sgmt)->bytes->window) return 0;
        }
    } else {
        // compare IP addresses
        if ((cur->dis.ipPkt->bytes->srcAddr == pkt->dis.ipPkt->bytes->srcAddr && cur->dis.ipPkt->bytes->dstAddr == pkt->dis.ipPkt->bytes->dstAddr) ||
            (cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr && cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr)) return 0;
    }
    return 1;
}

/**
 * @brief Checks if there is a VLAN tag change
 *
 * @param cur   one packet
 * @param pkt   another packet
 * @return      1 (TRUE) or 0 (FALSE)
 */
static inline int VLANchange(pkt_t *cur, pkt_t *pkt) {
    if (eth_get_VLANID(cur->frame) == eth_get_VLANID(pkt->frame))
        return 0;
    return 1;
}

/**
 * @brief Checks if there is a DSCP tag change
 *
 * @param cur   one packet
 * @param pkt   another packet
 * @return      1 (TRUE) or 0 (FALSE)
 */
static inline int DSCPchange(pkt_t *cur, pkt_t *pkt) {
    if (!(cur->dis.ethertype == ETH_PROTO_IPv4 && pkt->dis.ethertype == ETH_PROTO_IPv4)) return 0;
    if (cur->dis.ipPkt->bytes->dscpEcn == pkt->dis.ipPkt->bytes->dscpEcn) return 0;
    return 1;
}

/**
 * @brief Output formatter
 *
 * @param stream    output stream
 * @param cur       first packet
 * @param pkt       second packet (duplicate)
 * @param type      type of duplicate
 * @param dataCmp   output from sameData()
 * @return          number of characters printed
 */
static inline int dups_fprintf(FILE *stream, pkt_t *cur, pkt_t *pkt, int type, int dataCmp) {
    int count = 0;

    char macSrc2[20], macDst2[20], macSrc1[20], macDst1[20];
    char ipSrc1[INET_ADDRSTRLEN], ipSrc2[INET_ADDRSTRLEN], ipDst1[INET_ADDRSTRLEN], ipDst2[INET_ADDRSTRLEN];
    int ttl1=0, ttl2=0;

    if (cur->dis.ethertype == ETH_PROTO_IPv4 && pkt->dis.ethertype == ETH_PROTO_IPv4) {
        ttl1 = (u_int)cur->dis.ipPkt->bytes->ttl;
        ttl2 = (u_int)pkt->dis.ipPkt->bytes->ttl;
    }
    count += fprintf(stream, "%llu %llu %i %i %i %i %.9Lf %i",
        pkt->pos,
        pkt->pos - cur->pos,
        type,
        (dataCmp == -1) ? 1 : 0,
        VLANchange(cur, pkt),
        DSCPchange(cur, pkt),
        pkt->time - cur->time,
        ttl1-ttl2
    );


    if (dups_extended) {
        utils_mac2txt(pkt->dis.src, macSrc2);
        utils_mac2txt(pkt->dis.dst, macDst2);
        count += fprintf(stream, " %.9Lf %i %s > %s", pkt->time, ttl2, macSrc2, macDst2);
        if (pkt->dis.ethertype == ETH_PROTO_IPv4) {
            inet_ntop(AF_INET, &pkt->dis.ipPkt->bytes->srcAddr, ipSrc2, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &pkt->dis.ipPkt->bytes->dstAddr, ipDst2, INET_ADDRSTRLEN);
            count += fprintf(stream, " %s > %s", ipSrc2, ipDst2);
        }
        if (type) {
            utils_mac2txt(cur->dis.src, macSrc1);
            utils_mac2txt(cur->dis.dst, macDst1);
            count += fprintf(stream, " | %s > %s", macSrc1, macDst1);
            if (type == -1 || type == 2 || type == 3 || type == 5) {
                if (cur->dis.ethertype == ETH_PROTO_IPv4) {
                    inet_ntop(AF_INET, &cur->dis.ipPkt->bytes->srcAddr, ipSrc1, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &cur->dis.ipPkt->bytes->dstAddr, ipDst1, INET_ADDRSTRLEN);
                    count += fprintf(stream, " %s > %s", ipSrc1, ipDst1);
                }
            }
        }
    }

    count += fprintf(stream, "\n");

    return count;
}

/**
 * @brief Output formatter
 *
 * @param stream    output string
 * @param cur       first packet
 * @param pkt       second packet (duplicate)
 * @param type      type of duplicate
 * @param dataCmp   output from sameData()
 * @return          number of characters printed
 */
static inline int dups_sprintf(char *stream, pkt_t *cur, pkt_t *pkt, int type, int dataCmp) {
    int count = 0;

    char macSrc2[20], macDst2[20], macSrc1[20], macDst1[20];
    char ipSrc1[INET_ADDRSTRLEN], ipSrc2[INET_ADDRSTRLEN], ipDst1[INET_ADDRSTRLEN], ipDst2[INET_ADDRSTRLEN];
    int ttl1=0, ttl2=0;

    if (cur->dis.ethertype == ETH_PROTO_IPv4 && pkt->dis.ethertype == ETH_PROTO_IPv4) {
        ttl1 = (u_int)cur->dis.ipPkt->bytes->ttl;
        ttl2 = (u_int)pkt->dis.ipPkt->bytes->ttl;
    }
    count += sprintf(stream+count, "%llu %llu %i %i %i %i %.9Lf %i",
        pkt->pos,
        pkt->pos - cur->pos,
        type,
        (dataCmp == -1) ? 1 : 0,
        VLANchange(cur, pkt),
        DSCPchange(cur, pkt),
        pkt->time - cur->time,
        ttl1-ttl2
    );


    if (dups_extended) {
        utils_mac2txt(pkt->dis.src, macSrc2);
        utils_mac2txt(pkt->dis.dst, macDst2);
        count += sprintf(stream+count, " %.9Lf %i %s > %s", pkt->time, ttl2, macSrc2, macDst2);
        if (pkt->dis.ethertype == ETH_PROTO_IPv4) {
            inet_ntop(AF_INET, &pkt->dis.ipPkt->bytes->srcAddr, ipSrc2, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &pkt->dis.ipPkt->bytes->dstAddr, ipDst2, INET_ADDRSTRLEN);
            count += sprintf(stream+count, " %s > %s", ipSrc2, ipDst2);
        }
        if (type) {
            utils_mac2txt(cur->dis.src, macSrc1);
            utils_mac2txt(cur->dis.dst, macDst1);
            count += sprintf(stream+count, " | %s > %s", macSrc1, macDst1);
            if (type == -1 || type == 2 || type == 3 || type == 5) {
                if (cur->dis.ethertype == ETH_PROTO_IPv4) {
                    inet_ntop(AF_INET, &cur->dis.ipPkt->bytes->srcAddr, ipSrc1, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &cur->dis.ipPkt->bytes->dstAddr, ipDst1, INET_ADDRSTRLEN);
                    count += sprintf(stream+count, " %s > %s", ipSrc1, ipDst1);
                }
            }
        }
    }

    count += sprintf(stream+count, "\n");

    return count;
}

/**
 * @brief Checks if a packet verifies the window limit
 *
 * @param pkt   reference
 * @param cur   the packet
 * @return      1 (TRUE) or 0 (FALSE)
 */
static inline int in_window(pkt_t *pkt, pkt_t *cur) {
    switch (dups_window_mode) {
    case 0:
        if (dups_window_time < pkt->time - cur->time) return 0;
        break;
    case 1:
        if (dups_window_pos-1 < pkt->pos - cur->pos) return 0;
        break;
    }
    return 1;
}

// Normal mode
static inline int _dups_search(node_t *node, unsigned int id, char *output, int *bufSize) {
    UTILS_CHECK(!node || !node->load, EINVAL, return -1);
    UTILS_CHECK(((pkt_t *)node->load)->frame->caplen <= 13, ENODATA, return -1);

    if (bufSize) *bufSize = 0;
    pkt_t *cur, *pkt = (pkt_t *)node->load;
    node_t *marker = buffer_get_marker(node->buffer, id);
    node_t *last = node;
    node = node->prev;
    int type, dataCmp=0, fragCmp=0, macsCmp, dupe=0;

    while (node && (marker != last)) {
        cur = (pkt_t *)node->load;
        if (!in_window(pkt, cur)) break;

        type = 0;
        dataCmp = sameData(cur->dis.data, cur->dis.bufSize, pkt->dis.data, pkt->dis.bufSize);

        // payload match or null payload
        if (dataCmp) {
            if (cur->dis.ethertype == pkt->dis.ethertype) {
                macsCmp = compareMacs(cur, pkt);
                // switching
                if (macsCmp == 2) {
                    if (DUPS_TYPE[type].comparator)
                        if (DUPS_TYPE[type].comparator(cur, pkt, dataCmp)) dupe = 1;
                // routing
                } else if (macsCmp == 0 && cur->dis.ethertype == ETH_PROTO_IPv4) {
                    // check IP ID
                    if (cur->dis.ipPkt->bytes->identification == pkt->dis.ipPkt->bytes->identification && cur->dis.protocol == pkt->dis.protocol) {
                        for (type=1; type<4; type++) {
                            if (DUPS_TYPE[type].comparator)
                                if (DUPS_TYPE[type].comparator(cur, pkt, dataCmp)) {
                                    dupe = 1;
                                    break;
                                }
                        }
                    }
                }
            }
        // fragmentation
        } else {
            if (cur->dis.ethertype == ETH_PROTO_IPv4 && pkt->dis.ethertype == ETH_PROTO_IPv4 && ip_is_fragment(pkt->dis.ipPkt)) {
                if (pkt->dis.offset) fragCmp = fragmentInData((void *)cur->dis.ipData, cur->dis.ipBufSize, (void *)pkt->dis.ipData, pkt->dis.ipBufSize, pkt->dis.offset);
                else fragCmp = fragmentInData(cur->dis.data, cur->dis.bufSize, pkt->dis.data, pkt->dis.bufSize, 0);
                if (fragCmp) {
                    macsCmp = compareMacs(cur, pkt);
                    // routing + check IP ID
                    if (macsCmp == 0 && cur->dis.ipPkt->bytes->identification == pkt->dis.ipPkt->bytes->identification) {
                        for (type=4; type<DUPS_COMPARATORS; type++) {
                            if (DUPS_TYPE[type].comparator)
                                if (DUPS_TYPE[type].comparator(cur, pkt, fragCmp)) {
                                    dupe = 1;
                                    break;
                                }
                        }
                    }
                }
            }
        }

        // suspicious, type = -1
        if (dataCmp == 1 && !dupe) {
            pthread_mutex_lock(&dups_mutex);
            dups_stats->numSuspicious++;
            pthread_mutex_unlock(&dups_mutex);
            if (dups_suspicious) {
                if (!output) dups_fprintf(stdout, cur, pkt, -1, dataCmp);
                else *bufSize = dups_sprintf(output, cur, pkt, -1, dataCmp);
            }
        }

        // duplicate found!
        if (dupe) {
            pthread_mutex_lock(&dups_mutex);
            dups_stats->numDup[type]++;
            pthread_mutex_unlock(&dups_mutex);
            if (!output) dups_fprintf(stdout, cur, pkt, type, dataCmp);
            else *bufSize = dups_sprintf(output, cur, pkt, type, dataCmp);
            if (fragCmp) pkt_copy(cur, pkt, 0);
            break;
        }

        // continue
        last = node;
        node = node->prev;
    }

    // update end-of-window marker
    if (!dupe && node && (marker != last))
        buffer_set_marker(last, id);

    return dupe;
}

/**
 * @brief Fast mode comparator (only IPv4 duplicates)
 *
 * @param cur   one packet
 * @param pkt   another packet
 * @return      1 (TRUE) or 0 (FALSE)
 */
static inline int comparator_fast(pkt_t *cur, pkt_t *pkt) {
    if (cur->dis.ipPkt->bytes->identification != pkt->dis.ipPkt->bytes->identification) return 0;
    if (cur->dis.ipPkt->bytes->totalLength != pkt->dis.ipPkt->bytes->totalLength) return 0;
    if (cur->dis.ipPkt->bytes->srcAddr != pkt->dis.ipPkt->bytes->srcAddr || cur->dis.ipPkt->bytes->dstAddr != pkt->dis.ipPkt->bytes->dstAddr) return 0;
    if (cur->dis.protocol != pkt->dis.protocol) return 0;
    if (cur->dis.offset != pkt->dis.offset) return 0;
    return !memcmp(cur->dis.data, pkt->dis.data, MIN(cur->dis.bufSize, 20));
}

// Fast mode
static inline int _dups_search_fast(node_t *node, unsigned int id, char *output, int *bufSize) {
    UTILS_CHECK(!node || !node->load, EINVAL, return -1);
    UTILS_CHECK(((pkt_t *)node->load)->frame->caplen <= 13, ENODATA, return -1);

    if (bufSize) *bufSize = 0;
    pkt_t *cur, *pkt = (pkt_t *)node->load;
    node_t *marker = buffer_get_marker(node->buffer, id);
    node_t *last = node;
    node = node->prev;

    if (pkt->dis.ethertype != ETH_PROTO_IPv4) return 0;
    int dupe=0, type=0;

    while (node && (marker != last)) {
        cur = (pkt_t *)node->load;
        if (!in_window(pkt, cur)) break;

        if (cur->dis.ethertype == ETH_PROTO_IPv4) {
            dupe = comparator_fast(cur, pkt);
            // match
            if (dupe) {
                if (compareMacs(cur, pkt) != 2) type = 1;
                pthread_mutex_lock(&dups_mutex);
                dups_stats->numDup[type]++;
                pthread_mutex_unlock(&dups_mutex);
                if (!output) dups_fprintf(stdout, cur, pkt, type, 0);
                else *bufSize = dups_sprintf(output, cur, pkt, type, 0);
                break;
            }
        }

        // continue
        last = node;
        node = node->prev;
    }

    // update end-of-window marker
    if (!dupe && node && (marker != last))
        buffer_set_marker(last, id);

    return dupe;
}

/**
 * @brief Initializes the library
 *
 * @param dupMask           disables comparators
 * - bit 0 disables comparator_0() (switching)
 * - bit 1 disables comparator_1() (routing)
 * - ...
 * @param fast              fast mode flag (!=0 to enable)
 * @param mode              window mode flag
 * - 0 time limited
 * - 1 position limited
 * @param value             string with a new window limit (in seconds or positions)
 * @param extendedOutput    extended output flag (!=0 to enable)
 * @param suspicious        suspicious flag (!=0 to enable)
 * @param stats             pointer to stats_t struct
 */
void dups_init(unsigned int dupMask, int fast, int mode, char *value, int extendedOutput, int suspicious, stats_t *stats) {
    if (!(dupMask & 0x0001)) DUPS_TYPE[0].comparator = comparator_0;
    if (!(dupMask & 0x0002)) DUPS_TYPE[1].comparator = comparator_1;
    if (!(dupMask & 0x0004)) DUPS_TYPE[2].comparator = comparator_2;
    if (!(dupMask & 0x0008)) DUPS_TYPE[3].comparator = comparator_3;
    if (!(dupMask & 0x0010)) DUPS_TYPE[4].comparator = comparator_4;
    if (!(dupMask & 0x0020)) DUPS_TYPE[5].comparator = comparator_5;

    if (!fast) dups_search = _dups_search;
    else dups_search = _dups_search_fast;

    dups_extended = extendedOutput;
    dups_suspicious = suspicious;
    dups_stats = stats;
    pthread_mutex_init(&dups_mutex, NULL);

    float aux0; int aux1;
    if (value) {
        dups_window_mode = mode;
        switch (mode) {
        case 0:
            aux0 = atof(value);
            if (aux0 > 0) dups_window_time = aux0;
            break;
        case 1:
            aux1 = atoi(value);
            if (aux1 > 0) dups_window_pos = aux1;
            else dups_window_mode = 0;
            break;
        default:
            dups_window_mode = 0;
            break;
        }
    }
}

/**
 * @brief Cleaner
 */
void dups_destroy() {
    pthread_mutex_destroy(&dups_mutex);
}
