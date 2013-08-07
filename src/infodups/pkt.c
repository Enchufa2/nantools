/*
 * pkt.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include "pkt.h"
#include "../common/tcp.h"
#include "../common/udp.h"
#include "../common/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <obstack.h>

#define obstack_chunk_alloc malloc
#define obstack_chunk_free free

// private
static struct obstack pkt_obstack;	/**< obstack that stores packets */
static pktStats_t *pkt_stats;		/**< pointer to packet statistics */

/**
 * @brief Ethernet frame constructor
 *
 * This function fills a given frame or allocates a new one if NULL pointer is passed.
 *
 * @param frame		frame to fill or NULL
 * @param bytes		pointer to the new data (the data will be copied)
 * @param size		real size of data
 * @param caplen	size of captured data
 * @param timestamp	timestamp
 * @return a pointer to the frame or NULL
 */
inline ethFrame_t *pkt_new_ethFrame(ethFrame_t *frame, void *bytes, int size, int caplen, struct timeval *timestamp) {
    unsigned int flag = 0;
	if (!frame) flag = 1;
    if (flag) frame = obstack_alloc(&pkt_obstack, sizeof(ethFrame_t));

    // init
    if (frame) {
    	if (caplen > PKT_BYTES) caplen = PKT_BYTES;
    	if (flag) frame->bytes = obstack_alloc(&pkt_obstack, PKT_BYTES);
    	memcpy((void *)frame->bytes, bytes, caplen);
        frame->size = size;
        frame->caplen = caplen;
        frame->frameType = ETH_FRAMETYPE_NOTCHECKED;
        frame->timestamp = *timestamp;
    } else
    	perror("Error: pkt_new_ethFrame > obstack_alloc");

    return frame;
}

/**
 * @brief IP packet constructor
 *
 * This function fills a given packet or allocates a new one if NULL pointer is passed.
 *
 * @param ipPkt		packet to fill or NULL
 * @param bytes		pointer to the new data
 * @param caplen	size of captured data
 * @return a pointer to the packet or NULL
 */
inline IPPacket_t *pkt_new_ipPkt(IPPacket_t *ipPkt, void *bytes, int caplen) {
	if (!ipPkt) ipPkt = obstack_alloc(&pkt_obstack, sizeof(IPPacket_t));

    // init
    if (ipPkt) {
    	ipPkt->bytes = bytes;
    	ipPkt->caplen = caplen;
    } else
    	perror("Error: pkt_new_ipPkt > obstack_alloc");

    return ipPkt;
}

/**
 * @brief TCP/UDP segment constructor
 *
 * This function fills a given segment or allocates a new one if NULL pointer is passed.
 *
 * @param sgmt		segment to fill or NULL
 * @param bytes		pointer to the new data
 * @param size		real size of data
 * @param caplen	size of captured data
 * @return a pointer to the segment or NULL
 */
inline void *pkt_new_segment(void *sgmt, void *bytes, int size, int caplen) {
	if (!sgmt) sgmt = obstack_alloc(&pkt_obstack, sizeof(TCPSegment_t));

    // init
    if (sgmt) {
    	((TCPSegment_t *)sgmt)->bytes = bytes;
    	((TCPSegment_t *)sgmt)->size = size;
    	((TCPSegment_t *)sgmt)->caplen = caplen;
    } else
    	perror("Error: pkt_new_segment > obstack_alloc");

    return sgmt;
}

/**
 * @brief Packet filler
 *
 * This function fills a given node or allocates a new pkt if the node is empty.
 *
 * @param node		the node
 * @param pos		packet position
 * @param bytes		pointer to the new data (the data will be copied)
 * @param size		real size of data
 * @param caplen	size of captured data
 * @param timestamp	timestamp
 * @return a pointer to the pkt or NULL
 */
inline pkt_t *pkt_fill(node_t *node, unsigned long long pos, void *bytes, int size, int caplen, struct timeval *timestamp) {
	UTILS_CHECK(!node, EINVAL, return NULL);

	pkt_t *pkt = (pkt_t *)node->load;
	if (!pkt) {
		pkt = obstack_alloc(&pkt_obstack, sizeof(pkt_t));
		if (!pkt) {
			perror("Error: pkt_fill > obstack_alloc");
			return NULL;
		}
		pkt->frame = NULL;
		pkt->dis.ipPkt = NULL;
		pkt->dis.sgmt = NULL;
	}
	pkt->pos = pos;
	pkt->time = 0;
	pkt->container = node;
	pkt->frame = pkt_new_ethFrame(pkt->frame, bytes, size, caplen, timestamp);

	return pkt;
}

/**
 * @brief Dissects Ethernet level
 *
 * @param pkt the packet
 * @return 0 on success, -1 on error
 */
static inline int pkt_dissect_eth(pkt_t *pkt) {
	UTILS_CHECK(!pkt || !pkt->frame, EINVAL, return -1);

	pkt->time = utils_timeval2float(&pkt->frame->timestamp);
	pkt->dis.src = eth_get_src(pkt->frame);
	pkt->dis.dst = eth_get_dst(pkt->frame);
	pkt->dis.ethertype = eth_get_ethertype(pkt->frame);
	pkt->dis.data = (void *)eth_get_data(pkt->frame, &pkt->dis.bufSize);

	return 0;
}

// Normal mode
static inline int _pkt_dissect(pkt_t *pkt) {
	if (pkt_dissect_eth(pkt)) {
		if (pkt_stats) pkt_stats->numErrors++;
		return -1;
	}

	if (pkt->dis.ethertype == ETH_PROTO_IPv4) {
		if (pkt_stats) pkt_stats->numIP++;

		pkt->dis.ipPkt = pkt_new_ipPkt(pkt->dis.ipPkt, pkt->dis.data, pkt->dis.bufSize);
		pkt->dis.ipData = ip_get_data(pkt->dis.ipPkt, &pkt->dis.ipBufSize, &pkt->dis.ipPktSize);
		pkt->dis.data = (void *)pkt->dis.ipData;
		pkt->dis.bufSize = pkt->dis.ipBufSize;
		pkt->dis.protocol = (u_int)ip_get_proto(pkt->dis.ipPkt);
		pkt->dis.offset = ip_get_offset(pkt->dis.ipPkt);

		switch (pkt->dis.protocol) {
			case IP_PROTO_TCP: {
				if (pkt_stats) pkt_stats->numTCP++;
				pkt->dis.sgmt = pkt_new_segment(pkt->dis.sgmt, (void*)pkt->dis.ipData, pkt->dis.ipPktSize, pkt->dis.ipBufSize);
				pkt->dis.srcPort = tcp_get_src((TCPSegment_t *)pkt->dis.sgmt);
				pkt->dis.dstPort = tcp_get_dst((TCPSegment_t *)pkt->dis.sgmt);
				pkt->dis.sgmtData = tcp_get_data((TCPSegment_t *)pkt->dis.sgmt, &pkt->dis.sgmtBufSize, &pkt->dis.sgmtPktSize);
				pkt->dis.data = (void *)pkt->dis.sgmtData;
				pkt->dis.bufSize = pkt->dis.sgmtBufSize;
				break;
			}
			case IP_PROTO_UDP: {
				if (pkt_stats) pkt_stats->numUDP++;
				pkt->dis.sgmt = pkt_new_segment(pkt->dis.sgmt, (void*)pkt->dis.ipData, pkt->dis.ipPktSize, pkt->dis.ipBufSize);
				pkt->dis.srcPort = udp_get_src((UDPDatagram_t *)pkt->dis.sgmt);
				pkt->dis.dstPort = udp_get_dst((UDPDatagram_t *)pkt->dis.sgmt);
				pkt->dis.sgmtData = udp_get_data((UDPDatagram_t *)pkt->dis.sgmt, &pkt->dis.sgmtBufSize, &pkt->dis.sgmtPktSize);
				pkt->dis.data = (void *)pkt->dis.sgmtData;
				pkt->dis.bufSize = pkt->dis.sgmtBufSize;
				break;
			}
		}
	}

	return 0;
}

// Fast mode
static inline int _pkt_dissect_fast(pkt_t *pkt) {
	if (pkt_dissect_eth(pkt)) return -1;
	if (pkt->dis.ethertype != ETH_PROTO_IPv4) return -1;

	if (pkt_stats) pkt_stats->numIP++;

	pkt->dis.ipPkt = pkt_new_ipPkt(pkt->dis.ipPkt, pkt->dis.data, pkt->dis.bufSize);
	pkt->dis.data = (void *)ip_get_data(pkt->dis.ipPkt, &pkt->dis.bufSize, &pkt->dis.pktSize);
	pkt->dis.protocol = (u_int)ip_get_proto(pkt->dis.ipPkt);
	pkt->dis.offset = ip_get_offset(pkt->dis.ipPkt);
	pkt->time = utils_timeval2float(&pkt->frame->timestamp);

	return 0;
}

/**
 * @brief Copies the contents of a packet to another
 *
 * @param src 		source
 * @param dst 		destination
 * @param copyTs	if set, it copies the timestamp also
 * @return 0 on success, -1 on error
 */
inline int pkt_copy(pkt_t *src, pkt_t *dst, int copyTs) {
	UTILS_CHECK(!src || !dst, EINVAL, return -1);

	dst->pos = src->pos;
	if (copyTs) {
		dst->time = src->time;
		dst->frame->timestamp = src->frame->timestamp;
	}
	dst->frame->caplen = src->frame->caplen;
	dst->frame->frameType = src->frame->frameType;
	dst->frame->size = src->frame->size;
	memcpy((void *)dst->frame->bytes, (const void *)src->frame->bytes, src->frame->caplen);

	return 0;
}

/**
 * @brief Initializes the library
 *
 * @param fast	fast mode flag
 * @param stats	pointer to packet statistics
 */
void pkt_init(int fast, pktStats_t *stats) {
	obstack_init(&pkt_obstack);
	obstack_chunk_size(&pkt_obstack) = 1048576;

	if (!fast) pkt_dissect = _pkt_dissect;
	else pkt_dissect = _pkt_dissect_fast;

	pkt_stats = stats;
}

/**
 * @brief Cleaner
 */
void pkt_destroy() {
	obstack_free(&pkt_obstack, NULL);
}

/**
 * @brief Shows info about a packet
 *
 * @param load pointer to the packet
 */
inline void pkt_print(void *load) {
	UTILS_CHECK(!load, EINVAL, return);

	pkt_t *pkt = (pkt_t *)load;
	fprintf(stderr, "%llu,%.9Lf", pkt->pos, pkt->time);
}
