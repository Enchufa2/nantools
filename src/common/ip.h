/*
 * ip.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef IP_H
#define IP_H

#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

// IPv4 header
typedef struct {
    unsigned char   version_HeaderLength;   // 4 bits version, 4 bits internet header length
    unsigned char   dscpEcn;                // 6 bits DSCP, 2 bits ECN
    unsigned short  totalLength;
    unsigned short  identification;
    unsigned short  flags_Offset;           // 1 bit flag reserved, 1 bit DF, 1 bit MF, 13 bits fragmentOffset
    unsigned char   ttl;
    unsigned char   protocol;
    unsigned short  headerChecksum;
    unsigned int    srcAddr;
    unsigned int    dstAddr;
} IPheader_t;
/*
 0                   1                   2                   3   
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Version|  IHL  |Type of Service|          Total Length         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         Identification        |Flags|      Fragment Offset    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Time to Live |    Protocol   |         Header Checksum       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       Source Address                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Destination Address                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 Flags:  3 bits
 
 Various Control Flags.
 
 Bit 0: reserved, must be zero
 Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
 Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.
 
 0   1   2
 +---+---+---+
 |   | D | M |
 | 0 | F | F |
 +---+---+---+

*/

// packet
typedef struct {
    IPheader_t  *bytes; // packet bytes
    int         caplen; // captured size
} IPPacket_t;

// true if captured bytes cover the entire IP header
int ip_is_header_complete(IPPacket_t *pkt);

// true if captured bytes cover 20 bytes of the IP header
int ip_is_basic_header_complete(IPPacket_t *pkt);

// get formatted source IP (from inet_ntoa())
char *ip_get_src_txt(IPPacket_t *pkt);

// get formatted destination IP (from inet_ntoa())
char *ip_get_dst_txt(IPPacket_t *pkt);

// get source IP (error: -1)
int ip_get_src(IPPacket_t *pkt);

// get destination IP (error: -1)
int ip_get_dst(IPPacket_t *pkt);

// get underlying protocol (error: -1)
int ip_get_proto(IPPacket_t *pkt);

// get length (error: -1)
int ip_get_length(IPPacket_t *pkt);

// get offset (error: -1)
int ip_get_offset(IPPacket_t *pkt);

// get TTL (error: -1)
int ip_get_TTL(IPPacket_t *pkt);

// get IP flags (error: -1)
char ip_get_flags(IPPacket_t *pkt);

// get More Fragments flag (error: -1)
char ip_get_MF(IPPacket_t *pkt);

// get ip payload, captured size and real size
const char *ip_get_data(IPPacket_t *pkt, int *newSize, int *ipDataLength);

// true, false (error: -1)
int ip_is_fragment(IPPacket_t *pkt);

// true, false (error: -1)
int ip_is_first_fragment(IPPacket_t *pkt);

#endif /* IP_H_ */
