/*
 * tcp.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef TCP_H
#define TCP_H

// header
typedef struct {
    unsigned short  srcPort;
    unsigned short  dstPort;
    unsigned int    seqNumber;
    unsigned int    ackNumber;
    unsigned char   dataOffset_Reserved; // 4 bits dataOffset, 4 bits reserved
    unsigned char   flags; // CWR (RFC 3168 ECN), ECE (idem), URG, ACK, PSH, RST, SYN, FIN
    unsigned short  window;
    unsigned short  checksum;
    unsigned short  urgentPointer;
} TCPheader_t;

// segment
typedef struct {
    TCPheader_t *bytes; 	// segment bytes
    int size;   			// real size
    int caplen; 			// captured size
} TCPSegment_t;

// get source port (error: -1)
int tcp_get_src(TCPSegment_t *sgmt);

// get destination port (error: -1)
int tcp_get_dst(TCPSegment_t *sgmt);

// get sequence number (error: -1)
int tcp_get_seq(TCPSegment_t *sgmt);

// get ACK number (error: -1)
int tcp_get_ack(TCPSegment_t *sgmt);

// get window size (error: -1)
int tcp_get_window(TCPSegment_t *sgmt);

// get TCP payload, captured size and real size
const char *tcp_get_data(TCPSegment_t *sgmt, int *newSize, int *tcpDataLength);

#endif /* TCP_H_ */
