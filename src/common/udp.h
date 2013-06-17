/*
 * udp.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef UDP_H
#define UDP_H

// header
typedef struct {
    unsigned short  srcPort;
    unsigned short  dstPort;
    unsigned short  length;
    unsigned short  checksum;
} UDPheader_t;
/*
0      7 8     15 16    23 24    31  
+--------+--------+--------+--------+ 
|     Source      |   Destination   | 
|      Port       |      Port       | 
+--------+--------+--------+--------+ 
|                 |                 | 
|     Length      |    Checksum     | 
+--------+--------+--------+--------+ 
|                                     
|          data octets ...            
+---------------- ...                 

User Datagram Header Format
*/

// datagram
typedef struct {
    UDPheader_t     *bytes; // datagram bytes
    int             size;   // real size
    int             caplen; // captured size
} UDPDatagram_t;

// get source port (error: -1)
int udp_get_src(UDPDatagram_t *datagrama);

// get destination port (error: -1)
int udp_get_dst(UDPDatagram_t *datagrama);

// get UDP payload, captured size and real size
const char *udp_get_data(UDPDatagram_t *datagrama, int *newSize, int *udpDataLength);

#endif /* UDP_H_ */
