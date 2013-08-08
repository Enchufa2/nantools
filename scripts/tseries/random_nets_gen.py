#!/usr/bin/env python

import random
import ipaddr

prefixlengths = [8,10,12,14,16,18,20,24]
filters1 = []
filters2 = []

index=0
while index in range(2000):
    ip1 = [str(random.randrange(0, 256)) for i in range(4)]
    ip2 = [str(random.randrange(0, 256)) for i in range(4)]
    ip1 = '.'.join(ip1)
    ip2 = '.'.join(ip2)
    mask1 = str(prefixlengths[random.randrange(0, len(prefixlengths))])
    mask2 = str(prefixlengths[random.randrange(0, len(prefixlengths))])
    net1 = '/'.join([ip1, mask1])
    net2 = '/'.join([ip2, mask2])
    net1 = ipaddr.IPv4Network(net1)
    net2 = ipaddr.IPv4Network(net2)
    
    line = ' '.join([str(net1.network), str(net1.netmask), str(net2.network), str(net2.netmask)])
    if line not in filters1:
        filters1.append(line)
        filters2.append('src net '+str(net1.network)+'/'+str(net1.prefixlen)+' and dst net '+str(net2.network)+'/'+str(net2.prefixlen))
        index += 1

for line in filters1:
    print line

#print '###########################################################'

#for line in filters2:
#    print line
