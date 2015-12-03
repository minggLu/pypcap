#!/usr/bin/env python

import getopt, sys
import dpkt, pcap
import time

def usage():
    print >>sys.stderr, 'usage: %s [-i device] [pattern]' % sys.argv[0]
    sys.exit(1)

def __my_handler(ts,pkt, pc, ipp_list):

    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]

    #import pdb; pdb.set_trace()
    hex_payload = decode(pkt).data.data.data.encode("hex") 
    print hex_payload 

    if len(ipp_list) == 0 and hex_payload[:20] == "1f8b0800000000000003":
        ipp_list.append(hex_payload)
        print 'add first packet'
        print hex_payload

    # end of chunked encoding is '0\r\n\r\n' (or 30d0a0d0a)
    elif len(ipp_list) != 0 and hex_payload[-10:] != '300d0a0d0a':
        ipp_list.append(hex_payload)
        print 'add last packet'
        print hex_payload

    elif len(ipp_list) != 0 and hex_payload[-10:] == '300d0a0d0a':
        raise KeyboardInterrupt
        #raise Exception()


def main():
    opts, args = getopt.getopt(sys.argv[1:], 'i:h')
    name = None
    for o, a in opts:
        if o == '-i': name = a
        else: usage()
        
    pc = pcap.pcap(name)
    ipp_list = []
    output = ''
    # IPP protocol typically use destination port 631
    filter = 'tcp'
    pc.setfilter(filter)
    try:
        index = 0
        legit = False
        myfile = open('realtime.txt', 'w')
        print 'listening on %s: %s' % (pc.name, pc.filter)
        #import pdb; pdb.set_trace()
        pc.loop(-1, __my_handler, pc, ipp_list)

#            if begin != 0 and end != 0:
#                for ii in range(begin, end+1):
#                    if len(ipp_list) == 0:
#                        myfile.write(pkt_list[ii])
#                #        ipp_list.append(pkt_list[ii])
#                
#                        continue
#
#                    # preset
#                    legit = True
#                    # rip off repeating data, '' and '\r\n'
#                    # except the ending chunk where ends with '300d0a0d0a'
#                    for jj in range(0, len(ipp_list)):
#                        legit = legit and pkt_list[ii] != ipp_list[jj] and pkt_list[ii] != ''
#                    if pkt_list[ii][-4:] == '0d0a':
#                       legit = legit and pkt_list[ii][-10:] == '300d0a0d0a'
#
#                    if legit == True:
#                        myfile.write(pkt_list[ii])
#                #        ipp_list.append(pkt_list[ii])

    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print '\n%d packets received by filter' % nrecv
        print '%d packets dropped by kernel' % ndrop

if __name__ == '__main__':
    main()
