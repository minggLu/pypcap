#!/usr/bin/env python

import dpkt, pcap

def main():
    name = "printer6.pcapng"
    pc = pcap.pcap(name)
    filter = 'tcp dst port 631'
# filter = 'tcp dst port 631 and tcp[((tcp[12:1] & 0xf0) >> 2):4]=0x02000006'
    pc.setfilter(filter)
    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               #pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]
    try:
        for ts, pkt in pc:
            print ts, `decode(pkt)`
    except KeyboardInterrupt:
        print 'Stoped' 
        
if __name__ == '__main__':
    main() 
