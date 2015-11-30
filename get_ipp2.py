#!/usr/bin/env python

import dpkt, pcap

def main():
    name = "printer6.pcapng"
    begin = 0
    end = 0
    pc = pcap.pcap(name)
    filter = 'tcp dst port 631'
#    filter = 'tcp dst port 631 and tcp[((tcp[12:1] & 0xf0) >> 2):4]=0x02000006'
    pc.setfilter(filter)
    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]
    try:
        pc_enum = enumerate(iter(pc))
        pkt_list = []
        payload = ''
        hex_payload = ''
        index = 0
        output = ''
# the last 4 character in the chunked data is \r\n\r\n (or 0d0a0d0a)
        for ts, pkt in pc:
            payload = decode(pkt).data.data.data
            hex_payload = payload.encode("hex") 
            pkt_list.append(hex_payload)
            if begin == 0 and payload[:4] == '\x02\x00\x00\x06':
                begin = index
            
            if begin != 0 and end == 0 and hex_payload[-10:] == '300d0a0d0a':
                end = index

            index += 1
        
        for ii in range(begin, end+1):
            output += pkt_list[ii]

        print output

    except KeyboardInterrupt:
        print 'Stoped' 
        
if __name__ == '__main__':
    main() 
