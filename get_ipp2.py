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
        payload = ''
        hex_payload = ''
# the last 4 character in the chunked data is \r\n\r\n (or 0d0a0d0a)
        for ts, pkt in pc:
            payload = decode(pkt).data.data.data
            hex_payload = payload.encode("hex") 
            if payload[:4] == '\x02\x00\x00\x06':
                print payload
                import pdb; pdb.set_trace()
                begin = ts 
            
            if begin != 0 and end == 0 and hex_payload[-10:] == '300d0a0d0a':
                print payload
                end = ts

            print ts, `decode(pkt)`

    except KeyboardInterrupt:
        print 'Stoped' 
        
if __name__ == '__main__':
    main() 
