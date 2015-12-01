#!/usr/bin/env python

import dpkt, pcap

def main():
    name = "printer6.pcapng"
    pc = pcap.pcap(name)
    begin = 0
    end = 0
    pkt_list = []
    ipp_list = []
    output = ''
    # IPP protocol typically use destination port 631
    filter = 'tcp dst port 631'
    pc.setfilter(filter)
    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]
    try:
        index = 0
        legit = False
        payload = ''
        hex_payload = ''
        for ts, pkt in pc:
            payload = decode(pkt).data.data.data
            hex_payload = payload.encode("hex") 
            pkt_list.append(hex_payload)
            # beginning of Sent-Document
            # IPP version: \x02\x00 (2-byte)
            # Operation-id = \x00\x06 (2-byte)
            if begin == 0 and payload[:4] == '\x02\x00\x00\x06':
                begin = index

            # end of chunked encoding is '0\r\n\r\n' (or 30d0a0d0a)
            if begin != 0 and end == 0 and hex_payload[-10:] == '300d0a0d0a':
                end = index

            index += 1
 
        for ii in range(begin, end+1):
            if len(ipp_list) == 0:
                ipp_list.append(pkt_list[ii])
                continue

            # preset
            legit = True
            # rip off repeating data, '' and '\r\n'
            # except the ending chunk where ends with '300d0a0d0a'
            for jj in range(0, len(ipp_list)):
                legit = legit and pkt_list[ii] != ipp_list[jj] and pkt_list[ii] != '' and (pkt_list[ii][-4:] != '0d0a' or pkt_list[ii][-10:] == '300d0a0d0a')

            if legit == True:
                ipp_list.append(pkt_list[ii])

        # the first item is the request, data starts on the 2nd piece
        for kk in range(1, len(ipp_list)):
            output += ipp_list[kk]

        output = output[:-14]
        f = open("ipp.txt", "w")
        f.write(output)
        print output
        print len(output)

    except KeyboardInterrupt:
        print 'Stoped'

if __name__ == '__main__':
    main()
