#!/usr/bin/env python

import getopt, sys
import dpkt, pcap
import time

def usage():
    print >>sys.stderr, 'usage: %s [-i device] [pattern]' % sys.argv[0]
    sys.exit(1)

def get_data(ts,pkt, pc, pkt_list):

    decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
               pcap.DLT_NULL:dpkt.loopback.Loopback,
               pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]

    hex_payload = decode(pkt).data.data.data.encode("hex") 
    print hex_payload 

    # the gzip file signature is \x1f\x8b\x08
    if len(pkt_list) == 0 and hex_payload[:8] == "02000006":
        pkt_list.append(hex_payload)
        print 'add first packet'
        print hex_payload

    # end of chunked encoding is '0\r\n\r\n' (or 30d0a0d0a)
    elif len(pkt_list) != 0 and hex_payload[-10:] != '300d0a0d0a':
        pkt_list.append(hex_payload)
        print 'add last packet'
        print hex_payload

    elif len(pkt_list) != 0 and hex_payload[-10:] == '300d0a0d0a':
        print hex_payload
        raise KeyboardInterrupt


def main():
    opts, args = getopt.getopt(sys.argv[1:], 'i:h')
    name = None
    for o, a in opts:
        if o == '-i': name = a
        else: usage()
        
    output = ''

    # starts capturing with pypcap library
    pc = pcap.pcap(name, immediate=True)
    pkt_list = []
    ipp_list = []
    # IPP protocol uses TCP with destination port 631
    # the filter follows libpcap syntax
    filter = 'tcp dst port 631'
    pc.setfilter(filter)
    try:
        print 'listening on %s: %s' % (pc.name, pc.filter)
        # pc.loop is a function that process a packet
        # with a user callback, in this case is get_data 
        # get_data looks for the ipp packets that
        # contains document data
        pc.loop(-1, get_ipp, pc, pkt_list)


        # process tcp segments between beginning of operation-id 6 
        # and end of chunking
        for ii in range(begin, end+1):
            if len(ipp_list) == 0:
                ipp_list.append(pkt_list[ii])
                continue

            # pre-set
            legit = True
            # rip off repeating data, '' and '\r\n'
            # check to avoid repeating data segment
            # except the ending chunk where ends with '300d0a0d0a'
            # tcp segments with the chunked data all have length = 1448 byte
            for jj in range(0, len(ipp_list)):
                legit = legit and pkt_list[ii] != ipp_list[jj] and pkt_list[ii] != '' and (len(pkt_list[ii]) == 2896 or ii == end)

            if pkt_list[ii][-4:] == '0d0a':
               legit = legit and pkt_list[ii][-10:] == '300d0a0d0a'

            if legit == True:
                ipp_list.append(pkt_list[ii])

        # write data in to output string
        for kk in range(1, len(ipp_list)):
            output += ipp_list[kk]

        # rip off end of chunk encoding hex bits
        output = output[:-14]

        # remove random '\r\n' + some bytes + '\r\n' in output
        first = 0
        second = 0
        start = 0
        n = 0
        while output.find('0d0a', start) > -1:
            first = output.find('0d0a', start)
            second = output.find('0d0a', first+1)
            import pdb; pdb.set_trace()
            if second > 0 and second - first <= 64:
                pattern = output[first:second+4]
                output = ''.join(output.split(pattern))
                start = second + 5
                first = 0
                second = 0
        f = open("ipp.txt", "w")
        f.write(output)
        f.close()
        print output
        print len(output)
        import pdb; pdb.set_trace()

    except KeyboardInterrupt:
        nrecv, ndrop, nifdrop = pc.stats()
        print '\n%d packets received by filter' % nrecv
        print '%d packets dropped by kernel' % ndrop
        print '%d packets dropped by interface' % nifdrop

if __name__ == '__main__':
    main()
