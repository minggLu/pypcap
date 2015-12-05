#!/usr/bin/env python

import dpkt, pcap

#def replace_between(text, begin, end, alternative=''):
#    middle = text.split(begin, 1)[1].split(end, 1)[0]
#        return text.replace(middle, alternative)

def main():
    name = "printer3.pcapng"
    pc = pcap.pcap(name)
    begin = 0
    end = 0
    pkt_list = []
    ipp_list = ['']
    data_list = []
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
            if begin == 0 and hex_payload[:8] == '02000006':
                begin = index

            # end of chunked encoding is '0\r\n\r\n' (or 30d0a0d0a)
            if begin != 0 and end == 0 and hex_payload[-10:] == '300d0a0d0a':
                end = index

            index += 1
 
        for ii in range(begin, end+1):
#            if len(ipp_list) == 0:
#                ipp_list.append(pkt_list[ii])
#                continue

            # pre-set
            legit = True
            # rip off repeating data, '' and '\r\n'
            # except the ending chunk where ends with '300d0a0d0a'
            # check for length of data segment == 1446*2 
            # check for header != 0200000x, and delete the segment right before
            for jj in range(0, max(1, len(ipp_list))):
                legit = legit and pkt_list[ii] != ipp_list[jj] and pkt_list[ii] != '' and len(pkt_list[ii]) >= 128
            if pkt_list[ii][-4:] == '0d0a': 
                legit = legit and pkt_list[ii][-10:] == '300d0a0d0a'
            elif pkt_list[ii][:7] == '0200000':
                legit = False

            if legit == True:
                ipp_list.append(pkt_list[ii])

        for kk in range(1, len(ipp_list)):
            output += ipp_list[kk]

        output = output[:-14]

        # actually write a generic solution
        first = 0
        second = 0
        start = 0
        n = 0
        while output.find('0d0a', start) > -1:
            first = output.find('0d0a', start)
            second = output.find('0d0a', first+1)
            import pdb; pdb.set_trace()

            if second - first <= 64 and second > 0:
                pattern = output[first:second+4]
                output = ''.join(output.split(pattern))
                start = second + 5
                first = 0
                second = 0
            else:
                pattern = output[first:first+4]
                output = ''.join(output.split(pattern))
                import pdb; pdb.set_trace()
                start = first + 5
                first = 0
                second = 0

        f = open("ipp3.txt", "w")
        f.write(output)
        f.close()
        print output
        print len(output)
        import pdb; pdb.set_trace()

    except KeyboardInterrupt:
        print 'Stoped'

if __name__ == '__main__':
    main()
