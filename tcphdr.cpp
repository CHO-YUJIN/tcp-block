#include "tcphdr.h"
/**
 * @desc calc tcp checksum
 * @param ipHdr
 * @param tcpHdr
 * @return checksum in host byte order
*/
uint16_t TcpHdr::calc_checksum(IpHdr* ipHdr, TcpHdr* tcpHdr) {
    uint32_t res = 0;

    //? Init checksum
    uint16_t org_checksum_ = tcpHdr->checksum_;

    //? Clear checksum
    tcpHdr->checksum_ = 0;

    //? Sum each word(2byte)
    //? Pseudo header = ip.sip(32bits) / ip.dip(32bits) / fixd(0)(8bits) / ip.protocol(8bits) / tcp segment length(16bits)
    // ip.sip
    uint32_t sip = ipHdr->sip();
    res += ((sip & 0xFFFF0000) >> 16) + (sip & 0x0000FFFF);

    //ip.dip
    uint32_t dip = ipHdr->dip();
    res += ((dip & 0xFFFF0000) >> 16) + (dip & 0x0000FFFF);

    //ip.protocal
    res += uint32_t(ipHdr->protocol());
    // tcp segment length
    uint32_t tcp_segment_len = uint32_t(ipHdr->len()) - (uint32_t(ipHdr->hdr_len()) << 2);  //ipHdr->len() - sizeof(IpHdr);
    res += tcp_segment_len;

    //? TCP Segment
    uint16_t* wp = reinterpret_cast<uint16_t*>(tcpHdr);
    int i = int(tcp_segment_len);
    for (; i > 1; i -= 2) res += uint32_t(ntohs(*wp++));
    if (i) res += uint32_t(*reinterpret_cast<uint8_t*>(wp)) << 8;

    //? Fold upper 16bits
    while (res > 0xffff) res = (res >> 16) + (res & 0xffff);

    //? Restore init checksum
    tcpHdr->checksum_ = org_checksum_;

    //? one's complement
    return ~uint16_t(res);
}
