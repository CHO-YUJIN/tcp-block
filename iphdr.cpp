#include "iphdr.h"
/**
 * @desc calc ip checksum
 * @param ipHdr
 * @return checksum in host byte order
*/
uint16_t IpHdr::calc_checksum(IpHdr* ipHdr) {
    uint32_t res = 0;
    uint16_t* wp = reinterpret_cast<uint16_t*>(ipHdr);

    //? Init checksum
    uint16_t org_checksum_ = ipHdr->checksum_;

    //? Clear checksum
    ipHdr->checksum_ = 0;

    //? Sum each word(2byte)
    int i = sizeof(IpHdr) >> 1;
    while (i--) res += uint32_t(ntohs(*wp++));

    //? Fold upper 16bits
    while (res > 0xffff) res = (res >> 16) + (res & 0xffff);

    //? Restore init checksum
    ipHdr->checksum_ = org_checksum_;

    //? one's complement
    return ~uint16_t(res);
}
