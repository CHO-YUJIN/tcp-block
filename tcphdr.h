#pragma once

#include "iphdr.h"

#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t sport_;
    uint16_t dport_;
    uint32_t seq_;
    uint32_t ack_;
    uint8_t off_rsvd_;
    uint8_t flags_;
    uint16_t win_;
    uint16_t checksum_;
    uint16_t urp_;

    uint16_t sport() { return ntohs(sport_); }
    uint16_t dport() { return ntohs(dport_); }
    uint32_t seq() { return ntohl(seq_); }
    uint32_t ack() { return ntohl(ack_); }
    uint8_t off() { return (off_rsvd_ & 0xF0) >> 4; }
    uint8_t rsvd() { return off_rsvd_ & 0x0F; }
    uint8_t flags() { return flags_; }
    uint16_t win() { return ntohs(win_); }
    uint16_t checksum() { return ntohs(checksum_); }
    uint16_t urp() { return ntohs(urp_); }

    // Flag
    enum : uint8_t {
        Urg = 0x20,
        Ack = 0x10,
        Psh = 0x08,
        Rst = 0x04,
        Syn = 0x02,
        Fin = 0x01
    };

    // Checksum
    static uint16_t calc_checksum(IpHdr* ipHdr, TcpHdr* tcpHdr);
};
#pragma pack(pop)
