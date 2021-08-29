#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct IpHdr final {
    uint8_t hdr_len_ : 4;
    uint8_t version_ : 4;
    uint8_t tos_;
    uint16_t len_;
    uint16_t id_;
    uint8_t frag_offset : 5;
    uint8_t more_fragment : 1;
    uint8_t dont_fragment : 1;
    uint8_t reserved_zero : 1;
    uint8_t frag_offset1;
    uint8_t ttl_;
    uint8_t protocol_;
    uint16_t checksum_;
    Ip sip_;
    Ip dip_;

    uint8_t version() { return version_; }
    uint8_t hdr_len() { return hdr_len_; }
    uint8_t tos() { return tos_; }
    uint16_t len() { return ntohs(len_); }
    uint16_t id() { return ntohs(id_); }
    uint8_t ttl() { return ttl_; }
    uint8_t protocol() { return protocol_; }
    uint16_t checksum() { return ntohs(checksum_); }

    Ip sip() { return ntohl(sip_); }
    Ip dip() { return ntohl(dip_); }

    // Protocol
    enum : uint8_t {
        Icmp = 1,    // Internet Control Message Protocol
        Igmp = 2,    // Internet Group Management Protocol
        Tcp = 6,     // Transmission Control Protocol
        Udp = 17,    // User Datagram Protocol
        Sctp = 132,  // Stream Control Transport Protocol
    };

    // Checksum
    static uint16_t calc_checksum(IpHdr* ipHdr);
};
#pragma pack(pop)
