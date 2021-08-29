#include <cstdio>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"


#pragma pack(push, 1)
struct TcpPacket final {
    EthHdr eth_;
    IpHdr ip_;
    TcpHdr tcp_;
};
#pragma pack(pop)

char myip[16] = { 0 };
char mymac[18] = { 0 };
std::string ban_host;
std::string ban_redirection;
const int BLOCK = 1;

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

int IpMac(char* dev, char* ip, char* mac)
{
    struct ifreq ifr;
    int fd;
    int ret, ret2;
    uint8_t macADDR[6];

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("socket failed!!\n");
        return -1;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(fd, SIOCGIFHWADDR, &ifr);

    if (ret < 0) {
        printf("ioctl failed!!\n");
        return -1;
    }

    memcpy(macADDR, ifr.ifr_hwaddr.sa_data, 6);
    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", macADDR[0], macADDR[1], macADDR[2], macADDR[3], macADDR[4], macADDR[5]);

    ret2 = ioctl(fd, SIOCGIFADDR, &ifr);

    if (ret2 < 0) {
        printf("ioctl failed!!\n");
        return -1;
    }

    inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ip, sizeof(struct sockaddr));
}

int IsBlock(TcpPacket* _tcpPacket)
{
    TcpPacket& tcpPacket = *_tcpPacket;
    if (tcpPacket.eth_.type() == EthHdr::Ip4) {
        if (tcpPacket.ip_.protocol() == IpHdr::Tcp) {
            if (tcpPacket.tcp_.dport() == 80) {

                unsigned char* packet = reinterpret_cast<unsigned char*>(_tcpPacket);
                char* http = reinterpret_cast<char*>(packet + 14 + tcpPacket.ip_.hdr_len() * 4 + tcpPacket.tcp_.off() * 4);

                std::string str = std::string(http);
                int host_pos = str.find("Host: ");
                if (host_pos != std::string::npos) {
                    std::string host = str.substr(host_pos + std::string("Host: ").size(), str.find("\n", host_pos) - host_pos - std::string("Host: ").size() - 1);
                    if (ban_host == host) return 1;
                }
            }
        }
    }
    return 0;
}

int Forward(pcap_t* handle, TcpPacket* _tcpPacket)
{
    TcpPacket& tcpPacket = *_tcpPacket;

    uint32_t ethHdr_len = sizeof(EthHdr);
    uint32_t ipHdr_len = (uint32_t)tcpPacket.ip_.hdr_len() * 4;
    uint32_t tcpHdr_len = (uint32_t)tcpPacket.tcp_.off() * 4;
    uint32_t total_packet_len = ethHdr_len + ipHdr_len + tcpHdr_len;
    TcpPacket* blockPacket = (TcpPacket*)malloc(total_packet_len);
    memcpy(blockPacket, &tcpPacket, total_packet_len);

    blockPacket->eth_.smac_ = Mac(mymac);
    blockPacket->ip_.len_ = htons(sizeof(IpHdr) + sizeof(TcpHdr));
    blockPacket->tcp_.seq_ = htonl(tcpPacket.tcp_.seq() + 1);
    blockPacket->tcp_.off_rsvd_ = sizeof(TcpHdr) / 4;
    blockPacket->tcp_.flags_ = TcpHdr::Rst | TcpHdr::Ack;

    blockPacket->ip_.checksum_ = htons(IpHdr::calc_checksum(&blockPacket->ip_));
    blockPacket->tcp_.checksum_ = htons(TcpHdr::calc_checksum(&blockPacket->ip_, &blockPacket->tcp_));
    return pcap_sendpacket(handle, (u_char*)blockPacket, sizeof(EthHdr) + blockPacket->ip_.len_);
}

int Backward(pcap_t* handle, TcpPacket* _tcpPacket)
{
    TcpPacket& tcpPacket = *_tcpPacket;

    uint32_t ethHdr_len = sizeof(EthHdr);
    uint32_t ipHdr_len = (uint32_t)tcpPacket.ip_.hdr_len() * 4;
    uint32_t tcpHdr_len = (uint32_t)tcpPacket.tcp_.off() * 4;
    uint32_t total_packetHdr_len = ethHdr_len + ipHdr_len + tcpHdr_len;
    TcpPacket* blockPacket = (TcpPacket*)malloc(total_packetHdr_len + ban_redirection.size());
    memcpy(blockPacket, &tcpPacket, total_packetHdr_len);
    memcpy(blockPacket + total_packetHdr_len, ban_redirection.c_str(), ban_redirection.size());

    blockPacket->eth_.dmac_ = tcpPacket.eth_.smac_;
    blockPacket->eth_.smac_ = Mac(mymac);
    blockPacket->ip_.sip_ = tcpPacket.ip_.dip_;
    blockPacket->ip_.dip_ = tcpPacket.ip_.sip_;
    blockPacket->tcp_.sport_ = tcpPacket.tcp_.dport_;
    blockPacket->tcp_.dport_ = tcpPacket.tcp_.sport_;
    blockPacket->tcp_.seq_ = tcpPacket.tcp_.ack_;
    blockPacket->tcp_.ack_ = htonl(tcpPacket.tcp_.seq() + 1);
    blockPacket->ip_.len_ = htons(uint16_t(sizeof(IpHdr) + sizeof(TcpHdr)) + uint16_t(ban_redirection.size()));
    blockPacket->tcp_.off_rsvd_ = sizeof(TcpHdr) / 4;
    tcpPacket.tcp_.flags_ = TcpHdr::Psh | TcpHdr::Fin | TcpHdr::Ack;

    blockPacket->ip_.checksum_ = htons(IpHdr::calc_checksum(&blockPacket->ip_));
    blockPacket->tcp_.checksum_ = htons(TcpHdr::calc_checksum(&blockPacket->ip_, &blockPacket->tcp_));
    return pcap_sendpacket(handle, (u_char*)blockPacket, sizeof(EthHdr) + blockPacket->ip_.len_);
}

void TcpBlcok(pcap_t* handle)
{
    struct pcap_pkthdr* ReplyPacket;
    const u_char* pkt_data;
    TcpPacket packet;
    int res;
    int bBlock = 1;

    while (1)
    {
        res = pcap_next_ex(handle, &ReplyPacket, &pkt_data);
        if (res == 0) {
            printf("res == 0\n");
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("%s : pcap_next_ex return %d\n", pcap_geterr(handle), res);
            break;
        }

        auto packet = (TcpPacket*)(pkt_data);
        if (bBlock == IsBlock(packet))
        {
            Forward(handle, packet);
            Backward(handle, packet);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("*Fill in the form*\n");
        usage();
        return -1;
    }
    ban_host = std::string(argv[2]);
    ban_redirection = std::string("302");

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    if (IpMac(argv[1], myip, mymac) < 0)
    {
        printf("error");
    }

    TcpBlcok(handle);
    pcap_close(handle);
}
