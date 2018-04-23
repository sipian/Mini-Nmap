#include "sniff.h"


int Sniff::packetSize;

int Sniff::open_socket() {
     
    //Create a raw socket that will sniff
    int sockfd = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
    if(sockfd < 0) {
	    log.info("Sniff::open_socket => unable to open sniffer packet -- " + Error::ErrStr());
        throw Error::SOCKET_NOT_CREATED;
    }
    return sockfd;
}

void Sniff::process_packet(const u_char *packet, const std::string &targetIP) {

    const struct iphdr *ip_header = (struct iphdr*)packet;

    if (ip_header->protocol == 6) { 	// only accept TCP packets
    	if (ip_header->saddr == inet_addr(targetIP.c_str())) { 	// only accept packets from targetIP
		    unsigned short ip_header_length = ip_header->ihl*4;
		    struct tcphdr* tcp_header = (struct tcphdr *)(packet + ip_header_length);
		    uint16_t srcPort = ntohs(tcp_header->source);
		    log.info("Sniffed TCP packet from " + targetIP + ":" + std::to_string(srcPort));
		    sniffDetails[srcPort] = tcp_header;
    	}
    }
}

void Sniff::sniff(const std::string &targetIP) {

	int sockfd = open_socket();
    socklen_t saddr_size;
    struct sockaddr saddr;
    
    u_char* buffer = new u_char[Sniff::packetSize];
     
    while(!objectiveAchieved) {

        if(recvfrom(sockfd, buffer, Sniff::packetSize, 0, &saddr, &saddr_size) < 0 )
        {
            log.info("Sniff::sniff => recvfrom error -- " + Error::ErrStr());
        }
        process_packet(buffer, targetIP);
    }
}

